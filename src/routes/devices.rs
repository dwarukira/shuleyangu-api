use crate::mail::mail::send_email;
use crate::models::user::NewUser;
use crate::schema::users;
use crate::schema::verification_codes;
use crate::utils::auth::generate_auth_token;
use crate::{routes::ApiError, utils::validate::validation_errors_to_string};
use actix_web::cookie::Cookie;
use actix_web::{post, web, HttpResponse};
use chrono::Duration;
use diesel::prelude::*;
use serde::Serialize;
use validator::Validate;

#[derive(serde::Deserialize, Serialize, Validate)]
pub struct Verification {
    #[validate(length(min = 4))]
    pub code: String,
    #[validate(email)]
    pub address: String,
}

#[derive(serde::Deserialize, Serialize, Validate)]
pub struct Address {
    // todo add phone number validation or email validation
    #[validate(email)]
    pub address: String,
}

#[derive(serde::Deserialize, Serialize)]
pub struct VerificationResponse {
    pub auth_token: String,
    pub user_id: i32,
}

#[post["outbound_verification"]]
pub async fn outbound_verification(
    verification: web::Json<Verification>,
    connection: web::Data<crate::database::PostgresPool>,
) -> Result<HttpResponse, ApiError> {
    // validate the input
    verification
        .validate()
        .map_err(|e| ApiError::Validation(validation_errors_to_string(e, None)))?;

    let mut connection = connection.get().unwrap();
    let verification_code = verification_codes::table
        .filter(verification_codes::identifier.eq(&verification.address))
        .filter(verification_codes::code.eq(&verification.code))
        .filter(verification_codes::expires_at.gt(chrono::Utc::now().naive_utc()))
        .first::<crate::models::verification_codes::VerificationCode>(&mut connection)?;

    let user = NewUser {
        first_name: "".to_string(),
        last_name: "".to_string(),
        middle_name: None,
        email: Some(verification_code.identifier.clone()),
        phone: None,
        password: None,
        github_id: None,
    };
    let user = diesel::insert_into(users::table)
        .values(&user)
        .get_result::<crate::models::user::User>(&mut connection)?;

    let session = crate::models::session::NewSession {
        token: generate_auth_token(64),
        user_id: user.id,
        ip_address: Some("".to_string()),
        device_id: Some("".to_string()),
        expires_at: chrono::Utc::now().naive_utc() + Duration::days(30),
    };

    let session = diesel::insert_into(crate::schema::sessions::table)
        .values(&session)
        .get_result::<crate::models::session::Session>(&mut connection)?;

    let response = VerificationResponse {
        auth_token: session.token.to_string(),
        user_id: user.id,
    };
    let cookie = Cookie::build("auth_token", session.token)
        .path("/")
        .secure(false)
        .http_only(true)
        .finish();
    Ok(HttpResponse::Ok().cookie(cookie).json(response))
}

#[post("outbound_verification/code")]
pub async fn outbound_verification_code(
    verification: web::Json<Address>,
    connection: web::Data<crate::database::PostgresPool>,
) -> Result<HttpResponse, ApiError> {
    let mut connection = connection.get().unwrap();
    verification
        .validate()
        .map_err(|e| ApiError::Validation(validation_errors_to_string(e, None)))?;
    let code = crate::utils::auth::generate_verification_code();
    let verification_code = crate::models::verification_codes::NewVerificationCode {
        code: code.clone(),
        identifier: verification.address.clone(),
        expires_at: chrono::Utc::now().naive_utc() + chrono::Duration::minutes(30),
    };

    let verification_code = diesel::insert_into(verification_codes::table)
        .values(&verification_code)
        .get_result::<crate::models::verification_codes::VerificationCode>(&mut connection)?;

    let email = format!(
        include_str!("../emails/code.tmpl"),
        code = verification_code.code
    );
    let _ = send_email(
        &verification_code.identifier,
        "Please confirm your email address",
        &email,
    )
    .await;
    let address = Address {
        address: verification_code.identifier,
    };
    Ok(HttpResponse::Ok().json(address))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("devices")
            .service(outbound_verification)
            .service(outbound_verification_code),
    );
}
