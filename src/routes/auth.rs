use crate::models::error::ApiError;
use crate::models::ids::DecodingError;
use crate::models::ids::{parse_base62, to_base62};
use crate::models::user::CurrentUser;
use crate::utils::auth::{
    generate_auth_token, get_github_user_emails, get_github_user_from_token, hash_password,
};
use crate::utils::validate::validation_errors_to_string;
use crate::{database::PostgresPool, utils::env::parse_string_from_var};
use actix_web::cookie::Cookie;
use actix_web::web::Json;
use actix_web::{get, http, post, web, web::Data, web::Query, HttpRequest, HttpResponse};
use chrono::Duration;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validator::Validate;

#[derive(Deserialize, Serialize)]
pub struct OAuthInfoInit {
    pub url: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct OAuthInfoCallback {
    pub code: String,
    pub state: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct SignUpEmail {
    #[validate(email)]
    pub email: String,
    pub password: String,
    #[validate(length(min = 1))]
    pub first_name: String,
    #[validate(length(min = 1))]
    pub last_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccessToken {
    pub access_token: String,
    pub scope: String,
    pub token_type: String,
}

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Invalid callback URL specified")]
    Url,
    #[error("Environment Error")]
    Env(#[from] dotenvy::Error),
    #[error("Error while decoding Base62")]
    Decoding(#[from] DecodingError),
    #[error("Database Error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("Invalid Authentication credentials")]
    InvalidCredentials,
    #[error("Error while communicating to GitHub OAuth2")]
    Github(#[from] reqwest::Error),
    #[error("Error while parsing JSON: {0}")]
    SerDe(#[from] serde_json::Error),
    #[error("Authentication Error: {0}")]
    Authentication(#[from] crate::utils::auth::AuthenticationError),
    #[error("Error user already exists")]
    UserAlreadyExists,
    #[error("Error while validating input: {0}")]
    ValidationError(String),
}

impl actix_web::ResponseError for AuthorizationError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ApiError {
            error: match self {
                AuthorizationError::Url => "invalid_url",
                AuthorizationError::Env(..) => "environment_error",
                AuthorizationError::Decoding(..) => "decoding_error",
                AuthorizationError::Database(..) => "database_error",
                AuthorizationError::InvalidCredentials => "invalid_credentials",
                AuthorizationError::Github(..) => "github_error",
                AuthorizationError::SerDe(..) => "serde_error",
                AuthorizationError::Authentication(..) => "authentication_error",
                AuthorizationError::UserAlreadyExists => "user_already_exists",
                AuthorizationError::ValidationError(..) => "validation_error",
            },
            description: &self.to_string(),
        })
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AuthorizationError::Url => actix_web::http::StatusCode::BAD_REQUEST,
            AuthorizationError::Env(..) => http::StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationError::Decoding(..) => http::StatusCode::BAD_REQUEST,
            AuthorizationError::Database(..) => http::StatusCode::INTERNAL_SERVER_ERROR,
            AuthorizationError::InvalidCredentials => http::StatusCode::UNAUTHORIZED,
            AuthorizationError::Github(..) => http::StatusCode::FAILED_DEPENDENCY,
            AuthorizationError::SerDe(..) => http::StatusCode::BAD_REQUEST,
            AuthorizationError::Authentication(..) => http::StatusCode::UNAUTHORIZED,
            AuthorizationError::UserAlreadyExists => http::StatusCode::CONFLICT,
            AuthorizationError::ValidationError(..) => http::StatusCode::BAD_REQUEST,
        }
    }
}

#[get("init/github")]
pub async fn github_init(
    Query(info): Query<OAuthInfoInit>,
    client: Data<PostgresPool>,
) -> Result<HttpResponse, AuthorizationError> {
    let url = url::Url::parse(&info.url).map_err(|_| AuthorizationError::Url)?;
    let allowed_callback_urls = parse_string_from_var("ALLOWED_CALLBACK_URLS").unwrap_or_default();
    let domain = url.domain().ok_or(AuthorizationError::Url)?;
    if !allowed_callback_urls.iter().any(|x| domain.ends_with(x)) {
        return Err(AuthorizationError::Url);
    }
    let mut conn = client.get().unwrap();
    let state = crate::models::states::NewStates {
        url: info.url.clone(),
        expires_at: chrono::Utc::now().naive_utc() + Duration::hours(1),
    };
    let state = diesel::insert_into(crate::schema::states::table)
        .values(&state)
        .get_result::<crate::models::states::States>(&mut conn)
        .unwrap();

    let client_id = dotenvy::var("GITHUB_CLIENT_ID")?;

    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&state={}&scope={}",
        client_id,
        to_base62(state.id as u64),
        "read%3Auser user%3Aemail"
    );
    Ok(HttpResponse::TemporaryRedirect()
        .append_header((http::header::LOCATION, &*url))
        .json(OAuthInfoInit { url }))
}

#[get("callback/github")]
pub async fn github_callback(
    Query(info): Query<OAuthInfoCallback>,
    client: Data<PostgresPool>,
) -> Result<HttpResponse, AuthorizationError> {
    let state_id = parse_base62(&info.state)?;

    let mut conn = client.get().unwrap();
    let state = crate::schema::states::table
        .filter(crate::schema::states::id.eq(state_id as i32))
        .filter(crate::schema::states::expires_at.gt(chrono::Utc::now().naive_utc()))
        .first::<crate::models::states::States>(&mut conn)?;
    if state.url.is_empty() {
        return Err(AuthorizationError::Url);
    }
    let duration = state.expires_at - chrono::Utc::now().naive_utc();
    if duration.num_seconds() < 0 {
        return Err(AuthorizationError::InvalidCredentials);
    }
    diesel::delete(crate::schema::states::table.filter(crate::schema::states::id.eq(state.id)))
        .execute(&mut conn)?;
    let client_id = dotenvy::var("GITHUB_CLIENT_ID")?;
    let client_secret = dotenvy::var("GITHUB_CLIENT_SECRET")?;
    let url = format!(
        "https://github.com/login/oauth/access_token?client_id={}&client_secret={}&code={}",
        client_id, client_secret, info.code
    );

    let token = reqwest::Client::new()
        .post(&url)
        .header("Accept", "application/json")
        .send()
        .await?
        .json::<AccessToken>()
        .await?;

    let user = get_github_user_from_token(&token.access_token).await?;
    let local_user = crate::schema::users::table
        .filter(crate::schema::users::github_id.eq(user.id.to_string()))
        .first::<crate::models::user::User>(&mut conn)
        .optional()?;
    let mut email = user.email.clone();
    if user.email.is_none() {
        let emails = get_github_user_emails(&token.access_token).await?;
        email = emails
            .into_iter()
            .find(|x| x.primary && x.verified)
            .map(|x| x.email);
        if email.is_none() {
            return Err(AuthorizationError::InvalidCredentials);
        }
    }
    match local_user {
        Some(local_user) => local_user,
        None => {
            let u = user.clone();
            let username = u.name.unwrap_or("".to_string());
            let user = crate::models::user::NewUser {
                github_id: Some(u.id.to_string()),
                first_name: username.split(' ').next().unwrap_or("").to_string(),
                last_name: username.split(' ').last().unwrap_or("").to_string(),
                middle_name: Some("".to_string()),
                email: Some(email.unwrap_or("".to_string())),
                phone: Some("".to_string()),
                password: Some("".to_string()),
            };
            diesel::insert_into(crate::schema::users::table)
                .values(&user)
                .get_result::<crate::models::user::User>(&mut conn)?
        }
    };

    let redirect_url = if state.url.contains('?') {
        format!("{}&code={}", state.url, token.access_token)
    } else {
        format!("{}?code={}", state.url, token.access_token)
    };

    Ok(HttpResponse::TemporaryRedirect()
        .append_header(("Location", &*redirect_url))
        .json(OAuthInfoInit { url: redirect_url }))
}

#[post("signup/email")]
pub async fn sign_up_email(
    Json(sign_up_email_data): Json<SignUpEmail>,
    client: Data<PostgresPool>
) -> Result<HttpResponse, AuthorizationError> {
    sign_up_email_data
        .validate()
        .map_err(|e| AuthorizationError::ValidationError(validation_errors_to_string(e, None)))?;

    let mut conn = client.get().unwrap();
    let user = crate::schema::users::table
        .filter(crate::schema::users::email.eq(&sign_up_email_data.email))
        .first::<crate::models::user::User>(&mut conn)
        .optional()?;

    if user.is_some() {
        return Err(AuthorizationError::UserAlreadyExists);
    }
    let password_hash = hash_password(&sign_up_email_data.password);
    let user = crate::models::user::NewUser {
        github_id: None,
        first_name: sign_up_email_data.first_name,
        last_name: sign_up_email_data.last_name,
        middle_name: None,
        email: Some(sign_up_email_data.email),
        phone: None,
        password: Some(password_hash),
    };

    let user = diesel::insert_into(crate::schema::users::table)
        .values(&user)
        .get_result::<crate::models::user::User>(&mut conn)?;

    let session = crate::models::session::NewSession {
        token: generate_auth_token(64),
        user_id: user.id,
        ip_address: Some("".to_string()),
        device_id: Some("".to_string()),
        expires_at: chrono::Utc::now().naive_utc() + Duration::days(30),
    };

    let session = diesel::insert_into(crate::schema::sessions::table)
        .values(&session)
        .get_result::<crate::models::session::Session>(&mut conn)?;

    let cookie = Cookie::build("auth_token", session.token)
        .path("/")
        .secure(false)
        .http_only(true)
        .finish();

    Ok(HttpResponse::Ok()
        .append_header(("Set-Cookie", cookie.to_string()))
        .json(()))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmLogin {
    pub auth_token: String,
}

#[post("access_tokens/confirmed_login")]
pub async fn confirm_login(
    info: web::Json<ConfirmLogin>,
    client: Data<PostgresPool>,
    current_user: CurrentUser,
) -> Result<HttpResponse, AuthorizationError> {
    println!("confirm_login {:?}", current_user);
    // TODO: check if token is valid
    let mut conn = client.get().unwrap();
    let session = crate::schema::sessions::table
        .filter(crate::schema::sessions::token.eq(&info.auth_token))
        .first::<crate::models::session::Session>(&mut conn)
        .optional()?;
    if session.is_none() {
        return Err(AuthorizationError::InvalidCredentials);
    }
    let session = session.unwrap();
    let user = crate::schema::users::table
        .filter(crate::schema::users::id.eq(session.user_id))
        .first::<crate::models::user::User>(&mut conn)?;

    Ok(HttpResponse::Ok().json(user))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("auth")
            .service(github_init)
            .service(github_callback)
            .service(sign_up_email)
            .service(confirm_login),
    );
}
