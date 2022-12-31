use crate::{database::PostgresPool, mail::mail::send_email, routes::ApiError};
use actix_web::{
    get,
    web::{self, Data, Query},
    HttpResponse,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Serialize, Validate)]
pub struct ProfileIdentifier {
    #[validate(length(min = 1))]
    pub identifier: String,
}

#[derive(Deserialize, Serialize)]
pub struct Need {
    pub full_name: bool,
    pub password: bool,
}

#[derive(Deserialize, Serialize)]
pub struct Identity {
    pub email: String,
    pub needs: Need,
}

#[get("")]
pub async fn get_user_profile_by_identifier(
    Query(identifier): Query<ProfileIdentifier>,
    client: Data<PostgresPool>,
) -> Result<HttpResponse, ApiError> {
    let mut client = client.get().unwrap();
    if identifier.identifier.contains("@") {
        let email = identifier.identifier;
        let user = crate::schema::users::table
            .filter(crate::schema::users::email.eq(&email))
            .first::<crate::models::user::User>(&mut client)
            .optional()?;

        let mut needs = Need {
            full_name: true,
            password: true,
        };

        if let Some(user) = user {
            if user.first_name != "" && user.last_name != "" {
                needs.full_name = false;
            }
            if user.password.is_some() {
                needs.password = false;
            }
        }
        let identity = Identity { email, needs };

        Ok(HttpResponse::Ok().json(identity))
    } else {
        return Err(ApiError::Validation("Invalid identifier".to_string()));
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("profiles").service(get_user_profile_by_identifier));
}
