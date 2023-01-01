use crate::{
    database::PostgresPool,
    schema::{sessions, users},
};
use actix_web::{web, Error, FromRequest, HttpResponse, ResponseError};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use futures::future::{err, ok, Ready};
use serde::{Deserialize, Serialize};

use super::session::Session;

#[derive(Serialize, Deserialize, Clone, Debug, Queryable)]
pub struct User {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub middle_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub github_id: Option<String>,
    pub email_verified_at: Option<NaiveDateTime>,
    pub email_verification_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub github_id: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub middle_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Option<String>,
}

pub type CurrentUser = User;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Unauthorized")]
    Unauthorized,
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::Unauthorized => HttpResponse::Unauthorized().json("Unauthorized"),
        }
    }
}

impl FromRequest for CurrentUser {
    type Error = Error;
    type Future = Ready<Result<CurrentUser, Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let mut conn = req
            .app_data::<web::Data<PostgresPool>>()
            .unwrap()
            .get()
            .unwrap();
        if let Ok(auth) = BearerAuth::from_request(req, _payload).into_inner() {
            if let Ok(session) = sessions::table
                .filter(sessions::token.eq(auth.token()))
                .first::<Session>(&mut conn)
            {
                if let Ok(user) = users::table
                    .filter(users::id.eq(session.user_id))
                    .first::<User>(&mut conn)
                {
                    return ok(user);
                }
            }
        }
        err(ServiceError::Unauthorized.into())
    }
}
