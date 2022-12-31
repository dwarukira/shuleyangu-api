mod auth;
mod devices;
mod health;
mod profile;
use actix_web::{web, HttpResponse};

pub use self::health::test_database;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("v1")
            .configure(auth::configure)
            .configure(profile::configure)
            .configure(devices::configure),
    );
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error("Environment Error")]
    Env(#[from] dotenvy::Error),
    #[error("Deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid Input: {0}")]
    InvalidInput(String),
    #[error("Error while validating input: {0}")]
    Validation(String),
    #[error("Database Error: {0}")]
    Database(#[from] diesel::result::Error),
    
}

impl actix_web::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        actix_web::HttpResponse::build(self.status_code()).json(crate::models::error::ApiError {
            error: match self {
                ApiError::InvalidInput(_) => "invalid_input",
                ApiError::Validation(_) => "validation_error",
                ApiError::Json(..) => "json_error",
                ApiError::Env(..) => "env_error",
                ApiError::Database(..) => "database_error",
            },
            description: &self.to_string(),
        })
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            ApiError::Json(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ApiError::InvalidInput(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ApiError::Validation(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ApiError::Env(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Database(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
