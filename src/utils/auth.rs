use std::iter;

use actix_web::{dev::ServiceRequest, FromRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use alcoholic_jwt::{token_kid, validate, Validation, JWKS};

use crate::models::user::User;

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Invalid Authentication credentials")]
    InvalidCredentials,
    #[error("Error while communicating to GitHub OAuth2")]
    Github(#[from] reqwest::Error),
    #[error("Error while parsing JSON: {0}")]
    SerDe(#[from] serde_json::Error),
    #[error("Unauthorized")]
    Unauthorized,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubUser {
    pub login: String,
    pub id: i32,
    pub avatar_url: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub bio: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubUserEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

pub async fn get_github_user_from_token(
    access_token: &str,
) -> Result<GitHubUser, AuthenticationError> {
    Ok(reqwest::Client::new()
        .get("https://api.github.com/user")
        .header(reqwest::header::USER_AGENT, "Shule")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("token {}", access_token),
        )
        .send()
        .await?
        .json()
        .await?)
}

pub async fn get_github_user_emails(
    access_token: &str,
) -> Result<Vec<GitHubUserEmail>, AuthenticationError> {
    Ok(reqwest::Client::new()
        .get("https://api.github.com/user/emails")
        .header(reqwest::header::USER_AGENT, "Shule")
        .header(
            reqwest::header::AUTHORIZATION,
            format!("token {}", access_token),
        )
        .send()
        .await?
        .json()
        .await?)
}

pub fn hash_password(password: &str) -> String {
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 3,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let salt = [0u8; 16];
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    hash
}

pub fn generate_verification_code() -> String {
    let mut rng = rand::thread_rng();
    let sample = rng.gen_range(0..9999);
    format!("{:04}", sample)
}

pub fn generate_auth_token(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    iter::repeat_with(one_char).take(len).collect()
}
