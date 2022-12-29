use thiserror::Error;
use serde::{Deserialize, Serialize};


#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("Invalid Authentication credentials")]
    InvalidCredentials,
    #[error("Error while communicating to GitHub OAuth2")]
    Github(#[from] reqwest::Error),
    #[error("Error while parsing JSON: {0}")]
    SerDe(#[from] serde_json::Error),
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
            format!("token {}",
            access_token),
        )
        .send()
        .await?
        .json()
        .await?)

}