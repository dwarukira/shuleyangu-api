use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use crate::schema::sessions;
use diesel::prelude::*;

#[derive(Queryable, Serialize, Deserialize, Debug)]
pub struct Session {
    pub id: i32,
    pub user_id: i32,
    pub token: String,
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_used_at:Option<NaiveDateTime>,
}


#[derive(Debug, Serialize, Deserialize, Insertable)]
#[table_name = "sessions"]
pub struct NewSession {
    pub token: String,
    pub user_id: i32,
    pub ip_address: Option<String>,
    pub device_id: Option<String>,
    pub expires_at: NaiveDateTime,
}