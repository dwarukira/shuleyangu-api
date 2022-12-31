
use chrono::NaiveDateTime;
use diesel::Queryable;
use serde::{Deserialize, Serialize};
use crate::schema::verification_codes;
use diesel::prelude::*;

#[derive(Queryable, Serialize, Deserialize, Debug)]
pub struct VerificationCode {
    pub id: i32,
    pub code: String,
    pub identifier: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}


#[derive(Debug, Serialize, Deserialize, Insertable)]
#[table_name = "verification_codes"]
pub struct NewVerificationCode {
    pub code: String,
    pub identifier: String,
    pub expires_at: NaiveDateTime,
}