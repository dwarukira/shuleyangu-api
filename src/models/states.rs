
use chrono::{NaiveDateTime};
use serde::{
    Deserialize,
    Serialize,
};
use diesel::prelude::*;
use crate::schema::states;


#[derive(Queryable, Debug, Serialize, Deserialize)]
pub struct States {
    pub id: i32,
    pub url: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Debug, Serialize, Deserialize)]
#[table_name = "states"]
pub struct NewStates {
    pub url: String,
    pub expires_at: NaiveDateTime,
}