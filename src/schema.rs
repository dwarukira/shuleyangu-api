// @generated automatically by Diesel CLI.

diesel::table! {
    states (id) {
        id -> Int4,
        url -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        first_name -> Varchar,
        last_name -> Varchar,
        middle_name -> Nullable<Varchar>,
        email -> Nullable<Varchar>,
        phone -> Nullable<Varchar>,
        password -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        github_id -> Nullable<Varchar>,
        email_verified_at -> Nullable<Timestamptz>,
        email_verification_token -> Nullable<Varchar>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    states,
    users,
);
