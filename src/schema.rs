// @generated automatically by Diesel CLI.

diesel::table! {
    sessions (id) {
        id -> Int4,
        user_id -> Int4,
        token -> Varchar,
        device_id -> Nullable<Varchar>,
        ip_address -> Nullable<Varchar>,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
    }
}

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

diesel::table! {
    verification_codes (id) {
        id -> Int4,
        code -> Text,
        identifier -> Text,
        expires_at -> Timestamp,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::joinable!(sessions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    sessions,
    states,
    users,
    verification_codes,
);
