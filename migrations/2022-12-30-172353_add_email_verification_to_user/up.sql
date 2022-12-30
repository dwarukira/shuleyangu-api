-- Your SQL goes here
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN email_verification_token VARCHAR(255);
