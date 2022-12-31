CREATE TABLE verification_codes (
    id SERIAL PRIMARY KEY,
    code text NOT NULL,
    identifier text NOT NULL,
    expires_at TIMESTAMP NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);