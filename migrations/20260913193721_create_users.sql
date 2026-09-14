-- +goose Up
CREATE TABLE users
(
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    email varchar(254) NOT NULL CHECK(TRIM(email) <> '' AND email = TRIM(email)),
    display_name varchar(100) NOT NULL CHECK(TRIM(display_name) <> '' AND display_name = TRIM(display_name)),
    password_hash text NOT NULL CHECK(TRIM(password_hash) <> '' AND password_hash = TRIM(password_hash)),
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX users_email_idx ON users (LOWER(email));

-- +goose Down
DROP TABLE users;
