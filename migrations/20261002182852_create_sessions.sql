-- +goose Up
CREATE TABLE sessions
(
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL CHECK(octet_length(token_hash) = 32),
    csrf_token_hash bytea NOT NULL CHECK(octet_length(csrf_token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT NOW(),
    last_seen_at timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_reason TEXT,
    
    CONSTRAINT sessions_last_seen_after_creation
        CHECK (last_seen_at >= created_at),

    CONSTRAINT sessions_idle_expiry_after_creation
        CHECK (expires_at > created_at),

    CONSTRAINT sessions_absolute_expiry_after_creation
        CHECK (absolute_expires_at > created_at),

    CONSTRAINT sessions_idle_before_absolute
        CHECK (expires_at <= absolute_expires_at),

    CONSTRAINT sessions_revoked_reason_requires_revocation
        CHECK (revoked_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE UNIQUE INDEX sessions_token_hash_idx ON sessions(token_hash);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);

-- +goose Down
DROP TABLE sessions;
