CREATE TABLE pending_pairings (
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    record JSONB NOT NULL,
    signed_grant JSONB NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    confirmation_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, device_id),
    CHECK (octet_length(token_hash) = 32),
    CHECK (octet_length(confirmation_hash) = 32),
    CHECK (expires_at > created_at)
);

CREATE INDEX pending_pairings_expiry_idx ON pending_pairings(expires_at);
