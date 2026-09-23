CREATE TABLE vaults (
    vault_id TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    quota_bytes BIGINT NOT NULL CHECK (quota_bytes > 0),
    used_bytes BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0 AND used_bytes <= quota_bytes),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    record JSONB NOT NULL,
    token_hash BYTEA UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, device_id),
    CHECK ((active AND token_hash IS NOT NULL) OR (NOT active AND token_hash IS NULL))
);

CREATE INDEX devices_token_hash_idx ON devices(token_hash) WHERE active;

CREATE TABLE objects (
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    object_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    ciphertext_bytes BIGINT NOT NULL CHECK (ciphertext_bytes > 0),
    storage_key TEXT NOT NULL UNIQUE,
    payload_sha256 BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, object_id)
);

CREATE TABLE manifests (
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    revision_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    device_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    signed_manifest JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, revision_id),
    UNIQUE (vault_id, device_id, sequence)
);

CREATE TABLE manifest_parents (
    vault_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, revision_id, parent_id),
    FOREIGN KEY (vault_id, revision_id) REFERENCES manifests(vault_id, revision_id) ON DELETE CASCADE
);

CREATE TABLE manifest_objects (
    vault_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, revision_id, object_id),
    FOREIGN KEY (vault_id, revision_id) REFERENCES manifests(vault_id, revision_id) ON DELETE CASCADE,
    FOREIGN KEY (vault_id, object_id) REFERENCES objects(vault_id, object_id)
);

CREATE TABLE heads (
    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
    revision_id TEXT NOT NULL,
    PRIMARY KEY (vault_id, revision_id),
    FOREIGN KEY (vault_id, revision_id) REFERENCES manifests(vault_id, revision_id) ON DELETE CASCADE
);
