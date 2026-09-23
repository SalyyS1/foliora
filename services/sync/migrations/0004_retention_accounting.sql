ALTER TABLE manifests
    ADD COLUMN encoded_bytes BIGINT NOT NULL DEFAULT 0;

UPDATE manifests
SET encoded_bytes = octet_length(signed_manifest::text);

ALTER TABLE manifests
    ALTER COLUMN encoded_bytes DROP DEFAULT,
    ADD CONSTRAINT manifests_encoded_bytes_positive CHECK (encoded_bytes > 0);

ALTER TABLE objects
    ADD COLUMN accounting_version SMALLINT NOT NULL DEFAULT 1;

ALTER TABLE objects
    ALTER COLUMN accounting_version DROP DEFAULT,
    ADD CONSTRAINT objects_accounting_version_current CHECK (accounting_version = 1);

ALTER TABLE vaults
    ADD COLUMN object_count BIGINT NOT NULL DEFAULT 0
        CHECK (object_count >= 0),
    ADD COLUMN manifest_count BIGINT NOT NULL DEFAULT 0
        CHECK (manifest_count >= 0),
    ADD COLUMN manifest_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (manifest_bytes >= 0);

UPDATE vaults AS vault
SET object_count = (
        SELECT count(*) FROM objects WHERE objects.vault_id = vault.vault_id
    ),
    manifest_count = (
        SELECT count(*) FROM manifests WHERE manifests.vault_id = vault.vault_id
    ),
    manifest_bytes = (
        SELECT coalesce(sum(encoded_bytes), 0)
        FROM manifests
        WHERE manifests.vault_id = vault.vault_id
    );

ALTER TABLE manifest_parents
    ADD CONSTRAINT manifest_parents_parent_fk
    FOREIGN KEY (vault_id, parent_id)
    REFERENCES manifests(vault_id, revision_id)
    ON DELETE RESTRICT;

CREATE INDEX objects_created_idx ON objects(vault_id, created_at);
CREATE INDEX manifest_objects_object_idx ON manifest_objects(vault_id, object_id);
