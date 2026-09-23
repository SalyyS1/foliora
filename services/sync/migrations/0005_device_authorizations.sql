ALTER TABLE devices
    ADD COLUMN authorization_grant JSONB,
    ADD COLUMN is_root BOOLEAN NOT NULL DEFAULT FALSE;

-- create_vault inserted the vault and original device in the same transaction,
-- so their now() defaults are identical. Timestamp ordering is not identity:
-- a later pairing can predate the root after a database clock rollback.
-- Require exactly one matching device per vault, and require it to be active.
-- Missing, ambiguous, or revoked evidence must never promote another credential.
DO $$
BEGIN
    IF EXISTS (
        SELECT vault.vault_id
        FROM vaults AS vault
        LEFT JOIN devices AS device
            ON device.vault_id = vault.vault_id
            AND device.created_at = vault.created_at
        GROUP BY vault.vault_id
        HAVING count(device.device_id) <> 1
            OR count(device.device_id) FILTER (WHERE device.active) <> 1
    ) THEN
        RAISE EXCEPTION 'Cannot migrate missing, revoked, or ambiguous legacy root evidence; recover local data into a fresh sync vault using the previous binary before upgrading';
    END IF;
END $$;

UPDATE devices AS device
SET is_root = TRUE
FROM vaults AS vault
WHERE device.vault_id = vault.vault_id
  AND device.created_at = vault.created_at;

ALTER TABLE devices
    ALTER COLUMN is_root DROP DEFAULT;

ALTER TABLE devices
    ADD CONSTRAINT devices_authorization_shape CHECK (
        authorization_grant IS NULL
        OR (
            NOT is_root
            AND authorization_grant->'grant'->'recipient'->>'deviceId' IS NOT NULL
            AND authorization_grant->'grant'->'recipient'->>'deviceId' = device_id
        )
    ),
    ADD CONSTRAINT devices_root_has_no_authorization CHECK (
        NOT is_root OR authorization_grant IS NULL
    );

CREATE UNIQUE INDEX devices_one_root_per_vault_idx
    ON devices(vault_id)
    WHERE is_root;
