ALTER TABLE pending_pairings
    ADD COLUMN failed_attempts SMALLINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT pending_pairings_failed_attempts_bounds
        CHECK (failed_attempts >= 0 AND failed_attempts < 5);
