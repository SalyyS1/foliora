ALTER TABLE objects
    ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN deletion_marked_at TIMESTAMPTZ;

ALTER TABLE objects
    ALTER COLUMN lifecycle_state DROP DEFAULT,
    ADD CONSTRAINT objects_lifecycle_state_valid CHECK (
        (lifecycle_state = 'active' AND deletion_marked_at IS NULL)
        OR (lifecycle_state = 'deleting' AND deletion_marked_at IS NOT NULL)
    );

CREATE INDEX objects_staged_gc_idx
    ON objects(lifecycle_state, created_at)
    WHERE lifecycle_state = 'active';

CREATE INDEX objects_deletion_resume_idx
    ON objects(deletion_marked_at)
    WHERE lifecycle_state = 'deleting';
