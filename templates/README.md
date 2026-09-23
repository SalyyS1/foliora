# Templates

Production v1 templates are implemented as versioned manifests in
`crates/domain/src/templates.rs`:

- warranty or insurance claim;
- medical visit information handoff;
- project or client handoff.

Each manifest contains Vietnamese/English labels and questions, required versus
optional claim types, priority, default sensitivity, and a scope disclaimer. The
composer is deterministic: candidates, conflicts, and expired claims are never
silently selected.
