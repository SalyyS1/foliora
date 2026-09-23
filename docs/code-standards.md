# Code standards

## Rust

- Run `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets
  -- -D warnings` before handoff.
- Validate inputs at the boundary. Prefer typed contracts and checked arithmetic
  over implicit coercion or saturating behavior.
- Mutate vault state only after the proposed state validates; use rollback-safe
  persistence for multi-record operations.
- Keep secrets in `Zeroizing` values where practical. Never log passphrases,
  bearer tokens, recovery codes, plaintext, or request bodies.
- Error messages crossing Tauri or HTTP boundaries are generic and actionable;
  cryptographic details belong in tests, not user output.

## TypeScript/React

- Run `pnpm check`, `pnpm test`, and the relevant Vite build.
- Use `textContent`/React text nodes for untrusted or translated text. Any
  structured emphasis must be created as explicit elements.
- Keep network actions opt-in and visible. Every async button has a busy state,
  and failures do not leave stale success UI visible.
- Preserve keyboard focus, localized labels, semantic roles, and reduced-motion
  behavior.

## Tests

Test rejection paths as well as happy paths: malformed/oversized input, stale
revisions, duplicate identifiers, conflicting values, corrupted ciphertext,
revoked devices, request path traversal, and partial persistence. Use synthetic
fixtures only. Network integration tests must use disposable services and be
explicitly ignored when those services are unavailable.
