# System architecture

```text
Tauri + React desktop ── narrow IPC ── Rust domain/workspace
        │                              │
        │                              ├─ encrypted local Vault
        │                              ├─ bounded Ingestion/OCR worker
        │                              └─ reviewed Export engines
        │
        ├─ optional HTTPS SyncHttpClient ── opaque sync service
        │                                      ├─ PostgreSQL metadata
        │                                      └─ S3-compatible ciphertext
        ├─ optional previewed HTTPS request ── OpenAI Responses API
        └─ native messaging ── browser extension policy layer
```

## Boundaries

- `crates/domain` owns versioned source, claim, provenance, conflict, validity
  and bundle contracts. It has no filesystem or network access.
- `crates/vault` owns authenticated persistence and transactional state changes.
  Sync profiles and pending pairing private material are stored inside the
  encrypted state; sync snapshots exclude both.
- `crates/ingestion` accepts bounded bytes, sniffs formats, and emits inert
  source records. It never executes imported content.
- `crates/model` builds the exact optional provider payload, applies literal
  redactions, bounds disclosure/response sizes, and accepts only suggestions
  whose quotes occur exactly once in both disclosed and original source text.
  It has no vault mutation API.
- `crates/export` consumes reviewed contracts and produces deterministic,
  auditable artifacts.
- `crates/sync` owns E2EE objects, device signatures, pairing and bounded HTTP.
  It never sends plaintext or epoch keys to the service.
- `services/sync` authenticates devices and enforces opaque DAG, quota, epoch,
  replay and object/manifest invariants. It cannot derive client keys.
- `apps/desktop/src-tauri` is the only native command boundary. Commands return
  safe summaries and generic network errors, not secrets or raw vault state.

## Data flow

1. A source is read under size/decompression limits and content-addressed.
2. A user-selected locator creates a candidate; the user confirms or rejects it.
3. The vault persists the state through an authenticated encrypted envelope.
4. Export engines validate the whole graph, create an exact preview, and write
   only after the reviewed inputs still match.
5. Sync serializes a snapshot without credentials, encrypts it with the epoch
   key, uploads the object, then commits a signed manifest.
6. Optional model assistance separately previews a hashed request, re-creates
   it before an explicit send, releases the vault lock during HTTPS, and returns
   unpersisted suggestions. Creating a candidate reuses normal span validation.

## Threat assumptions

The local OS/user account and unlocked process are trusted boundaries. A sync
service, browser page, imported document and AI provider are untrusted. TLS
protects transport credentials; client encryption and signatures protect vault
confidentiality/integrity. See `threat-model.md` for residual metadata leaks.
