# Codebase summary

## Current implementation

- Domain: versioned bilingual pack templates, provenance locators, validity and
  conflict contracts with 18 unit tests.
- Vault: Argon2id + XChaCha20-Poly1305 encrypted persistence, backup/recovery,
  transactional source/claim/bundle mutations, and encrypted sync profile.
- Ingestion: bounded UTF-8/Markdown, native-text/password-protected PDF, EML,
  PNG/JPEG and optional pipe-only Tesseract OCR contracts with compiled
  full-resource SHA-256 inventory validation.
- Model: optional fixed-endpoint OpenAI Responses BYOK adapter with exact
  redacted request preview, payload freshness hash, bounded I/O and unique
  source-quote validation. It returns suggestions without persisting them.
- Export: reviewed deterministic JSON, redacted clipboard, portable archive and
  searchable PDF with evidence index and audit fingerprints.
- Sync: E2EE object/manifest DAG, durable HTTP service adapters, optional
  client-side HTTPS sync, encrypted pending pairing, ten-minute request expiry,
  two-phase confirmation-code activation with abandoned-registration cleanup
  and persistent five-attempt lockout,
  initial remote bootstrap, resumable grace-period staged/orphan ciphertext collection and
  label-free Prometheus service metrics. Protected service routes have bounded
  pre-body global/per-credential request buckets with aggregate 429 metrics.
  The HTTP client has bounded,
  idempotency-aware retry with partition and temporary-status tests.
- Sync maintenance: `services/sync/src/durable/integrity.rs` streams SQL rows
  and object chunks, verifies physical payload SHA-256, and counts untracked
  bucket objects. `--verify-integrity --inventory-jsonl` additionally hashes
  every `v1` bucket entry, including untracked objects, for sorted live/restored
  comparisons. Verification uses read-only PostgreSQL connections;
  no migrations, HTTP listener, or background writes. Stop all writers and GC
  during verification. Two-phase staged GC persists `deleting` before physical
  deletion, then removes metadata/accounting under locks; retries resume after
  interruption. Manifest commits reject deleting rows until upload verifies or
  repairs the bytes and reactivates them. New/repair writes use fresh random
  physical storage generations so delayed DELETEs affect retired keys only.
  Migration 0005 requires exactly one device with `created_at` equal to the
  vault's creation time, and requires that device active; timestamp ordering
  cannot establish root identity. Committed history remains retained.
- Desktop: Tauri 2 + React shell, local workspace, extension bridge, sync and
  pairing commands, plus opt-in native OS-keychain quick unlock.
  Session-generation guards reject async results after lock/reopen, including
  the same vault path. Profile/pending-pairing and snapshot checks protect
  pairing and downloads; a committed upload can persist its checkpoint after
  local edits without replacing those edits. Regression fixtures are present;
  execution evidence is tracked separately below.
- Web/extension: bilingual static public demo with Vite artifact validation and
  Chromium/Firefox MV3 policy-first builds.

## Intentionally incomplete

Packaged Tesseract/OCR assets, hosted
billing/operations, signed production installers and
independent cryptographic review remain release phases. These omissions are
visible in the UI/docs and do not weaken the offline core.

## Verification and plan alignment

See [2026-09-13 verification](verification-2026-09-13.md) for confirmed results,
including 33 service tests and two fresh PG16.11 + LocalFS scenarios passed.
The revised migration passed one test with nine fixtures; isolated PG dump/copy
restore passed with five matching physical keys/hashes, including untracked data.
Full workspace tests passed 196; all five aggregate-ignored environment tests
passed explicitly. Frontend/site checks, formatting, Clippy, and Actionlint
passed; S3 restore evidence is absent. The record also tracks release gates.
The parent Continuum plan remains proposed with incomplete
user/pilot validation; its phases do not map directly to the current roadmap.
Implementation inventory is not full plan completion or a completion percentage.
