# Changelog

All notable changes to Foliora are documented here.

## 0.2.0 - 2026-11-14

Context pack verification, indirect prompt-injection scanning, Markdown context export, and dependency security hardening.

### Included

- Added fail-closed `verify_reviewed_bundle` and `verify_portable_archive` in `foliora-export` enforcing schema contracts, canonical UTC timestamps, bundle expiry, referential evidence integrity, orphan-evidence rejection, conflict checks, bounded 16 MiB per-entry ZIP extraction, and constant-time SHA-256 `ExportAuditEvent` binding.
- Added `scan_bundle_hazards` detecting indirect prompt-injection and smuggling patterns (`FP001` Unicode BiDi controls, `FP002` Plane-14 tag and zero-width characters, `FP003` ChatML/XML/instruction-override markers, and `FP004` external Markdown image beacons) across nested JSON claim values and evidence titles.
- Added deterministic citation-grounded Markdown context pack exporter (`export_reviewed_markdown`) with control/table-injection escaping and transitive evidence pruning.
- Upgraded `zip` to 9.5, `object_store` to 0.14, `rustls` to 0.23.46, `rustls-webpki` to 0.103.17, `webpki-roots` to 1.0.12, `quinn-proto` to 0.11.19, and `quinn-udp` to 0.5.16 while preserving Rust 1.88.0 MSRV compatibility and embedding sync SQL migrations without `sqlx-macros`.
- Added automated GitHub Pages deployment workflow for `@foliora/site` and restored disposable S3 durability CI against `motoserver/moto:5.2.3`.

## 0.1.0 - 2026-09-23

Initial engineering release candidate for review.

### Included

- Offline-first encrypted vault with Argon2id and XChaCha20-Poly1305.
- Bounded text, Markdown, PDF, email, PNG/JPEG ingestion with source evidence.
- Review-required claims, provenance, expiry, conflict and completeness checks.
- Deterministic reviewed JSON, PDF, clipboard and portable archive exports.
- Bilingual Vietnamese/English desktop shell, public preview site and browser extension.
- Preview-first optional BYOK model suggestions with literal redaction and exact quote checks.
- End-to-end encrypted sync protocol with PostgreSQL metadata and opaque S3-compatible objects.
- Durable quota, pairing, revocation, migration, restart and backup/restore tests.
- Windows Tauri native build and native-host fail-closed smoke coverage.

### Verification

- Workspace Rust tests: 196 passed, 0 failed, 5 environment tests ignored by default.
- Rust 1.88 Windows workspace tests: 196 passed, 0 failed, 5 environment tests ignored.
- Rust fmt and Clippy: passed.
- JavaScript checks, tests, site artifact validation and desktop web build: passed.
- Local PostgreSQL 16 + Moto 5.2.3 S3-compatible durability and destructive restore drill: passed.
- Windows Tauri `build --no-bundle` and native-host smoke: passed.

### Release limits

This is an engineering release candidate. Tesseract runtime assets, signed
installers, macOS/Linux packaging, MinIO-specific CI evidence, hosted operations,
independent security review and user pilot acceptance remain release gates.
