# Changelog

All notable changes to Foliora are documented here.

## 0.1.0 — 2026-09-23

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
