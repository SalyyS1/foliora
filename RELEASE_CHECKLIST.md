# Release checklist

## Completed for 0.1.0 engineering release candidate

- [x] README, license boundary, NOTICE and security policy present.
- [x] AGPL application boundary and Apache-2.0 schema/protocol boundary documented.
- [x] Rust fmt, Clippy, workspace tests and Rust 1.88 workspace tests pass.
- [x] JavaScript checks/tests, site build and artifact validation pass.
- [x] Windows Tauri native build produces desktop and native-host executables.
- [x] Native host fails closed without a running authenticated desktop bridge.
- [x] Local PostgreSQL + Moto durable restart/quota/migration/restore evidence recorded.
- [x] CI includes Windows native build and disposable PostgreSQL/MinIO integration jobs.

## Required before production release

- [ ] Stage and verify Tesseract 5.5.0 plus Vietnamese/English models for each target.
- [ ] Run OCR synthetic, corrupt-input, timeout, rotation and offline package tests.
- [ ] Produce signed Windows installer/updater and test rollback/update security.
- [ ] Produce macOS notarized and Linux AppImage/deb artifacts.
- [ ] Run pinned MinIO or selected maintained S3-compatible provider restore evidence.
- [ ] Run sustained-load and cross-store clock-drift drills.
- [ ] Complete independent protocol, dependency and SBOM review.
- [ ] Complete browser store/native-host installed-extension smoke.
- [ ] Complete hosted backup, restore, TLS, secret rotation and operations evidence.
- [ ] Complete user/pilot acceptance and legal/trademark/domain clearance.
