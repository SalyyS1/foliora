# Verification — 2026-09-22

This is a fresh environment snapshot for the Windows harness and frontend
delivery gates. It does not replace the historical PostgreSQL/LocalFileSystem
evidence in [verification-2026-09-13](verification-2026-09-13.md), and it does
not establish an actual S3/MinIO restore.

## Fresh evidence

| Check | Result | Boundary |
| --- | --- | --- |
| `scripts/test-sync-tooling.ps1` | **12/12 passed**; PowerShell 7.6.5, Node.js 24.12.0. A clean-checkout simulation also passed 12/12 and created its missing `.test-build` parent. | Exercises owned-process/checkpoint mechanics only; no PostgreSQL or S3. |
| `node scripts/build-context.test.mjs` | **2/2 passed**. | Checks `.dockerignore`/`.gitignore` policy, not a Docker build. |
| PowerShell parser checks | **Passed** for the native drill, tooling harness, helper, and report files. | Syntax only. |
| `cargo fmt --all -- --check` | **Passed**. | Formatting only. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | **Passed**. | Lint gate; current host Rust is 1.98.0, not the 1.88 MSRV toolchain. |
| Rust 1.88 `cargo check --locked --workspace -j1` | **Passed** after locking `aes` to 0.9.2; all 8 workspace crates compiled with the declared MSRV. | Clean MSRV target directory; not a Rust 1.88 test run. |
| Rust 1.88 `cargo test --locked --workspace -j1` | **Passed**: 196 passed, 0 failed, 5 ignored. | Clean Windows MSRV target; the five ignored integration tests require disposable PostgreSQL/S3 services. |
| `pnpm check` | **Passed** in the current workspace after dependencies were available. | TypeScript checks; not runtime behavior. |
| `pnpm test` | **Passed**; build-context 2/2, extension 13/13, desktop 2/2, plus schema/protocol/locales checks. | Workspace JavaScript tests; does not exercise native Tauri packaging. |
| Site build + `validate:artifact` | **Passed**; Vite emitted a static artifact and the artifact verifier passed. | Does not prove deployment or browser compatibility on every supported OS. |
| Desktop web build | **Passed**; TypeScript and Vite build completed. | Does not prove Tauri native packaging. |
| Windows Tauri `build --no-bundle` | **Passed**; release executables were produced with the target and temporary directories on `D:` to avoid linker temporary-file pressure on `C:`. | Confirms native compilation only; installers, signing, OCR resources, and native-host registration remain separate release gates. |
| Native-host registration and binary smoke | **Passed**; the built native host failed closed when the desktop bridge was absent, and Chromium/Firefox manifest plus Windows registry targets were rendered in dry-run mode without changing user registry or files. | Registration was intentionally dry-run only; browser store packaging and an installed-extension end-to-end smoke remain open. |
| `cargo test --locked --workspace -j1` | **Passed**: 196 passed, 0 failed, 5 ignored. | The ignored integration tests require disposable PostgreSQL and S3-compatible services. A previous parallel attempt failed from Windows paging-file exhaustion (OS error 1455), not a source diagnostic; the sequential run passed. |
| Disposable PostgreSQL 16 + Moto 5.2.3 durable drill | **Passed**: restart durability, quota atomicity, legacy migration authorization, backup seed, and destructive database/object restore verification. | Real PostgreSQL and S3-compatible HTTP/object semantics through Moto; this is local integration evidence and does not replace the pinned MinIO CI run. |

The lockfile pins `aes` to 0.9.2 because `aes` 0.9.3 raises its declared
minimum Rust version to 1.89; this keeps the workspace's stated Rust 1.88
MSRV enforceable while retaining the current `lopdf` API.

## Open gates

- The native S3/MinIO drill has **not** run. `dl.min.io` returned HTTP 410 for
  the historical fixture binary because the upstream archive no longer serves
  community binaries. A SourceForge mirror was investigated but did not yield a
  verified binary within the available transfer window; no unverified executable
  is accepted.
- A local PostgreSQL + Moto S3-compatible drill now covers the durable scenarios
  listed above, including a destructive restore. MinIO-specific CI execution
  remains required because Moto does not prove MinIO behavior or production
  object-store compatibility.
- Rust 1.88 MSRV compilation and workspace test execution are established by
  clean Windows runs above; the hosted `sync-msrv` job remains the reproducible
  release gate and checks the complete workspace before building the sync
  service.
- Sustained load, cross-store clock drift, independent protocol review,
  coordinated client epoch rotation, OCR packaging, signed installers,
  native-host registration, hosted operations, and user/pilot evidence remain
  release gates listed in [the roadmap](project-roadmap.md).

No full-project completion claim is supported by this snapshot.
