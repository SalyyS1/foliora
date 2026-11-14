# Foliora 0.1.0

Foliora is a provisional product codename for a desktop-first personal context pack app. Name, domain, trademark, and package availability are not cleared yet.

This repository is an engineering release candidate. See
[CHANGELOG.md](CHANGELOG.md) and [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
for verified capabilities and remaining production gates.

Foliora helps people turn selected local documents into a clear, reviewable pack with sources. The core product is planned to work offline first; optional AI, sync, and browser filling must stay preview-first and opt-in.

For Vietnamese launch copy, see [docs/marketing-facebook-vi.md](docs/marketing-facebook-vi.md).

## Tiếng Việt

Foliora là tên tạm thời cho ứng dụng tạo hồ sơ ngữ cảnh cá nhân. Tên này chưa được kiểm tra pháp lý, domain, trademark hoặc registry package.

Mục tiêu: người dùng nhập tài liệu của họ, xem nguồn và dữ kiện, chọn phần muốn chia sẻ, rồi xuất pack. Core không được phụ thuộc tài khoản, cloud hoặc AI.

## Repository map

```text
apps/desktop/        Tauri + React desktop shell and IPC boundary
apps/extension/      Browser extension boundary; preview-first, no submit
apps/site/           Public site boundary; no production claims before release gate
crates/domain/       Shared Rust domain types and state transitions
crates/vault/        Argon2id + XChaCha20-Poly1305 encrypted local vault
crates/ingestion/    Bounded offline text, PDF, email and PNG/JPEG ingestion + OCR contracts
crates/model/        Preview-first optional OpenAI BYOK suggestion boundary
crates/export/       Reviewed JSON/PDF/Markdown + redacted clipboard exports and audit hashes
crates/sync/         E2EE objects, device signatures and revision DAG protocol
services/sync/       Authenticated PostgreSQL/S3 opaque sync service
packages/schema/     Apache-2.0 JSON schema definitions
packages/protocol/   Apache-2.0 protocol definitions
packages/locales/    Translation resources
templates/           Pack templates
assets/brand/        Provisional brand assets and usage notes
tests/fixtures/      Synthetic fixtures only
tests/e2e/           End-to-end test boundary
```

## Development

Requirements are intentionally minimal for the skeleton:

- Node.js 22+
- pnpm 10+
- Rust 1.88+

```sh
pnpm install
pnpm check
cargo check --workspace
```

The current foundation implements versioned claim/provenance contracts, three bilingual workflow templates, deterministic offline ingestion for UTF-8 plain text/Markdown/pasted text, native-text and password-protected PDFs, RFC 5322 `.eml` messages, and PNG/JPEG images, an encrypted local vault, and exact-preview reviewed JSON/PDF exports. Imports are content-addressed with SHA-256, size-limited, binary-safe, and idempotent; text candidates must point to an exact source substring, PDF page span, or validated image region. PDF parsing bounds file size, page count, per-page decompression and total extracted text; image-only documents fail closed for OCR. Email parsing bounds MIME parts and decoded bytes, prefers plain text, converts HTML to inert text, and represents decoded body/attachments as independently fingerprinted sources so citations remain exact. Image parsing sniffs bytes instead of trusting extensions, fully decodes within dimension/pixel/allocation limits, records display orientation, and creates an in-memory normalized PNG. The Tesseract worker sends that PNG over pipes without plaintext temporary files, enforces a deadline/output cap, parses TSV into bounded regions, and retains engine/version/language/quality metadata; OCR can only create review-required candidates. Vault files use Argon2id-derived keys and XChaCha20-Poly1305 authenticated encryption. Export blocks unconfirmed, conflicting, expired, missing-evidence, duplicate, or unapproved sensitive claims. PDF output embeds caller-supplied Unicode font bytes, includes an evidence index and caution notice, and hashes the exact artifact for audit; the desktop package must ship a redistributable font covering its supported locales.

The Tauri 2 + React desktop shell now builds and launches on Windows. Its narrow
IPC creates and opens encrypted vaults, reports non-content counts, supports
manual locking, and enforces a bounded inactivity lock in Rust. Passphrases are
zeroized after each command and are never returned to the webview. The first real
workspace journey imports bounded text/Markdown, native-text PDF, `.eml`, PNG,
and JPEG
files directly in Rust. It accepts password-protected PDFs through a transient
in-memory password used only for extraction and per-view unlocking; the original
encrypted bytes stay the source of record. It previews encrypted source text or page-aware PDF text,
shows inert email headers, exposes independently fingerprinted body/attachments,
converts a user-selected UTF-8 byte span into a candidate, and persists explicit
confirm/reject review transitions. Multi-part email imports commit atomically. It
shows conflicts without selecting a winner. Images are decoded under strict
limits, orientation-normalized in Rust, and sent to the viewer over binary IPC.
The desktop also composes the three production templates, reports
ranked missing information, requires per-claim approval for private data, and
writes a full exact-preview JSON payload with an audit SHA-256, rejects stale
previews, and never overwrites an existing destination. Clipboard export adds an
exact preview, per-claim redaction, transitive evidence removal, localized safety
framing, and an audit hash. Citation-grounded Markdown export (`export_reviewed_markdown`)
renders deterministic tables with exact source byte/page/region citations (`[E1: p.2, bytes 10..48]`),
escapes untrusted control and table-breaking characters against prompt or markup injection,
prunes orphaned evidence transitively when claims are redacted, and emits a SHA-256 audit digest
for LLM context workflows. Portable `.foliora-pack` archives are deterministic
standard ZIP files containing only reviewed JSON, a versioned manifest, and a
localized warning—never original source blobs by default. Searchable PDF export
embeds Noto Sans, previews the exact cached bytes through binary IPC, invalidates
that preview on vault changes/lock, and writes only the PDF the user reviewed.
For PNG/JPEG sources, the desktop discovers only an application-packaged
Tesseract runtime with pinned Vietnamese and English models, runs it under the
bounded pipe-only worker, overlays recognized regions on the normalized image,
and lets the user turn one reviewed region into a source-backed candidate. The
control stays visibly unavailable when those package resources are absent.
For UTF-8 text sources, an optional OpenAI BYOK assistant can suggest exact
source spans. Foliora first renders the complete request JSON, disclosure and
redaction counts, and SHA-256; it sends only after explicit consent and rejects
stale previews, incomplete responses, non-unique quotes, or quotes absent from
the source. The endpoint is fixed to HTTPS, provider storage is disabled in the
request, no tools are enabled, the API key is transient, and suggestions remain
unsaved candidates until the user creates and reviews them. The offline/manual
journey remains fully functional without a provider; see
`docs/model-assistance.md`.
An unlocked vault can also create a verified encrypted `.foliora-backup`
snapshot. Restore authenticates that snapshot with the passphrase and writes to
a new `.vault` destination only; existing files are never overwritten, and the
restored vault is validated again before it is opened.
New vaults require a separately stored recovery kit before the workspace opens.
The native core generates a one-time 256-bit recovery code, wraps the vault key
with XChaCha20-Poly1305, and never stores that code in the vault or kit. Recovery
requires the encrypted backup, matching kit, and code, then re-encrypts the
restored data under a new passphrase and a fresh Argon2id salt.
Users can rotate recovery from Desktop: Foliora verifies the current passphrase,
creates a new key/salt epoch and kit, invalidates old kits against the current
vault, and requires confirmation of the new one. Externally copied artifacts
remain the user's responsibility to destroy.

Platform-built Tesseract binaries and Vietnamese/English OCR assets, billing,
signed installers, and production packaging are not implemented yet. See
`docs/threat-model.md` for security boundaries and limitations.

The sync foundation encrypts objects client-side with per-epoch XChaCha20 keys,
content-addresses ciphertext, signs canonical append-only manifests with
Ed25519 device identities, represents deletion as tombstones, and preserves
concurrent offline revisions as multiple DAG heads until an explicit merge. The
opaque service core enforces device status, epoch rotation on revoke, quota,
idempotent object upload, parent/object existence, per-device sequence replay
protection, and atomic manifest commit. Its HTTP v1 transport uses separately
hashed per-device bearer credentials, strict path/payload binding, bounded
bodies, signed pairing, immediate credential revocation, honest health,
label-free Prometheus metrics, grace-period collection of bucket orphans and
metadata-tracked uploads that never reach a manifest, and
inactive, expiring two-phase device pairing registrations. Protected `/v1`
traffic is guarded before body parsing by bounded in-process token buckets: a
global ceiling plus per-credential budgets keyed only by the bearer token's
SHA-256 digest. PostgreSQL persists
transactional metadata and S3-compatible storage
holds immutable encrypted objects; ephemeral storage requires an explicit
development flag. Desktop sync configuration, encrypted pending pairing
requests, signed trusted-device grants, confirmation-code verification, and
initial remote snapshot bootstrap are implemented. Pending pairing confirmation
allows four failed valid-code attempts; the fifth atomically destroys the
registration, including across service restart. The client retries only
proven-idempotent GET/PUT and activation operations, caps attempts/delays and
the overall operation, honors bounded numeric `Retry-After`, and never retries
authentication, validation, conflict or unsafe side-effecting operations.
Routed requests also have a deadline and object transfers have a process-local
pre-body concurrency cap. Multi-replica shared edge/IP/byte controls and the
remaining managed hosted operations remain release work. See
`docs/sync-service.md`.

The extension now builds separate Chromium and Firefox MV3 artifacts with no
persistent host permissions. Its tested policy requires an HTTPS active-tab
gesture, a frozen approved claim subset and exact preview; navigation or DOM
changes make that preview stale. It blocks hidden/password/payment/OTP fields
and never submits forms. The desktop now issues five-minute exact-origin grants
for user-selected claims, freezes their values, and serves them through a
bounded native-messaging companion authenticated by a per-run 256-bit local
capability. Locking or changing approved claim state/value invalidates access.
Browser host registration is installer work and never uses wildcard extension
origins; see `docs/browser-extension.md`.

### Verified commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm check
pnpm test
pnpm --filter @foliora/site run build
pnpm --filter @foliora/site run validate:artifact
pnpm --filter @foliora/desktop run build
# Windows native smoke artifact (requires Tauri prerequisites):
pnpm --filter @foliora/desktop exec tauri build --no-bundle
# Windows harness process/checkpoint regressions (does not start PostgreSQL/S3):
pwsh -NoProfile -File scripts/test-sync-tooling.ps1
# Requires disposable PostgreSQL and S3-compatible endpoints (CI provisions them):
cargo test --locked -p foliora-sync-service --test durable_repository encrypted_object_and_manifest_survive_repository_restart -- --ignored --exact --nocapture
cargo test --locked -p foliora-sync-service --test durable_repository durable_quota_boundaries_are_atomic -- --ignored --exact --nocapture
```

Do not run all ignored durable tests together. Fixture seeding and verification
must run in order around an actual PostgreSQL and object-store backup/restore;
follow the [ordered backup/restore runbook](docs/sync-backup-restore.md) and
[CI workflow](.github/workflows/ci.yml).

## Licensing

Application, services, extension, and desktop code are intended to be AGPL-3.0-or-later.

Independent schema/protocol definitions and conformance samples are Apache-2.0 so other implementations can interoperate without inheriting the application license.

See `LICENSE`, `NOTICE`, `packages/schema/LICENSE`, and `packages/protocol/LICENSE`.
