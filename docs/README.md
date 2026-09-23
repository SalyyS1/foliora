# Foliora documentation

Foliora is an in-development, provisional product codename.

See [codebase summary](codebase-summary.md) for module boundaries and
[2026-09-13 verification](verification-2026-09-13.md) for actual evidence,
release gates, and unresolved mapping to the older Continuum research plan.

## Implemented foundation

- Domain contracts: source provenance, claim state transitions, validity windows,
  conflict detection, completeness, and bundle-draft validation.
- Ingestion: UTF-8 text/Markdown/paste, bounded native-text PDFs, RFC 5322 email
  with MIME attachments, and fully validated PNG/JPEG images. Sources use SHA-256
  identity; candidate evidence uses exact spans, page spans, or bounded regions.
  The Tesseract subprocess receives an orientation-normalized PNG over pipes,
  enforces timeout/output limits, and emits region contracts preserving
  engine/version/language/confidence. OCR never promotes output beyond candidate.
- Encrypted local vault: Argon2id key derivation, XChaCha20-Poly1305 authenticated
  encryption, source/blob integrity checks, recoverable saves, and no-overwrite
  creation semantics. See `threat-model.md` for explicit limits.
- Reviewed JSON export: exact preview/payload parity, confirmed-claim enforcement,
  explicit sensitive-data approvals, evidence index, expiry/conflict checks, and a
  SHA-256 audit event. The Apache-2.0 schema and synthetic conformance fixture live
  in `packages/schema` and `tests/fixtures`.
- Redacted clipboard export: deterministic JSON wrapped with an untrusted-data
  notice, transitive removal of orphaned evidence, unknown/total-redaction guards,
  and an audit hash over the exact clipboard bytes.
- Portable archive export: deterministic standard ZIP output with a versioned
  manifest, exact reviewed JSON, localized safety guidance, per-entry hashes, and
  no original source documents or attachments by default.
- Reviewed PDF export: desktop-packaged Noto Sans with Vietnamese coverage,
  caution notice, confirmed claims, evidence index, pagination, binary exact
  preview, cache invalidation on mutation/lock, and hash over the exact artifact.
- Bundle composition: versioned Vietnamese/English manifests for warranty or
  insurance, medical-visit information, and project handoff. One deterministic
  engine reports confirmed/required counts, missing questions, candidates,
  conflicts, and explicit-expiry exclusions without silently choosing values.
- Public preview site: bilingual Vietnamese/English trust UI with a verified Vite
  build artifact. It is a local demo and does not parse or upload documents.
- Desktop shell: a bilingual Tauri 2 + React vault entry and evidence-review
  journey. It creates/opens/locks a vault; imports bounded text/Markdown,
  native-text or password-protected PDF and EML in Rust; previews exact text or PDF page spans; asks
  for a protected PDF password again when viewing it later without storing that
  password; and shows inert email metadata with independently stored body/attachments. EML
  source batches commit atomically. User-selected evidence becomes a candidate
  with persisted confirm/reject transitions, while conflicts stay visible. The
  shell has a restrictive CSP and generated Windows/macOS/Linux icon
  assets from one original SVG. A Windows release executable has been built and
  process-smoked locally; installer and other-OS evidence are still required.
- Optional model assistance: OpenAI BYOK for selected UTF-8 text sources, with
  literal redaction, complete payload preview/hash, explicit per-request
  consent, transient credentials, bounded responses and exact-quote grounding.
  Suggestions are never persisted until the user creates a normal candidate.
  See `model-assistance.md`.
- Sync protocol and service: client-encrypted XChaCha objects, Ed25519 manifests,
  trusted-device epoch-key pairing, replay/quota/revoke invariants, and an
  authenticated bounded HTTP v1 API, PostgreSQL transactional metadata and
  immutable S3-compatible ciphertext storage. Desktop configuration and
  two-phase copy/paste pairing, abandoned-registration cleanup, resumable
  staged/orphan-object collection, aggregate metrics and pre-body single-process request limiting
  are implemented. Staged GC marks deletion durably before physical removal and
  metadata/accounting cleanup. Fresh random physical generations for new/repair
  writes isolate them from delayed DELETEs of retired keys. Root migration
  requires a unique device matching vault creation time and that device active.
  The streaming `--verify-integrity` maintenance command checks tracked hashes;
  `--inventory-jsonl` also hashes every `v1` bucket entry, including untracked
  objects, for live/restored comparisons. It uses read-only SQL, with no
  migrations, HTTP listener, or background writes; all writers/GC must be stopped.
  Desktop session-generation, profile, and snapshot guards protect async sync
  and pairing application while preserving committed upload checkpoints after
  local edits. CI defines a destructive PostgreSQL plus object-store restore
  drill; no actual MinIO execution is confirmed in this verification record. A
  disposable PostgreSQL + Moto 5.2.3 S3-compatible drill covered restart,
  quota, migration, and destructive restore behavior; MinIO-specific and
  production-storage evidence remains open.
  After review-driven changes, 33 service tests and two fresh PG16.11 + LocalFS
  scenarios passed; desktop focused regressions also passed. Nine migration
  fixtures passed within one test. Isolated PostgreSQL dump/copy restore passed,
  with all five physical keys/hashes matching, including untracked data.
  Full workspace tests passed 196, with all five aggregate-ignored environment
  tests also passed explicitly. Frontend/site checks, formatting, Clippy, and
  Actionlint passed. These results do not establish S3 or production readiness.
  Protocol v1's conservative historical retention is documented;
  hosted off-site backup operations, shared edge abuse controls, alerting and
  capacity operations remain deployment work. See `sync-protocol.md`,
  `sync-service.md`, and `sync-backup-restore.md`.
- Browser extension: Chromium/Firefox MV3 artifacts, active-tab-only injection,
  exact-origin five-minute desktop grants, a bounded native companion, frozen
  approved claims, stale-page invalidation, and no form submission. See
  `browser-extension.md`.
- Desktop convenience: an explicit opt-in stores a vault passphrase only in
  the native Windows Credential Manager, macOS Keychain, or Linux credential
  store; the webview never receives it. This does not replace the vault
  passphrase or recovery materials.

## Not implemented yet

Platform-built OCR binaries/models, signed native
installers, and hosted operations remain future phases.
Imported document content is untrusted data and must never be executed as
instructions by later adapters.

The older parent plan's interviews, demand validation, and pilot acceptance
remain incomplete/unverified. Current implementation does not close those gates;
see the dated verification record for the unresolved phase-to-roadmap mapping.
