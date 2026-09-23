# Foliora local foundation threat model

Status: implemented foundation, not an independent security audit.

## Protected assets

- Original imported document bytes.
- Source metadata and provenance.
- Future claims, bundles, consent grants, and audit events.
- Vault encryption key while the vault is unlocked.

## Trust boundaries

| Zone | Trusted for | Not trusted for |
|---|---|---|
| Desktop UI | Explicit user intent | Parsing arbitrary documents |
| Ingestion | Size/type validation and deterministic extraction | Instructions embedded in content |
| Vault | Local authenticated encryption and integrity checks | Protecting an already-unlocked process |
| Optional model | Schema-constrained candidate suggestions only | Confirming facts or authorizing export |
| Export | Rendering an approved snapshot | Selecting data without user review |
| Sync server | Storing opaque encrypted objects | Reading plaintext or holding vault keys |
| Native host | Forwarding bounded browser messages for the current OS user | Choosing claims, origins, or submitting forms |

## Implemented controls

- Argon2id password-based key derivation with versioned, bounded parameters.
- XChaCha20-Poly1305 authenticated encryption and a fresh nonce per save.
- Salt and KDF parameters authenticated as associated data.
- Keys and decrypted serialized buffers are zeroized on drop where supported.
- Source blobs are size-limited and checked against their SHA-256 fingerprint.
- Password-protected PDF passwords are borrowed only for bounded in-memory
  import or per-view extraction; the original encrypted bytes remain the stored
  source and the password is never persisted.
- Decrypted state is validated before it becomes available to callers.
- Creating a vault refuses to overwrite an existing vault.
- Saves use a temporary file and retain the prior encrypted file as a backup.
- Imported text remains untrusted data and cannot trigger network/model actions.
- Optional model assistance is dormant until the user selects a UTF-8 text
  source, prepares the complete payload, reviews its SHA-256 and checks explicit
  consent. Literal redactions are applied before preview. The HTTPS endpoint is
  fixed to OpenAI Responses, `store` is false, no tools are enabled, disclosure
  is capped at 64 KiB, and the provider response is capped at 1 MiB.
- The OpenAI API key crosses the webview/native IPC only for the explicit send,
  is cleared from the UI afterward, wrapped in zeroizing Rust storage, and is
  never written to the vault/configuration or included in returned errors.
- Provider output is untrusted. Only completed structured responses are parsed;
  each proposed quote must occur exactly once in disclosed and original text.
  Suggestions are returned without persistence and normal candidate creation
  revalidates the source byte span.
- Native PDF, RFC 5322 email, PNG, and JPEG parsing enforce file/part/page,
  decoded-byte, dimension, pixel, or allocation limits as applicable.
- OCR output contracts require bounded image regions and explicit
  engine/version/language/confidence metadata; output remains a candidate.
- The Tesseract boundary uses an absolute executable path, verifies requested
  trained-data files, pipes an orientation-normalized PNG through stdin/stdout,
  caps output, applies a deadline, and does not create plaintext temporary files.
- Desktop vault ownership is held in Rust rather than the webview. IPC returns
  only lock state, path, and aggregate counts; command passphrases are zeroized
  after use. Manual and bounded inactivity locking drop the in-memory vault.
- Optional quick unlock stores the passphrase only in the native OS credential
  store, under a versioned account derived from a SHA-256 vault-path identifier.
  It is never stored in the encrypted vault state, returned to the webview, or
  used without an explicit user opt-in.
- The desktop webview has a restrictive content security policy and loads no
  remote fonts, scripts, images, or network resources.
- Browser filling requires an exact HTTPS origin and a five-minute frozen claim
  subset approved in Desktop. The native companion accepts bounded framed JSON;
  a per-run 256-bit capability authenticates its loopback broker connection.
  Claim changes, conflicts, vault lock, and ambiguous field mappings fail closed.
  Browser manifests allowlist exact extension IDs and request no persistent host
  permissions; content scripts contain no form-submission operation.
- Desktop text import opens an absolute local path in Rust, accepts only the
  supported document extensions, reads at most the format bound plus one byte,
  and stores exact fingerprinted bytes. Candidate offsets are converted from
  browser UTF-16 selection positions to UTF-8 byte offsets and revalidated by
  ingestion before an atomic encrypted save. PDF candidates also bind the page.
  Raw EML, rendered body, and decoded attachments are inserted as one atomic
  source batch so a failed derived source cannot leave a partial message import.

## Known limits before stable release

- No independent cryptographic audit has been completed.
- Verified encrypted backup/restore is available. Restore authenticates the
  backup and creates a new vault without overwriting existing paths.
- Independent recovery uses a random 256-bit code and a separate key-wrapping
  kit. The code is shown once and is not stored in either artifact. Recovery is
  bound to the source vault, rejects wrong codes/tamper/mismatched kits, and
  re-encrypts into a new path with a new passphrase.
- Recovery is only as safe as the separation of backup, kit, and code. Anyone
  holding all three can decrypt the snapshot. Rotation changes the local vault
  salt/key epoch, invalidates old kits against the current vault, and removes
  the local rollback artifact; independently copied old artifacts still require
  user deletion. OS keychain quick unlock is convenience only: anyone who can
  use the same OS account and unlock that credential store may unlock the vault.
- Sync objects are encrypted before leaving the client and manifests are signed
  by Ed25519 device identities. The service core validates ciphertext hashes,
  append-only parent links, device sequences, quotas, and current key epoch. It
  does not receive content keys or plaintext.
- The desktop verifies downloaded manifest signatures through retained signed
  pairing authorizations to a bounded local trust snapshot. Initial pairing
  binds the exact known head set; later downloads must descend from every local
  head and authenticate each traversed manifest. This detects signer
  substitution and rollback below an observed checkpoint. A malicious server
  can still withhold a branch that no trusted client has observed, and the
  protocol has no global transparency log.
- Sync applies asynchronous results with a compare-and-swap guard over a fresh
  in-memory session identity, vault path, encrypted profile, and snapshot digest.
  Lock/reopen invalidates old guards even for the same file. Downloads cannot
  overwrite local edits. A verified own upload retains its consumed sequence
  checkpoint without replacing content edited during network I/O. Pairing
  completion and initial download require an empty destination, and grant
  receipts are released only to the matching live session/profile. An aggregate
  five-minute deadline bounds signer/ancestry traversal. A lost successful PUT
  is reconciled only from the expected self-signed sequence/parents and an
  encrypted object whose plaintext digest matches the current local snapshot.
  A crash/timeout before that verified result followed by local edits may still
  require explicit conflict recovery; there is no durable pending-upload journal.
- Sync retry is restricted to GET, idempotent PUT and crash-safe activation,
  with three attempts, bounded delay and an overall deadline. Authentication,
  conflict and non-idempotent state transitions fail immediately; this avoids
  turning an ambiguous lost response into repeated revocation or registration.
- Protected sync routes are rate-limited before body parsing by process-local
  global and SHA-256 bearer-token buckets with bounded identity storage. Raw
  credentials and tenant identifiers are not limiter labels. This is not a
  distributed or byte/concurrency limiter: public ingress must add shared
  source-IP, connection, bandwidth and slow-request controls, and the initial
  service must remain single-replica until those controls are verified.
  The service independently applies a 120-second routed-request deadline and a
  configurable process-local object-transfer semaphore before body parsing;
  slow headers and aggregate multi-replica byte pressure remain ingress duties.
- Sync still leaks unavoidable service metadata: vault/device identifiers,
  ciphertext sizes, graph shape, access timing, IP/account data at a future
  transport layer, and usage totals. Traffic padding is not implemented.
- Trusted-device pairing transfers only the confirmed current epoch key. The
  authenticated service persists transactional metadata in PostgreSQL and
  immutable ciphertext in S3-compatible storage. Aggregate metrics, cleanup
  jobs and the single-process request limiter are implemented; shared edge
  controls, alerting/runbooks and third-party crypto review remain incomplete.
  Pending pairing confirmation is invalidated atomically after five failed
  well-formed codes, with the counter persisted in PostgreSQL across restart.
- Sync-device revocation rotates the service epoch and disables the credential,
  but coordinated client rekey, signed active-device checkpoints, new-key
  delivery, and cross-epoch DAG verification are not complete. The revoke API
  is therefore not a production desktop workflow yet; using it can require
  recovery/re-pairing rather than an automatic continuation.
- Durable pairing expiry/cleanup and GC cutoffs use PostgreSQL time, so an API
  host-clock rollback cannot extend a registration. S3 object age is still
  reported by the object-store clock; production must monitor cross-store drift.
- No multi-process file lock exists; one desktop process must own a vault.
- Auto-lock is checked by a 15-second UI heartbeat and before session commands;
  OS suspend/resume and process-memory behavior still require packaged E2E tests.
- An attacker controlling the unlocked process can read plaintext in memory.
- A model provider receives every byte shown in the exact payload preview and
  may retain/process it under its own terms despite the request's `store:false`.
  Redaction is literal, not semantic, and the API key necessarily exists in
  process/network-library memory during the request. No live-provider E2E test
  runs in CI because Foliora does not own a user's key or billable account.
- The native bridge trusts the current OS user boundary. Malware running as the
  same user can inspect application-data rendezvous metadata, browser state, and
  the unlocked desktop process; the capability is not a sandbox against a fully
  compromised account. Forced process termination may leave an expired
  rendezvous file, but its loopback port dies with the process and the next start
  replaces it. Graceful exit removes it.
- File names, directory location, size, and modification time remain visible to the OS.
- Secure deletion cannot be guaranteed on SSDs, copy-on-write filesystems, or backups.
- Document/image parsers currently run in-process; OS process sandboxing,
  cancellation deadlines, and parser crash isolation are not implemented yet.
- Platform-built Tesseract binaries and Vietnamese/English trained-data are not
  staged in the repository yet. The staging command pins the official models
  and the desktop verifies a compiled full-tree size/SHA-256 inventory, but
  signed runtime builds and target-OS smoke evidence remain release gates.
- Managed hosted-sync operations are not implemented yet.

## Recovery policy

The application must never imply that an account reset recovers local data.
Without either the vault passphrase or all three recovery artifacts (backup,
matching kit, and code), access is lost. A successful save retains
the previous encrypted envelope beside the vault with a `.vault.bak` suffix. Backup
restoration must authenticate and validate the envelope before replacing current
state.
