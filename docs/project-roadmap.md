# Project roadmap

## Done

- Offline domain, encrypted vault, recovery, ingestion, OCR contract, reviewed
  JSON/PDF/clipboard/archive exports.
- Tauri desktop workspace and Windows release smoke.
- Chromium/Firefox MV3 extension with exact-origin, preview-first policy.
- E2EE sync protocol, memory service, PostgreSQL/S3 durable service, bounded
  HTTP client, encrypted profile persistence and copy/paste trusted-device
  pairing.
- Bilingual Vite public preview and desktop sync/pairing UI.
- Optional OpenAI BYOK candidate suggestions with exact disclosure preview,
  literal redaction, transient keys and source-grounding validation.

## Next release gates

1. **Operational hardening:** disposable Postgres/S3 integration suite, retry and
   partition tests, restore/load/clock-skew tests and historical-data retention
   policy. Transactional per-vault quotas and an operator quota ceiling are
   implemented.
   Grace-period object garbage collection, label-free service metrics and
   server-side activation/cleanup for abandoned pairing registrations are
   implemented. Bounded client retry and simulated partition tests are also
   implemented for proven-idempotent operations only.
   Routed request deadlines and process-local object-transfer concurrency limits
   are implemented before body allocation.
   A disposable PostgreSQL/MinIO CI job is defined to run migrations, repository
   restart, concurrent activation, persistent lockout, and opaque object/manifest
   durability checks. It also defines a destructive dual-store backup/restore
   drill and verification of the restored credential, object, manifest and head;
   workflow execution remains evidence that must be recorded per release.
   Protocol v1's conservative indefinite history/tombstone retention policy is
   documented; signed multi-device compaction is required before committed-history
   quota can be reclaimed. Pairing boundary/skew tests and lifetime clamping are
   implemented. Downloaded signer chains are epoch-bound to local trust anchors,
   pairing binds the initial head set, later history is ancestry-checked, and
   stale asynchronous results are rejected by session-identity/profile/snapshot
   guards. Pairing cannot overwrite documents added to its destination; verified
   own-upload checkpoints preserve local edits. A crash before verified upload
   acknowledgement followed by edits can still need explicit conflict recovery.
   Durable expiry and GC decisions use the PostgreSQL clock rather than the API
   process clock; cross-store clock-drift and sustained load drills remain.
   Object count, manifest count and signed-manifest byte ceilings are enforced
   transactionally and persisted for capacity reporting. Staged objects that
   never become referenced are reclaimed after the GC grace window through a
   resumable two-phase delete state; committed history remains retained. Fresh
   physical storage generations fence late deletes from repaired payloads.
   Offline `--verify-integrity` streams all tracked object hashes through read-only
   SQL without migrations or background tasks. Its `--inventory-jsonl` option
   independently hashes tracked and untracked bucket entries. CI compares live
   and restored inventories. Interrupted-GC, delayed-delete and stale digest fixtures
   passed on disposable PostgreSQL 16.11 with LocalFileSystem, alongside an
   isolated database dump/restore and five matching physical-object hashes.
   The five environment tests were executed separately from the 196 passing
   workspace tests. Actual S3/MinIO restore, sustained load and cross-store clock
   drift evidence remain open; see [verification record](verification-2026-09-13.md).
2. **Device security:** independent protocol review and dependency/SBOM review.
   Coordinated client-side epoch rotation after sync-device revocation—including
   signed active-device checkpoints, new-key delivery, and cross-epoch history
   verification—remains a release gate; the current service-side revoke endpoint
   is not exposed as a production desktop workflow.
   Recovery-key rotation/revocation UX and opt-in OS-keychain quick unlock are
   implemented for the local vault epoch. External copies of old backups/kits
   still require user deletion. Quick unlock uses the native credential stores
   on Windows, macOS and Linux.
   Automated RustSec/Node audits and CycloneDX generation are implemented;
   independent review and release-by-release evidence remain required.
3. **Content completeness:** build and smoke-test pinned Tesseract runtimes for
   each target; resource mapping, official Vietnamese/English model staging and
   a compiled full-tree integrity lock are implemented. The optional BYOK AI
   adapter, redaction/preview flow and no-provider fallback are implemented.
4. **Distribution:** signed Windows installer/updater, macOS notarization,
   Linux AppImage/deb evidence, browser native-host registration, rollback and
   update security tests.
5. **Hosted launch:** in-process pre-body global/per-credential request limits
   are implemented for the single-replica baseline. TLS/secret rotation, shared
   multi-replica edge/IP/byte/concurrency controls, production off-site backup
   operations and scheduled restore evidence,
   billing entitlement service with full self-host parity,
   support/privacy/legal pages, and trademark/domain/package clearance remain.
   Five-attempt persistent pairing lockout is implemented transactionally.

## Exit criteria

Production v1 ships only when all release gates are green on supported OSes,
the threat model and limitations are published, a fresh user can recover without
the operator, sync conflict behavior is demonstrated, and no marketing claim
exceeds the verified artifact or deployment configuration.
