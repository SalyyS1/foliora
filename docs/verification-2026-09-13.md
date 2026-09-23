# Verification — 2026-09-13

Scoped evidence snapshot for sync maintenance and desktop guards. Runtime results
below are confirmed by main's task messages, not rerun by this docs task.
Source inspection establishes implementation only. No production database touched.
Review found earlier tests insufficient. Revised results below are confirmed by
main, including the final workspace and Actionlint runs. S3 remains untested.
No full release-completion claim.

## Evidence

| Check | Actual evidence | Status / limit |
|---|---|---|
| Service library tests | Main confirms current `--lib` run: 33/33 passed, including same-size untracked corruption coverage. | Passed; does not execute ignored durable tests. |
| `cargo check --tests` | Main previously reported success. | Earlier compilation evidence; current all-target Clippy also passed. |
| Formatting / lint / frontend checks | `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, and `pnpm check`: main confirms all passed. | Current checks passed; compilation/lint are not runtime tests. |
| Frontend tests | `pnpm test` passed: desktop 2, extension 13, plus schema/protocol checks. | Confirmed; no invented aggregate count. |
| Site artifact | Site build and `validate:artifact` passed. | Confirmed local artifact checks; not deployment evidence. |
| PG16.11 migration authorization | Revised runtime test passed 1/1 with nine fixture cases, DDL rollback and per-vault checks. | Exact vault/device creation-time evidence; replaces insufficient three-fixture coverage. |
| PG16.11 + LocalFS integration | Tester fresh-database rerun: two exact ignored scenarios passed (restart/repair including delayed DELETE after commit; quota). | Current runtime pass confirmed by main; LocalFS only. |
| Local dump/copy restore | Seed test 1/1 passed; `pg_dump` and `pg_restore` exited 0, restoring into new `foliora_restored_test` and a separate object directory. Five source/restored keys and SHA-256 hashes match, including untracked data; exact `verify_backup_restore_fixture` passed 1/1. | Actual PG16.11 + LocalFS restore passed; temporary source untouched; cluster shut down. Not S3. |
| S3/MinIO restore and CLI scrub | Docker/MinIO and S3 execution unavailable; CI workflow and fixtures inspected. | No actual S3 restore drill; no end-to-end CLI result claimed. |
| Desktop guards | Main confirms 12 added regressions passed, with focused groups session 23 and sync 5 passing. | Focused runs passed; overlapping counts are not added together. |
| Full workspace tests | `cargo test --locked --workspace` exited 0: 196 passed (desktop 51, domain 18, export 13, ingestion 23, model 11, sync 26, service 33, vault 21). | Five environment tests ignored in aggregate; all five passed in explicit runs below. Focused/service counts overlap this total. |
| Explicit environment tests | Restart 1, quota 1, seed 1, restore 1, root migration 1: all passed. | First four used PG16.11 + LocalFS; migration used PostgreSQL only, with nine fixtures within one test. |
| Service rereview / CI pipelines | Main reports no remaining verified P1/P2 findings and Bash pipefail correction; explicit Bash inspected in CI. | Scoped rereview result, not independent protocol review or executed S3 CI evidence. |
| Actionlint | Cached v1.7.9: `GOPROXY=off GOSUMDB=off go run -mod=readonly ./cmd/actionlint D:/Project/.Crawl/foliora/.github/workflows/ci.yml`, run from the cached module, exited 0. | Passed; no dependencies fetched. Workflow lint does not execute CI. |

The test-only `FOLIORA_INTEGRATION_LOCAL_OBJECT_DIR` selects `LocalFileSystem` in
[durable tests](../services/sync/tests/durable_repository.rs); the `fs` feature is
in [dev-dependencies](../services/sync/Cargo.toml). Real PostgreSQL + local files
can validate SQL/repository behavior, but cannot validate S3 transport or MinIO
backup/restore. [Migration fixtures](../services/sync/tests/migration_authorization.rs)
use isolated transactional schemas and roll back. Runtime command:
`cargo test --locked -p foliora-sync-service --test migration_authorization -- --ignored --nocapture`.
`pg_ctl stop` exited 0. Source/generated fixtures remain under the task-specific
Temp `foliora-sync...` directory; the temporary source was not destroyed.

## Inspected changes

- [Integrity module](../services/sync/src/durable/integrity.rs) streams SQL rows
  and object chunks, compares stored physical SHA-256, and counts untracked
  `v1` bucket entries without deleting them. `--verify-integrity --inventory-jsonl`
  additionally streams independent hashes for every entry under `v1`, including
  untracked objects. Sort complete JSONL outputs to compare live/restored bytes;
  discard partial output on failure. A unit fixture detects same-size changes
  to untracked bytes. [CLI](../services/sync/src/main.rs) uses read-only PostgreSQL
  connections and exits before migrations, HTTP
  startup, or background writes. Operators must stop every writer and GC for
  the entire run; this is maintenance verification, not a readiness probe.
- [Staged GC](../services/sync/src/durable.rs) uses the PostgreSQL clock and
  persists `deleting` before object deletion, then removes metadata and quota
  accounting under locks. Missing physical bytes allow retry completion;
  manifest commits cannot resurrect deleting rows. Upload verifies/repairs bytes
  and updates the physical digest before reactivation. New/repair writes use
  fresh random physical storage generations; delayed DELETEs target retired
  keys. The durable fixture completes a delayed DELETE after manifest commit
  and checks the new payload remains readable. Referenced history stays.
  [Migration 0006](../services/sync/migrations/0006_staged_object_gc.sql) adds this
  state during normal service migration, never during verification.
- [Root migration](../services/sync/migrations/0005_device_authorizations.sql)
  requires exactly one device matching `device.created_at = vault.created_at`,
  and that device must be active. Nine fixtures cover active/revoked roots,
  predating survivors, ambiguous matches, missing matches/devices, and empty
  vaults, with an independent control vault, old-writer rejection, and rollback
  checks. Nine fixtures execute within one passing runtime test.
- [Desktop session](../apps/desktop/src-tauri/src/session.rs) guards registration,
  sync, and pairing with session identity, including same-path lock/reopen.
  Profile/pending-request and snapshot checks prevent stale pairing/downloads;
  initial download requires an unchanged empty recipient. Committed uploads
  preserve their sequence checkpoint after local edits without replacing content.
  [Regression fixtures](../apps/desktop/src-tauri/src/session_tests.rs) cover these
  prepare/apply races; fixture presence alone is not a passing run.

## Release gates

- Execute disposable PostgreSQL + S3/MinIO dual-store restore and read-only CLI
  scrub before/after restore; compare full `v1` inventories including untracked
  hashes, and retain restored-readiness evidence.
  [CI](../.github/workflows/ci.yml) defines this workflow; execution is unconfirmed.
- Complete sustained load/cross-store clock-drift drills, independent protocol
  review, and coordinated client device-epoch rotation.
- Keep supported-OS OCR packaging, signed distribution, and hosted operations
  gates open as specified in the [current roadmap](project-roadmap.md).

## Unresolved old-plan mapping

Read the [parent proposed plan](../../plans/260910-0322-continuum-context-escrow/plan.md)
and every phase file 00–06. Its owner is unassigned, phase 00 pending, phases
01–06 blocked, and checklists unchecked. Leave this historical plan unchanged;
the roadmap's implementation inventory does not establish its acceptance gates.

| Old phase | Current roadmap relationship | Unresolved acceptance / mapping |
|---|---|---|
| 00 Opportunity validation | No explicit equivalent release gate. | 15 interviews/concierge bundles, demand/payment evidence, schema-reuse measurement, launch wedge and go/no-go remain unverified. |
| 01 Foundation/threat model | Offline foundation implemented; device-security/distribution gates remain. | Reconcile threat-review, stack-spike, migration-rollback and measured offline-baseline acceptance with current evidence. |
| 02 Ingestion/claim ledger | Ingestion implemented; OCR packaging remains a content gate. | Map full offline format/provenance and deletion-dependency acceptance to executed fixtures and shipped OCR resources. |
| 03 Bundle composition | Three templates/domain engine implemented. | Measured shared-schema reuse and domain-review acceptance remain unverified. |
| 04 Trust review/export | Reviewed export formats implemented. | First-time recipient-preview study, screen-reader/keyboard and PDF accessibility evidence remain unverified; resolve optional share-link scope. |
| 05 Pilot hardening | Recovery implemented; operational/security/distribution gates overlap. | No confirmed 20-user pilot, under-five-minute median, assisted-completion/conflict metrics or 30-day reuse evidence. |
| 06 Optional browser fill | Extension implemented; installer registration remains. | Old prerequisite of proven core-pilot demand is unverified; reconcile browser/store acceptance evidence and permission to advance. |

Who owns reconciliation of the old validation-first gates with the current
roadmap, and where will user/pilot evidence be recorded? No full-completion claim
or invented completion percentage is supported by this snapshot.
