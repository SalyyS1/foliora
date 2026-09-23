# Native Windows synthetic sync drill

[scripts/test-sync-s3.ps1](../scripts/test-sync-s3.ps1) exercises the durable sync
repository against a new localhost PostgreSQL cluster and MinIO instance. It
backs up synthetic database rows and S3 objects, restores into a second database
and bucket, compares inventories, checks API readiness, and stops its processes.
No Docker or existing service is required.

MinIO is a compatibility fixture only. The existing
[backup/restore runbook](sync-backup-restore.md) records its archived,
unmaintained Community status and the production-storage boundary. This native
drill adds no production recommendation or support commitment.

## Current evidence and release gate

Status for the 2026-09-22 implementation session: operational release gate
**OPEN**. These are the reported session gates plus source inspection, not a
record of a successful native drill.

| Item | Evidence/status | Required next input or evidence |
| --- | --- | --- |
| Actual PostgreSQL + S3 restore | Disposable PostgreSQL 16 + Moto 5.2.3 passed restart, quota, migration, and destructive restore checks. MinIO and `mc` are still missing. | Owner supplies installed, pinned MinIO tools and their explicit paths; main records MinIO-specific evidence. |
| Locked offline Cargo | Blocked by missing cached `aead 0.5.2`. | Owner supplies a cache covering the lockfile and selected Windows toolchain/target; other missing dependencies may appear next. |
| Rust 1.88 | Clean Windows `cargo test --locked --workspace -j1` passed: 196 passed, 0 failed, 5 ignored. | Hosted `sync-msrv` execution remains the reproducible CI gate. |
| Launcher/tooling regressions | `scripts/test-sync-tooling.ps1` passed 12/12 on Windows PowerShell 7.6.5 with Node.js 24.12.0; a clean-checkout simulation also passed 12/12 and created its missing `.test-build` parent. | This verifies harness process/checkpoint mechanics only; it is not S3 evidence. |
| Capacity | Script checks a minimum; no cold-build capacity result is established here. | Owner provides enough scratch and Cargo target capacity for retained stores, copies, logs, and the actual build. |

This work maps to the existing roadmap's
[operational hardening gate](project-roadmap.md#next-release-gates). A native
drill PASS would add restore evidence for that fixture; sustained load,
cross-store clock drift, and the other existing operational requirements still
need their own evidence. The historical plan is unchanged. Main owns the final
verification record and `.dockerignore`, package, CI, and script integration.

## Prerequisites

- Native Windows, PowerShell **7.4.1 or newer** (`pwsh`), and a non-elevated
  session. PostgreSQL runs directly as the caller, not as an installed service.
  `Get-NetTCPConnection` must work so readiness can check listener ownership.
- Already installed, owner-pinned PostgreSQL, MinIO server, and MinIO client
  (`mc`). Pass absolute paths. The PostgreSQL `bin` directory must contain
  `initdb.exe`, `postgres.exe`, `pg_ctl.exe`, `pg_isready.exe`, `createdb.exe`,
  `psql.exe`, `pg_dump.exe`, and `pg_restore.exe`. Select compatible dump/restore
  tools from that installation. The script checks presence, not a version or
  checksum allowlist; retain the actual versions/pins with the run evidence.
- Installed `cargo.exe` on PATH, an installed compatible Rust toolchain
  (repository minimum: 1.88), and native Windows build/link prerequisites.
  Every Cargo test/build uses `--locked --offline`; the script also sets
  `CARGO_NET_OFFLINE=true` and `RUSTUP_AUTO_INSTALL=0`. All needed registry/git
  dependencies must already be cached for the selected toolchain and target.
  A populated target directory alone does not prove that cache is complete.
- An existing writable scratch parent and writable Cargo target location.
  Preflight requires at least **256 MiB free on each volume**. This is a floor
  for an already warm build, not a complete disk budget or a reservation. When
  both locations share a volume, they compete for the same free space.

The default Cargo target is the repository's `target` directory; reusing it can
avoid rebuilding unchanged dependencies. A cold target still needs cached
dependency sources for offline operation, plus substantially more free disk for
compilation and linking. Budget separately for the PostgreSQL cluster, both
MinIO buckets, dump, two object mirrors, native temporary files, logs, and all
retained previous runs. No measured cold-build space guarantee is available.

The procedure performs no installs, downloads, or `.env` reads. Provision tools
and the offline cache separately before using it. Do not substitute production
credentials, real vaults, an existing PostgreSQL data directory, or remote
endpoints for the synthetic fixture.

## Example invocation

Run from PowerShell 7.4.1+ after the prerequisites are available. Replace the
three tool paths below with the installed pinned binaries; they are placeholders,
not download locations. This example only creates `.test-build` if absent and
does not remove or overwrite an existing directory.

```powershell
$ErrorActionPreference = 'Stop'
$repo = 'D:/Project/.Crawl/foliora'
Set-Location -LiteralPath $repo
$scratchParent = Join-Path $repo '.test-build'
if (-not (Test-Path -LiteralPath $scratchParent)) {
    $null = New-Item -ItemType Directory -Path $scratchParent
}
if (-not (Test-Path -LiteralPath $scratchParent -PathType Container)) {
    throw 'Scratch parent must be a directory'
}

pwsh -NoProfile -File (Join-Path $repo 'scripts/test-sync-s3.ps1') `
    -PostgresBin 'C:/path/to/pinned-postgresql/bin' `
    -MinioBinary 'C:/path/to/pinned-minio/minio.exe' `
    -McBinary 'C:/path/to/pinned-mc/mc.exe' `
    -ScratchParent $scratchParent `
    -CargoTargetDir (Join-Path $repo 'target')
if ($LASTEXITCODE -ne 0) {
    throw 'Native S3 drill failed; inspect the printed evidence directory'
}
```

`-ScratchParent` otherwise defaults to the OS temporary directory. Each invocation
creates `foliora-s3-drill-<guid>` below that parent with `New-Item` and no `-Force`;
it never resumes or adopts a previous run. Use the exact evidence path printed by
the script when reading results. The run directory is unique even when multiple
runs share the Cargo target cache.

The script chooses four distinct loopback ports for PostgreSQL, MinIO's API and
console, and the sync API. Before health probes, it checks that the expected
process owns the `127.0.0.1` listener and fails on an unexpected owner. It creates
`foliora_live`/`foliora_restored` databases and
`foliora-live`/`foliora-restored` buckets inside this run's stores. PostgreSQL
uses local test `trust` authentication; MinIO and the API use synthetic test
credentials. This is an isolated test setup, not a deployment configuration.

Process-scoped settings replace inherited storage credentials/endpoints, disable
the local-filesystem fallback, isolate `mc` configuration, and point child
`TEMP`/`TMP` into `native-temp` under the run directory. The script restores the
changed environment in `finally`; it does not edit global configuration.

## Ordered checkpoints

The script owns the ordering. Do not run all ignored durable tests together.
Each selected Cargo test uses `--ignored --exact --nocapture` and must report
exactly one passing test; zero matching tests cannot satisfy the stage.

| Stage(s) | Work and evidence |
| --- | --- |
| `preflight`, `postgres`, `minio` | Check capacity/tools, create isolated settings and stores, verify owned listeners and readiness. |
| `restart`, `quota`, `migration` | Run the repository restart, atomic quota, and legacy-root migration authorization fixtures in sequence. `restart` reconnects the repository; it is not a PostgreSQL server restart. |
| `seed`, `build` | Seed the encrypted object, signed manifest, head, device credential, and an untracked bucket object; build the sync CLI offline with the lockfile. |
| `inventory-live`, `backup` | With the API still stopped, run `--verify-integrity --inventory-jsonl`, inventory every public database table including migrations, record bucket key/size listings, mirror objects and hash files, then take a custom-format database dump. |
| `restore`, `fixture-restored` | Restore the dump and object mirror into the new database/bucket, authenticate the retained synthetic device credential, and verify the exact object, manifest, head, and accounting through the repository. Live stores remain available. |
| `inventory-restored`, `inventory-diff` | Independently repeat the scrub, database inventory, bucket listing and mirrored-file SHA-256 hashes; compare sorted live/restored files. Untracked bucket bytes are included; S3 ETags are not used as content hashes. |
| `api-ready` | Start the real HTTP service against restored stores and require `/readyz`. This does not replace the full scrub or add an HTTP object/manifest read test. |
| `stop-service`, `stop-postgres`, `stop-minio`, `stop-children`, `restore-environment` | Stop the owned service/store processes and remaining children, restore process environment, and only then finalize the report. |

The retained `report.txt` begins with `RESULT: RUNNING` and is checkpointed before
and after each stage. Stage states are `SKIP` (not reached), `RUNNING`, `PASS`, or
`FAIL`; failure details identify the stage error, with native output in logs.
Final `RESULT: PASS` is allowed only when **every stage, including cleanup, has
passed** and no failure details remain. Individual `PASS` lines, successful
inventories, or readiness alone are insufficient. A caught failure leads to
cleanup attempts and final `RESULT: FAIL`; the script exits with an error.

An interrupted host may leave `RESULT: RUNNING`, partial logs, or no report if
startup failed before the first checkpoint. None establishes completion. Inspect
the last checkpoint and cleanup evidence; rerun into a fresh directory after the
cause is addressed. This guide contains no artifact-deletion commands.

## Launcher repair and tooling-only regressions

The launcher repair uses Windows Job Objects: create each child suspended,
assign it to a job before resuming its thread, enable kill-on-close, and verify
the job has zero active processes during explicit cleanup. Job ownership must
include descendants even after the original parent exits; observing only the
parent's exit is insufficient.

The integrated [PowerShell helper](../scripts/lib/sync-test-helpers.ps1),
[owned-process implementation](../scripts/lib/owned-drill-process.cs), and
[native interop](../scripts/lib/owned-drill-process-native.cs) use a Windows Job
Object with atomic job-list assignment at suspended process creation, explicit
descendant cleanup, and kill-on-close. The helper also resolves one
PATH-preferred executable when multiple installations are discoverable. The
tooling suite passed 12/12, including argument round-tripping, nonzero exits,
deadline cleanup, parent-exit descendant cleanup, independent-job isolation,
checkpoint fail-closed behavior, and kill-on-close. This verifies harness
mechanics only; source inspection and tooling tests do not establish an S3 PASS.

[scripts/test-sync-tooling.ps1](../scripts/test-sync-tooling.ps1) is a separate
Windows harness regression suite requiring installed Node.js and PowerShell
7.4.1+. It tests checkpoint behavior, native argument quoting, nonzero exits,
timeouts, descendant cleanup, and inventory comparison. It uses no PostgreSQL or
S3 service and retains small synthetic artifacts under `.test-build/tooling-<guid>`.

```powershell
pwsh -NoProfile -File 'D:/Project/.Crawl/foliora/scripts/test-sync-tooling.ps1'
```

Its report file is itself a test fixture. The script keeps the report `RUNNING`
until all cases pass, writes `FAIL` when a later case or cleanup fails, and only
writes final `PASS` after the complete suite. Require the suite's successful
process exit and cleanup evidence for a tooling result. Even a fully passing
tooling suite supplies **no S3 backup/restore evidence**.

## Retained evidence

Cleanup stops processes and restores environment; it does not purge the run
directory. Retained files include `report.txt`, per-command stdout/stderr under
`logs`, `fixture.json`, `database.pgdump`, the PostgreSQL/MinIO data,
`integrity-{live,restored}.jsonl`, `database-{live,restored}.txt`,
`listing-{live,restored}.txt`, `objects-{live,restored}.txt`, and both object
mirrors. Synthetic fixture credentials are deliberately retained to verify
restore; never put real credentials or user data in these artifacts.

Treat logs, dumps, and inventories as sensitive metadata even when payloads are
encrypted or synthetic: credentials, token digests, identifiers, object sizes,
timing, graph structure, and local paths may appear. Keep the scratch directory
access-restricted and out of commits, published artifacts, and build contexts;
review/redact evidence before sharing it. The script does not provide encrypted
artifact storage or prove packaging exclusions.

Main's final verification record should identify the actual command, installed
tool versions/pins, Rust version and target, run directory, exit status, report,
inventory comparison, and cleanup outcome. Until that evidence exists, retain
the OPEN operational gate and the pending statuses above.
