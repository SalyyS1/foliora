# Deployment guide

## Desktop development

```sh
pnpm install
pnpm check
pnpm test
pnpm --filter @foliora/desktop run build
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The Tauri build requires the platform WebView toolchain. The app stores vaults
where the user chooses; it does not upload them unless sync is explicitly
configured. Optional quick unlock uses the native credential store of the
target OS and must be tested with a locked/unavailable keychain as a recoverable
configuration error. A release pipeline must sign installers and verify the
artifact on Windows, macOS and Linux before publishing.

The Windows CI job also runs `tauri build --no-bundle` with a single Cargo job
and isolated temporary/target directories. This catches native compilation and
linker regressions before installer work begins; the resulting binaries are
unsigned and are not distribution artifacts.

## Local reference sync stack

The bundled Compose file is a compatibility/development reference, not a
production-ready storage recommendation. MinIO's Community repository is now
archived and marked unmaintained; its pinned source remains useful for isolated
protocol testing. Before exposing a deployment, select and audit a maintained
S3-compatible storage service, use bucket-scoped credentials, and run the same
restore/integrity suite against that implementation. See the
[MinIO upstream notice](https://github.com/minio/minio). This newly verified
upstream lifecycle change is a production release gate, not a reason to claim
S3 compatibility from local-file tests.

Copy `.env.self-host.example` to `.env`, set random secrets, then run:

```sh
docker compose up --build -d
curl --fail http://127.0.0.1:8787/readyz
```

The reference stack uses PostgreSQL for transactional metadata and MinIO/S3 for
opaque immutable objects. Put a trusted TLS reverse proxy in front for remote
clients. Bind plain HTTP only to loopback during development. Back up the
database and object volume together from a quiesced service, and verify restores
regularly using `sync-backup-restore.md`; orphan ciphertext can be garbage-collected
after failed database commits, and old metadata-tracked uploads that never reach
a manifest are reclaimed through the same scheduled job. Set the maximum
per-vault bytes, GC grace/scan
intervals, object/manifest metadata ceilings and pairing-cleanup interval in
`.env`; scrape `/metrics` only from a
private monitoring network.

Stop or drain every older sync-service instance before applying migrations and
do not run mixed binary versions. The retention-accounting migration makes new
object/manifest accounting fields mandatory so an older writer fails closed
instead of silently bypassing counters.

Migration `0005_device_authorizations.sql` begins retaining signed authorization
grants for newly activated devices. Root devices intentionally have no grant.
Non-root devices paired by an earlier development build also have no retained
certificate and must be revoked/re-paired before clients can authenticate their
manifest signer chain. Such credentials fail authentication and `/readyz`
remains unhealthy until the root device revokes them; pair a newly generated
device identity afterward. This is a pre-stable compatibility break. Do not
infer or fabricate authorization records during migration. The root must be the
unique active device whose creation timestamp matches its vault's creation in
the same original transaction. Ordering timestamps is not sufficient after a
clock rollback. Migration aborts atomically for missing, revoked, or ambiguous
creation evidence. Never promote a surviving
credential by changing `is_root` manually. Use the previous binary to recover
needed data into local encrypted backups, then bootstrap the new service against
a **fresh, separate database and bucket** and enroll fresh sync identities. Keep
the old service backup for historical recovery. Creating another vault in the
same legacy database does not remove the migration blocker. Audit unresolved
rows with:

```sql
SELECT vault_id, device_id
FROM devices
WHERE active AND NOT is_root AND authorization_grant IS NULL;
```

The service enforces configurable per-credential and global request buckets
before parsing `/v1` bodies. These buckets are process-local. Keep the initial
deployment at one API replica, and enforce shared source-IP, connection,
cross-replica concurrency, byte-rate, and slow-header limits at a trusted ingress proxy that
strips untrusted forwarding headers. Do not expose the Rust listener directly.
The Rust service itself bounds routed requests to 120 seconds and admits at most
32 concurrent object transfers by default; tune these with
`SYNC_REQUEST_DEADLINE_SECONDS` and `SYNC_OBJECT_CONCURRENCY` in `.env`.

CI starts disposable PostgreSQL and MinIO containers and runs the ignored
`durable_repository` scenario explicitly. That scenario applies every migration,
survives a repository restart, verifies opaque object/manifest recovery, runs
overlapping successful activations, and proves the five-attempt pairing counter
persists across restart and concurrent guesses. CI also seeds an encrypted
fixture, backs up both stores, destroys and recreates them, restores both, and
verifies the credential, object, signed manifest, and head. The same repository
also exercises concurrent durable object quota boundaries, sequential manifest
quota rejection, and staged
object reclamation. The restore drill compares checksums for every object and
row inventories for every sync table, then starts the service and requires
`/readyz` to pass. The repository scenario can be run locally when
Docker-backed endpoints are available:

```sh
cargo test --locked -p foliora-sync-service --test durable_repository encrypted_object_and_manifest_survive_repository_restart -- --ignored --exact --nocapture
cargo test --locked -p foliora-sync-service --test durable_repository durable_quota_boundaries_are_atomic -- --ignored --exact --nocapture
```

Do not run all ignored tests together: fixture seeding and restore verification
are ordered around an actual dual-store restore. Follow CI or the
[backup/restore runbook](sync-backup-restore.md) for those steps. The separate
`--verify-integrity` command hashes all tracked payloads using read-only SQL,
with writers/GC stopped; it does not apply migrations or start HTTP.

## Release checklist

- replace every example secret and restrict network ingress;
- configure TLS, shared edge limits, off-site backups, restore schedule, byte and
  metadata quotas, and
  abandoned-device revocation;
- build the public site and run `validate:artifact`;
- sign and smoke-test each desktop installer and native-host registration;
- verify Vietnamese/English copy, CSP, dependency licenses and SBOM;
- publish threat model, recovery limitations and support contact with the
  release, never implying that the service can decrypt user data.

The `Security and SBOM` workflow runs RustSec, the production Node audit and a
CycloneDX workspace scan on every main-branch push, pull request and weekly
schedule. Third-party actions are pinned to reviewed commit SHAs; update those
pins only after checking the upstream signed release and changelog. The SBOM is
a CI artifact and must be attached to each public binary release.
