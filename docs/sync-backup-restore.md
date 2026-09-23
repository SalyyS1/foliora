# Sync retention, backup, and restore

This runbook applies to the durable PostgreSQL plus S3-compatible sync service.
It does not replace the user's encrypted `.foliora-backup`; the server never has
the vault epoch keys needed to recover plaintext.

The MinIO-specific commands target the local reference/test stack. Upstream
[MinIO Community is archived and unmaintained](https://github.com/minio/minio);
production needs a maintained storage deployment and its own verified equivalent
backup/restore tooling. Do not infer a production support commitment from this
compatibility drill.

## Protocol v1 retention policy

Protocol v1 is deliberately conservative:

- every committed signed manifest is retained indefinitely;
- every ciphertext object referenced by any committed manifest is retained
  indefinitely;
- opaque tombstones are part of immutable signed manifests and are retained with
  the complete revision graph;
- bucket-only orphans and metadata-tracked staged objects never referenced by a
  committed manifest are eligible for collection after the upload grace period;
- staged rows use a resumable `active` → `deleting` lifecycle. A commit cannot
  clear a deletion mark; an identical upload must first verify/repair the bytes;
- repairs use a fresh random physical key, so a delayed DELETE for a retired
  generation cannot erase the new payload. Old physical generations are orphans;
- vault quota counts stored ciphertext bytes. Reclaiming abandoned staged rows
  releases their byte/object quota. Protocol v1 has no committed-history prune,
  tombstone-expiry, or remote-vault-deletion endpoint.
- independent object-count, manifest-count, and signed-manifest-byte ceilings
  bound persistent metadata even when a device reuses existing ciphertext.

This means an offline device can still fetch and verify the complete signed DAG.
It also means operators must not delete old rows or referenced objects to recover
space. Safe compaction requires a future signed checkpoint protocol and explicit
acknowledgement from every active device; wall-clock retention alone is unsafe
for long-offline clients.

## Backup contract

A recoverable service backup contains both of these from one quiesced window:

1. a PostgreSQL custom-format dump, including the migration table;
2. a complete mirror or snapshot of the configured object bucket.

Stop or drain every API writer before taking either copy and keep writes stopped
until both copies finish. A database-only backup can reference missing objects;
an object-only backup loses credentials, quota accounting, heads, and the signed
graph. Encrypt backup media and restrict it like production credentials: object
contents are encrypted, but token digests, public keys, sizes, timing, and graph
metadata remain sensitive.

Run a full read-only scrub before backup and after restore, with **every API
replica and scheduled GC stopped** for the entire operation:

```sh
docker compose run --rm --no-deps sync --verify-integrity
```

For a local binary with the usual PostgreSQL/S3 variables already configured:

```sh
cargo run --locked -p foliora-sync-service -- --verify-integrity
```

This mode does not start HTTP, run migrations, repair data, or start background
workers. PostgreSQL connections are set read-only. It streams every metadata row
and hashes every corresponding object against its stored SHA-256; missing or
corrupt tracked payloads fail with a nonzero exit. Its JSON report counts metadata
objects, bucket objects and untracked bucket entries. Untracked entries have no
trusted digest and are counted, not certified. A `deleting` row with missing S3
bytes also fails until GC recovery or a valid reupload reconciles it. Use a
compatible schema and allow a maintenance window proportional to total data.

To prove complete live-to-restored bucket equivalence, including untracked
objects, additionally capture independently read hashes before copying:

```sh
set -eu
set -o pipefail
umask 077
docker compose run --rm --no-deps sync --verify-integrity --inventory-jsonl |
  LC_ALL=C sort > bucket-inventory.live.jsonl
```

Repeat against the isolated restored service and compare the sorted JSONL files.
Keep these inventories with protected backup metadata. Discard partial output
on any command failure; key/size listings alone cannot detect same-size copying
corruption, and hashing only the backup would not establish a live baseline.

Example for the provided Compose stack, from the repository root:

```sh
set -eu
umask 077
backup_root="${FOLIORA_BACKUP_DIR:-../foliora-backups}"
backup_dir="$backup_root/$(date -u +%Y%m%dT%H%M%SZ)"
sync_stopped=0
cleanup() {
  docker compose exec -T minio rm -rf /tmp/foliora-backup >/dev/null 2>&1 || true
  if [ "$sync_stopped" = 1 ]; then docker compose start sync >/dev/null || true; fi
}
trap cleanup EXIT
mkdir -p "$backup_dir"
docker compose stop sync
sync_stopped=1
docker compose exec -T postgres pg_dump -U foliora -d foliora --format=custom > "$backup_dir/postgres.pgdump"
docker compose exec -T minio sh -c 'rm -rf /tmp/foliora-backup && mc alias set backup-local http://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" && mc mirror backup-local/foliora-sync /tmp/foliora-backup'
minio_container="$(docker compose ps -q minio)"
docker cp "$minio_container:/tmp/foliora-backup" "$backup_dir/objects"
test -s "$backup_dir/postgres.pgdump"
test -n "$(find "$backup_dir/objects" -type f -print -quit)"
```

The exit trap removes the temporary bucket mirror and restarts the service after
success or failure. `backups/` is excluded from Git and Docker build contexts,
but the example defaults outside the repository as a second guard.
Copy the finished backup to independently encrypted storage, record checksums,
and apply the same access controls and deletion policy to every replica.

## Restore drill

Restore into an empty, isolated environment running compatible PostgreSQL and
object-store versions. Never restore over a live service.

1. Keep the sync API stopped.
2. Create an empty database and empty bucket.
3. Run `pg_restore --exit-on-error` into the empty database.
4. Mirror the saved object tree into the empty bucket without rewriting keys.
5. Run `--verify-integrity` with writers still stopped and require success;
   compare complete database row inventories and backup-object checksums.
6. Start one API replica and require `/readyz` to pass. Readiness samples storage
   health; it is not a substitute for the full scrub.
7. Authenticate with a dedicated drill credential and fetch its known object,
   signed manifest, and head. Compare them with the pre-backup fixture.
8. Run an orphan-GC observation window before enabling scheduled deletion.
9. Record duration, backup age, checksums, versions, and verification result.

The `durable-sync` CI job automates the destructive middle of this procedure on
disposable PostgreSQL and MinIO containers: it seeds encrypted data, dumps and
mirrors both stores, destroys and recreates both, restores them, then verifies
the credential, exact encrypted object, exact signed manifest, and head. It also
scrubs every tracked payload before and after restore, independently hashes every
live and restored bucket entry (including a seeded orphan), compares live/backup key
and size listings, database row inventories, and mirrored-file SHA-256 hashes.
S3 ETags are not used as content hashes: multipart copies can change them.

Run an isolated restore drill at least quarterly and after database, object-store,
migration, or backup-tooling changes. Production backup frequency and retention
must be chosen from an explicit RPO/RTO; CI proves mechanics, not that an
operator's off-site copies are current or accessible during an incident.

## Native Windows synthetic drill

See the [native Windows sync drill](sync-native-drill.md) for the isolated
PostgreSQL/MinIO procedure, installed pinned-tool and offline-cache prerequisites,
retained evidence, checkpoint/cleanup semantics, and current verification gaps.
The separate tooling regression suite does not establish S3 restore evidence;
the operational release gate remains open pending the required runtime evidence.
