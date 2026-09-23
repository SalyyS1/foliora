# Self-hosted sync service

Status: authenticated HTTP transport and durable PostgreSQL/S3-compatible
storage are implemented. PostgreSQL transactions protect vault/device/manifest
invariants. Object storage receives only immutable serialized encrypted objects;
the database stores their size, location and SHA-256 integrity digest.

## Durable self-hosting

Copy `.env.self-host.example` to `.env`, replace every secret, then run:

```sh
docker compose up --build -d
curl --fail http://127.0.0.1:8787/readyz
```

The Compose stack binds the API to loopback and persists PostgreSQL and MinIO in
named volumes. Put a TLS reverse proxy in front before remote access. Back up
both stores from one quiesced window and practice restoring them together; see
`sync-backup-restore.md`. An object successfully written before a failed database
commit can become an unreachable ciphertext orphan; it cannot become visible to
a manifest. The service now garbage-collects such ciphertext only when its key
is absent from PostgreSQL and its object age exceeds the configured grace
window. This avoids racing the interval between an immutable object write and
its metadata commit. Metadata-tracked objects that never become referenced by a
manifest use a separate two-phase lifecycle: an old row is first marked
`deleting`, then the service locks its storage key and vault, rechecks references,
deletes the payload, removes the row, and decrements byte/object counters in one
transactional critical section. Only an identical upload retry verifies or repairs
the payload before reactivating the row. Manifest commits fail with `MissingObject`
while a row is marked: the S3 deletion may already have succeeded before a SQL
rollback, so clearing the mark on a commit would risk missing committed data.
New writes and repairs use fresh random physical storage generations, while the
logical content-addressed object ID stays unchanged. Metadata points to the new
key atomically. A remote DELETE that finishes after a timeout can touch only the
retired generation, never the repaired payload. Existing healthy legacy keys
remain readable. Retired and interrupted-write generations become bucket-only
orphans; capacity planning must allow their grace-window overhead beyond logical
vault quotas.

The default scan interval is six hours and the default grace period is 24
hours. Override them with `FOLIORA_SYNC_GC_INTERVAL_SECONDS` (minimum 60) and
`FOLIORA_SYNC_GC_GRACE_SECONDS` (minimum 300). A scan that cannot list the
database or bucket stops on that failure; deletions completed earlier in the scan
are not rolled back. Each candidate fails closed if its reference check fails.
Individual delete failures are counted and retried on the next scan.

Committed history is not garbage-collected in protocol v1. All signed manifests,
opaque tombstones, and every ciphertext object referenced by any manifest remain
available indefinitely. This preserves the complete verifiable DAG for offline
devices, but consumed ciphertext quota is not reclaimable. Operators must not
manually prune database rows or referenced bucket keys.

Each vault still has its own immutable bootstrap quota. Operators can cap every
new vault with `FOLIORA_SYNC_MAX_VAULT_BYTES`; the default is 10 GiB and the
minimum accepted operator limit is 1 MiB. Requests above the cap fail before a
vault or credential is created. Existing per-vault accounting remains enforced
transactionally on every object upload.

Ciphertext bytes alone do not bound database growth, because a device can reuse
objects across many signed revisions. The service therefore also enforces
transactional per-vault ceilings of 100,000 object rows, 100,000 manifest rows,
and 512 MiB of serialized signed manifests. Configure them with
`FOLIORA_SYNC_MAX_OBJECTS_PER_VAULT`,
`FOLIORA_SYNC_MAX_MANIFESTS_PER_VAULT`, and
`FOLIORA_SYNC_MAX_MANIFEST_BYTES_PER_VAULT`. Invalid or zero values fail startup;
crossing any dimension rejects the write before heads, sequence, or counters
change. Vault status reports aggregate `objectCount`, `manifestCount`, and
`manifestBytes` without exposing content identifiers.

Manifest-byte accounting is defined as PostgreSQL `jsonb::text` UTF-8 length for
both migrated and newly committed rows. The service obtains that value from
PostgreSQL before enforcing the limit, so upgraded and new records share one
reproducible unit.

## Application rate limits

Every protected `/v1` request passes through two in-process token buckets before
body limits, JSON decoding, authentication or repository work: a global budget
and a per-credential budget. Missing or malformed authorization shares an
anonymous bucket. Valid `Bearer` values are keyed by the SHA-256 digest of the
canonical token; raw credentials and tenant identifiers are never retained by
the limiter. The credential table is bounded and excess identities share an
overflow bucket, so token rotation cannot create unbounded server memory. The
defaults are 240 requests/minute with burst 60 per credential, 6,000/minute
with burst 600 globally, and 10,000 tracked credentials.

Configure these with `FOLIORA_SYNC_RATE_PER_CREDENTIAL_PER_MINUTE`,
`FOLIORA_SYNC_RATE_PER_CREDENTIAL_BURST`,
`FOLIORA_SYNC_RATE_GLOBAL_PER_MINUTE`, `FOLIORA_SYNC_RATE_GLOBAL_BURST`, and
`FOLIORA_SYNC_RATE_MAX_CREDENTIALS`. Invalid or zero settings fail startup.
Exhaustion returns `429`, a numeric `Retry-After`, `Cache-Control: no-store`, and
a stable `rate_limited` JSON error including `retryAfterSeconds`. Liveness,
readiness, and private metrics do not share this user-traffic budget.

`FOLIORA_SYNC_REQUEST_DEADLINE_SECONDS` bounds every routed `/v1` request,
including streaming body parsing and repository work; the default is 120 seconds
and the maximum is ten minutes. Timeout returns `408` with `no-store`. Object
GET/PUT routes additionally acquire one of
`FOLIORA_SYNC_OBJECT_CONCURRENCY` process-local permits (default 32, maximum
1,024) before reading a body. When all permits are held, the service returns the
same retryable `429` contract without allocating a second object payload.

This limiter is defense-in-depth for a single service process: it resets on
restart and each replica has a separate budget. A public deployment must prevent
direct access to the Rust listener and configure its trusted ingress proxy with
shared source-IP, connection, upload/download byte, cross-replica concurrency,
and slow-header limits. Client-supplied forwarding headers must be stripped. Run
one API replica until those shared controls are verified.

## Ephemeral development mode

Set a random bootstrap token of at least 32 bytes. It authorizes vault creation
only; each device supplies a separate random token and the server retains only
its SHA-256 digest.

```sh
export FOLIORA_SYNC_BOOTSTRAP_TOKEN='replace-with-a-random-secret-of-32-or-more-bytes'
export FOLIORA_SYNC_BIND='127.0.0.1:8787'
export FOLIORA_SYNC_EPHEMERAL=1
cargo run -p foliora-sync-service
```

The service speaks plain HTTP. Bind to loopback for development. Any remote or
hosted deployment must terminate TLS at a trusted reverse proxy and must not
log request bodies or the `Authorization` header.

## API v1

All protected calls use `Authorization: Bearer <device-token>`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Process liveness and protocol version |
| `GET` | `/readyz` | PostgreSQL readiness |
| `GET` | `/metrics` | Aggregate Prometheus counters; no vault/device labels |
| `POST` | `/v1/vaults` | Create vault with bootstrap bearer |
| `GET` | `/v1/vaults/{vault}/status` | Epoch, quota, heads, active devices |
| `POST` | `/v1/vaults/{vault}/pairings` | Verify grant and create an inactive, expiring registration |
| `POST` | `/v1/vaults/{vault}/pairings/activate` | Activate after recipient confirms and decrypts the grant |
| `GET` | `/v1/vaults/{vault}/devices/{device}` | Read the retained signed authorization grant for a non-root device |
| `DELETE` | `/v1/vaults/{vault}/devices/{device}` | Revoke device, token, and rotate epoch |
| `PUT/GET` | `/v1/vaults/{vault}/objects/{object}` | Idempotent opaque encrypted object transfer |
| `PUT/GET` | `/v1/vaults/{vault}/manifests/{revision}` | Atomic signed revision commit/read |

Paths are bound to payload vault/object/revision/signer identifiers. Metadata
bodies are limited to 4 MiB. Object JSON is limited to 36 MiB, covering the
protocol's 25 MiB ciphertext ceiling in the canonical padded-base64 wire form.
Readers accept the earlier byte-array form only for migration compatibility.
Persisted legacy objects remain readable and semantically idempotent when a new
writer retries them, but legacy maximum-size array uploads must upgrade because
they exceed the request cap. Missing,
revoked, replayed, stale-epoch, over-quota, forged, and conflicting operations
fail without a partial manifest commit.

The server receives opaque ciphertext, signatures, public device records,
revision graph metadata, sizes and timing. It never receives epoch keys or vault
plaintext. Device tokens protect the account transport; they do not replace
client-side encryption or signature verification.

The desktop pairing UI uses a ten-minute request window. The request carries a
public recipient record and temporary bearer token; the recipient private key
stays in the encrypted local vault. A trusted device creates a signed
current-epoch grant, but the server stores the recipient as inactive. The token
cannot authenticate normal sync calls yet. Only after the recipient verifies
the out-of-band confirmation code and decrypts the grant does it call the
activation endpoint. The server stores only the code's SHA-256 digest, makes
activation idempotent for crash-safe retry, and removes expired inactive
registrations every 60 seconds by default. Configure that interval with
`FOLIORA_SYNC_PAIRING_CLEANUP_SECONDS` (minimum 10). A trusted device may also
delete an inactive registration through the normal device-revocation route;
doing so does not rotate the vault epoch because it never received access.

Activation also persists the exact signed pairing grant on the device row. An
active device may fetch that certificate through the device endpoint so a
client can verify a downloaded manifest signer back to a local trust anchor.
The root device has no authorization grant because it is the local trust root;
the endpoint therefore returns not found for it. Revocation blocks the revoked
credential but does not erase its certificate, which remains necessary to
authenticate historical manifests.

For the pre-stable `0005` upgrade only, active non-root rows without a retained
grant are treated as unusable credentials and make readiness fail. A root device
must revoke those legacy rows and pair fresh device identities; the service does
not invent an authorization chain that was never signed.

Confirmation attempts are persisted with the pending registration. Expiry is
checked before comparing a code. Four incorrect well-formed codes keep the
request pending; the fifth incorrect code deletes it atomically and every later
attempt receives the same generic unauthorized response. PostgreSQL takes a
transaction-scoped lock for the recipient token, then locks the pending row and
commits each failed-attempt update, so concurrent guesses and service restart
cannot reset or lose the counter. The same token lock serializes overlapping
successful calls; both observe the same active principal, preserving idempotency.
Malformed code strings are rejected before comparison and do not consume this
persistent budget, but they remain subject to the request limiter.

Recipient pairing timestamps allow up to five minutes of positive clock skew.
Accepted future expirations are clamped to the server's own ten-minute lifetime,
so skew tolerance cannot lengthen the server-side guessing window. Requests at
or before server time, beyond the bounded allowance, or outside the client's own
ten-minute lifetime fail closed.

In durable mode, PostgreSQL `clock_timestamp()` is the authority for pairing
clamping, activation expiry, cleanup, and the GC cutoff; rolling the API process
clock backward cannot reopen a registration or extend its lifetime. Bucket
object age still comes from the S3-compatible service's `last_modified`, so
operators must monitor PostgreSQL/object-store clock drift and fail deployment
checks when either clock is unsynchronized.

`/metrics` exposes process uptime, aggregate HTTP status/rate-limit counts, readiness
checks, orphan-GC totals, and expired-pairing cleanup totals. It intentionally
carries no vault, device, object, token, or path labels. Keep it on a private
monitoring network or protect it at the reverse proxy even though the default
Compose binding is loopback-only.

Readiness checks PostgreSQL, rejects active legacy non-root credentials without
an authorization certificate, and verifies that one deterministic metadata row
has a corresponding object-store key (or checks bucket access when no rows
exist). It is a bounded health signal, not a complete cross-store scrub; the
backup/restore drill compares full database and object inventories. With writers
and GC stopped, `--verify-integrity` performs a streaming read-only full scrub;
adding `--inventory-jsonl` emits independently hashed live entries, including
untracked orphans, for externally sorted pre-backup/post-restore comparisons.
Neither maintenance mode starts HTTP, applies migrations, or repairs data.

Production mode fails closed unless `DATABASE_URL`, `FOLIORA_S3_BUCKET`,
`FOLIORA_S3_REGION`, `FOLIORA_S3_ENDPOINT`, `FOLIORA_S3_ACCESS_KEY_ID`, and
`FOLIORA_S3_SECRET_ACCESS_KEY` are set. Plain-HTTP S3 endpoints additionally
require `FOLIORA_S3_ALLOW_HTTP=1`; use that only on a trusted private network.
