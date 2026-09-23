# E2EE sync protocol foundation

Protocol version 1 separates client cryptography from opaque service storage.

## Client objects

Each vault epoch has a random 256-bit key. A client encrypts a non-empty bounded
object with XChaCha20-Poly1305 and authenticates the protocol version, vault ID,
and epoch as associated data. The object ID is SHA-256 over that associated data,
nonce, and ciphertext. Changing the vault, epoch, nonce, or payload invalidates
the identifier or authentication tag. New writers serialize ciphertext as
canonical padded base64, allowing the full 25 MiB plaintext ceiling to remain
inside the 36 MiB HTTP object bound. Readers accept the earlier JSON byte-array
shape for stored-object migration and bounded requests. A legacy client sending
a maximum-size byte array must upgrade because that representation exceeds the
hardened request cap.

Devices have Ed25519 identities. A canonical manifest records vault, epoch,
parents, referenced object IDs, opaque tombstones, device ID, and a monotonic
per-device sequence. It is content-addressed and signed. Concurrent children of
one parent remain separate heads; a later client must resolve domain conflicts
and create an explicit merge revision referencing every chosen head.

A device record binds its Ed25519 signing key and X25519 exchange key into the
device ID. Pairing is authorized by a signed grant from an active trusted device.
The grant transports only the current epoch key, encrypted to the recipient via
X25519, HKDF-SHA-256 and XChaCha20-Poly1305. A short code derived from the exact
grant must be compared out of band before the recipient accepts the key. A
malicious server cannot replace the recipient, ciphertext, epoch, or signer
without invalidating the signature or confirmation.

The same signed grant carries a bounded snapshot of trusted device records and
the exact manifest heads known to the authorizer. The service retains that grant
as the recipient's authorization certificate. On download, the desktop verifies
the manifest signature through at most 32 signed device-authority links until it
reaches a device in its local trust snapshot. A newly paired device accepts its
first server view only when the returned heads exactly match the heads signed at
pairing. Later remote heads must descend from every locally known head; the
client authenticates each traversed manifest and fails closed after 4,096
ancestors. These checks detect substitution and rollback below a state the
client has already observed, but cannot prove that an untrusted server disclosed
branches that no trusted client has ever seen.

Every authorization link must use the same key epoch as the downloaded manifest
and local profile, preventing an old pre-revocation grant from authorizing a new
epoch. One desktop sync run has an aggregate five-minute deadline in addition to
per-request limits. Before applying any asynchronous result, the desktop
compares a volatile session identity, exact vault path and encrypted sync profile.
Lock/reopen invalidates the identity even for the same path. Downloads also
compare the captured local snapshot digest and never replace intervening edits.
A verified own-upload result may persist its consumed sequence/head checkpoint
without replacing edited content. Pairing completion and initial download require
an empty destination; returning a pairing grant also requires the live matching
session/profile. A crash before a verified upload acknowledgement followed by
local edits remains an explicit conflict-recovery case.

## Opaque service invariants

The service accepts an object before its manifest so interrupted uploads can be
retried idempotently. Old staged objects that never become referenced may be
reclaimed after the advertised grace window; an identical client retry restores
or reactivates them into a fresh physical storage generation. Late deletes can
touch only the retired key. Logical object IDs and wire formats are unchanged;
healthy legacy storage keys remain readable. A manifest cannot reactivate a
deletion-marked row without a reupload. A commit is rejected unless its signature, device,
epoch, sequence, parents, and every referenced object validate. The head set and
sequence advance only after all checks pass.

Revoking a device disables its credential and increments the key epoch. The
server does not distribute keys; trusted clients must deliver the new epoch key
only to active devices. Old ciphertext remains available to devices that already
possessed its key, which revocation cannot undo.

## Historical retention

Protocol v1 retains the complete immutable signed manifest graph, every opaque
tombstone inside it, and every ciphertext object referenced by any committed
manifest. The server garbage collector deletes only unreferenced upload orphans
after a grace window. It never interprets tombstones or prunes committed history.

This fail-closed policy preserves the historical bytes needed for recovery and
future graph verification by long-offline devices. Only abandoned staged uploads
reclaim vault quota; committed history does not. A safe future compaction protocol
must use a client-signed checkpoint and explicit acknowledgement from every
active device; server wall-clock age is not sufficient. Operational backup and
restore requirements are documented in `sync-backup-restore.md`.

## Still required before network release

- signed multi-device compaction if reclaiming historical quota is required;
- clock-skew, malicious-server and load tests;
- independent cryptographic protocol review.

## Network retry policy

The client makes at most three attempts within a 180-second overall deadline.
It retries transport failures and temporary HTTP 408/425/429 or 5xx
responses only for operations whose server behavior is idempotent: GET, PUT
object/manifest, and crash-safe pairing activation. Numeric `Retry-After` is
honored up to five seconds; otherwise delays are 100 ms then 300 ms.

Vault creation, pairing registration and device revocation are never retried
automatically because a lost response could hide a committed side effect.
Authentication, authorization, validation and conflict responses also return
immediately. Tests cover a dropped connection, temporary failure recovery,
activation retry, and negative cases for credentials and unsafe POST requests.
If a manifest PUT committed but its response was lost, the next run can recover
without reusing the sequence: it accepts only the expected self-signed sequence
and parents, decrypts its sole object, and requires the plaintext digest to equal
the current local snapshot before advancing the encrypted profile.

## Desktop pairing flow

The desktop implements a copy/paste pairing flow for a second device. The new
device creates a request containing only its public device record, a temporary
transport token, the target vault and endpoint. The private device keys remain
in a pending record inside the encrypted local vault. The trusted device
verifies the target, signs a current-epoch grant, and registers the recipient
token with the service as an inactive registration. The devices compare the
grant confirmation code over a separate channel; only then does the new device
accept the epoch key and activate its token. Activation is idempotent so a
client can retry after a crash before local profile persistence. Requests
expire after ten minutes; the service periodically removes abandoned inactive
registrations, and the encrypted local pending record is consumed only after
activation succeeds. Initial sync downloads the remote snapshot before the new
device can write a revision. The initial heads are bound into the signed grant;
the desktop rejects a different server head set instead of silently accepting a
rolled-back or substituted starting point.

The service checks expiry before the confirmation digest and persists failed
attempts under a token-scoped transaction lock plus a pending-row lock. The
fifth incorrect well-formed code destroys the pending registration; the generic
unauthorized response does not reveal whether that deletion just occurred.
The token lock also makes overlapping successful activation retries idempotent.

Pairing request validation tolerates at most five minutes of positive device
clock skew. The server never extends its own ten-minute activation window: a
request within that skew allowance is clamped to server time plus ten minutes,
an already-expired request is rejected, and larger skew fails closed. Exact
expiry is treated as expired on both client and service boundaries.
