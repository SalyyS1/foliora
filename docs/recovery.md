# Vault backup and recovery

Foliora has two offline restore paths:

1. A verified `.foliora-backup` can be restored with its original passphrase.
2. The same backup can be restored without that passphrase when accompanied by
   its matching `.foliora-recovery` kit and one-time recovery code.

The recovery code contains 256 random bits rendered as sixteen hexadecimal
groups. It is returned to the webview once for the user to record and is never
written to disk. The kit stores only the vault encryption key wrapped with a
domain-separated SHA-256 key derived from that random secret and a per-kit salt,
using XChaCha20-Poly1305. Its authenticated data binds the kit format, source
vault salt, and kit salt.

Recovery validates the kit binding, unwraps the old vault key, authenticates and
validates the complete encrypted snapshot, then writes a new non-existing vault
encrypted under a new passphrase, fresh Argon2id salt, and fresh nonce. It never
overwrites the source backup or an existing destination.

## Operational rules

- Keep the encrypted backup, recovery kit, and recovery code in separate places.
- Creating a kit is not enough: onboarding remains blocked until the user
  explicitly confirms that the code was saved.
- A recovered vault requires a new recovery kit because it has a new encryption
  key and salt.
- Rotating recovery re-encrypts the local vault with a new salt/key epoch,
  invalidates old kits against the current vault, removes the local rollback
  artifact, and requires confirmation of the new kit. Copies of old backups or
  kits made elsewhere cannot be revoked remotely and must be destroyed by the
  user.
- There is no server-side password reset or master recovery secret.
