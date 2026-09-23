# Foliora sync protocol v1

This Apache-2.0 package documents the wire shape shared by clients and the
self-hostable service. Cryptographic verification remains in the Rust client
and service; the JavaScript helpers validate only bounded transport shapes.

- Encrypted objects are XChaCha20-Poly1305 ciphertext, addressed by SHA-256 over
  the protocol AAD, nonce, and ciphertext. New writers encode ciphertext as
  canonical padded base64 so the 25 MiB payload limit fits the 36 MiB HTTP body
  bound. Persistence readers and bounded network requests retain compatibility
  with the earlier JSON byte-array shape; legacy maximum-size array uploads must
  be upgraded because they exceed the hardened HTTP body cap.
- Manifest revisions are canonical JSON records signed with Ed25519.
- Parents form an append-only DAG. Multiple heads represent concurrent offline
  edits and must be merged explicitly by a client.
- Tombstones represent deletion. The server cannot interpret their identifiers.
- Device revocation advances the vault epoch. A revoked credential cannot read
  or write through the service and receives no future epoch keys.
- The server sees account/device identifiers, epochs, sizes, graph shape, and
  timing. It never receives epoch keys or plaintext objects.
- Trusted-device pairing binds Ed25519 signing and X25519 exchange keys into one
  device ID. The trusted device signs a grant and encrypts the current epoch key
  to the recipient with X25519, HKDF-SHA-256, and XChaCha20-Poly1305. Both users
  compare the grant's short confirmation code before the recipient accepts it.
  The HTTP service keeps the recipient registration inactive until that local
  verification succeeds; abandoned registrations expire after ten minutes.
  The signed grant also carries at most 64 sorted trust-anchor records and at
  most 32 sorted manifest heads. Rust clients use that context to authenticate
  future signer-authorization chains and bind the recipient's initial history.

Canonical signature bytes are UTF-8 JSON serialization of the Rust `Manifest`
field order. Cross-language signers must reproduce the corresponding conformance
fixture before claiming protocol compatibility.
