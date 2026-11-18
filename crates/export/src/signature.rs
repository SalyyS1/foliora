//! Ed25519 cryptographic signing and verification for `ReviewedBundle` artifacts.
//!
//! Uses a domain-separated canonical JSON digest (`FOLIORA-REVIEWED-BUNDLE-SIG-V1`)
//! and strict Ed25519 verification (`verify_strict`) so formatting whitespace never
//! breaks valid signatures while any mutation to claims, provenance, evidence, or
//! signature metadata fails closed.

use crate::{hex_digest, ReviewedBundle};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use foliora_domain::validate_canonical_timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SIGNATURE_SCHEMA_VERSION: u16 = 1;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const SECRET_KEY_PREFIX: &str = "foliora-ed25519-secret-v1:";
pub const PUBLIC_KEY_PREFIX: &str = "foliora-ed25519-public-v1:";

const CANONICAL_BUNDLE_HASH_DOMAIN: &[u8] = b"FOLIORA-REVIEWED-BUNDLE-CANONICAL-V1\0";
const BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"FOLIORA-REVIEWED-BUNDLE-SIG-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    Randomness,
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignatureEncoding,
    UnsupportedSchemaVersion(u16),
    UnsupportedAlgorithm(String),
    InvalidTimestamp,
    KeyIdMismatch {
        expected: String,
        actual: String,
    },
    PinnedKeyMismatch {
        expected_key_id: String,
        actual_key_id: String,
    },
    BundleIdMismatch {
        expected: String,
        actual: String,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
    CryptographicVerificationFailed,
    Serialize(String),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Randomness => write!(f, "OS CSPRNG failed to generate Ed25519 key seed"),
            Self::InvalidSecretKey => {
                write!(
                    f,
                    "invalid Ed25519 secret key encoding (expected 32-byte seed)"
                )
            }
            Self::InvalidPublicKey => {
                write!(
                    f,
                    "invalid Ed25519 public key encoding (expected 32-byte point)"
                )
            }
            Self::InvalidSignatureEncoding => {
                write!(
                    f,
                    "invalid Ed25519 signature encoding (expected 64-byte signature)"
                )
            }
            Self::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported signature schema version {v}")
            }
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported signature algorithm '{alg}'")
            }
            Self::InvalidTimestamp => {
                write!(
                    f,
                    "signed_at must use canonical UTC format YYYY-MM-DDTHH:MM:SSZ"
                )
            }
            Self::KeyIdMismatch { expected, actual } => {
                write!(
                    f,
                    "key_id mismatch: derived {expected}, manifest has {actual}"
                )
            }
            Self::PinnedKeyMismatch {
                expected_key_id,
                actual_key_id,
            } => write!(
                f,
                "signer public key ({actual_key_id}) does not match pinned key ({expected_key_id})"
            ),
            Self::BundleIdMismatch { expected, actual } => {
                write!(
                    f,
                    "bundle_id mismatch: bundle is {expected}, signature binds {actual}"
                )
            }
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "canonical bundle digest mismatch: signature binds {expected}, computed {actual}"
            ),
            Self::CryptographicVerificationFailed => {
                write!(f, "Ed25519 cryptographic signature verification failed")
            }
            Self::Serialize(err) => write!(f, "canonical JSON serialization failed: {err}"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Generated Ed25519 keypair with armored secret/public strings and deterministic `key_id`.
#[derive(Debug, Clone)]
pub struct GeneratedSigningKeyPair {
    pub key_id: String,
    pub public_key: String,
    pub secret_key: Zeroizing<String>,
}

/// Detached cryptographic signature envelope for a `ReviewedBundle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSignature {
    pub schema_version: u16,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub bundle_id: String,
    pub bundle_sha256: String,
    pub signed_at: String,
    pub signature: String,
}

/// Self-contained inline signed `ReviewedBundle` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReviewedBundle {
    pub bundle: ReviewedBundle,
    pub signature: BundleSignature,
}

/// Report returned when an Ed25519 signature over a `ReviewedBundle` verifies cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationReport {
    pub bundle_id: String,
    pub key_id: String,
    pub bundle_sha256: String,
    pub signed_at: String,
    pub pinned_key_verified: bool,
}

/// Generates a fresh Ed25519 signing keypair from the OS CSPRNG.
pub fn generate_signing_keypair() -> Result<GeneratedSigningKeyPair, SignatureError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| SignatureError::Randomness)?;

    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let key_id = derive_key_id(&verifying);
    let public_key = format!(
        "{PUBLIC_KEY_PREFIX}{}",
        BASE64_STD.encode(verifying.as_bytes())
    );
    let secret_key = Zeroizing::new(format!(
        "{SECRET_KEY_PREFIX}{}",
        BASE64_STD.encode(seed.as_ref())
    ));

    Ok(GeneratedSigningKeyPair {
        key_id,
        public_key,
        secret_key,
    })
}

/// Derives the deterministic key identifier (`ed25519:<16-hex>`) from an Ed25519 verifying key.
pub fn derive_key_id(verifying_key: &VerifyingKey) -> String {
    let digest = hex_digest(verifying_key.as_bytes());
    format!("ed25519:{}", &digest[..16])
}

/// Computes the deterministic canonical SHA-256 digest (`sha256:<64-hex>`) of a `ReviewedBundle`.
pub fn canonical_bundle_sha256(bundle: &ReviewedBundle) -> Result<String, SignatureError> {
    let value =
        serde_json::to_value(bundle).map_err(|e| SignatureError::Serialize(e.to_string()))?;
    let mut canonical_bytes = Vec::with_capacity(512);
    write_canonical_json(&value, &mut canonical_bytes)?;

    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_BUNDLE_HASH_DOMAIN);
    hasher.update(&canonical_bytes);
    Ok(format!("sha256:{}", hex_digest(&hasher.finalize())))
}

fn write_canonical_json(value: &Value, out: &mut Vec<u8>) -> Result<(), SignatureError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(num) => {
            let encoded =
                serde_json::to_string(num).map_err(|e| SignatureError::Serialize(e.to_string()))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::String(s) => {
            let encoded =
                serde_json::to_string(s).map_err(|e| SignatureError::Serialize(e.to_string()))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // serde_json::Map defaults to BTreeMap when preserve_order is not enabled,
            // and sorting keys explicitly guarantees lexicographic UTF-8 byte order regardless
            // of feature unification across workspace dependencies.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (idx, key) in keys.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                let encoded_key = serde_json::to_string(key)
                    .map_err(|e| SignatureError::Serialize(e.to_string()))?;
                out.extend_from_slice(encoded_key.as_bytes());
                out.push(b':');
                if let Some(val) = map.get(key) {
                    write_canonical_json(val, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn build_signing_message(
    schema_version: u16,
    key_id: &str,
    bundle_id: &str,
    bundle_sha256: &str,
    signed_at: &str,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(BUNDLE_SIGNATURE_DOMAIN);
    msg.extend_from_slice(schema_version.to_string().as_bytes());
    msg.push(0);
    msg.extend_from_slice(key_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(bundle_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(bundle_sha256.as_bytes());
    msg.push(0);
    msg.extend_from_slice(signed_at.as_bytes());
    msg
}

fn decode_32_byte_key(encoded: &str, expected_prefix: &str) -> Option<Zeroizing<[u8; 32]>> {
    let trimmed = encoded.trim();
    let payload = trimmed.strip_prefix(expected_prefix).unwrap_or(trimmed);

    let decoded = if payload.len() == 64 && payload.bytes().all(|b| b.is_ascii_hexdigit()) {
        decode_hex(payload)?
    } else {
        BASE64_STD
            .decode(payload)
            .or_else(|_| URL_SAFE_NO_PAD.decode(payload))
            .ok()?
    };

    if decoded.len() != 32 {
        return None;
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&decoded);
    Some(arr)
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut idx = 0;
    while idx + 1 < bytes.len() {
        let hi = hex_nibble(bytes[idx])?;
        let lo = hex_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_signing_key(secret_key: &str) -> Result<SigningKey, SignatureError> {
    if secret_key.trim().starts_with(PUBLIC_KEY_PREFIX) {
        return Err(SignatureError::InvalidSecretKey);
    }
    let seed = decode_32_byte_key(secret_key, SECRET_KEY_PREFIX)
        .ok_or(SignatureError::InvalidSecretKey)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parses an armored, base64, or hex Ed25519 public key into a `VerifyingKey`.
pub fn parse_verifying_key(public_key: &str) -> Result<VerifyingKey, SignatureError> {
    if public_key.trim().starts_with(SECRET_KEY_PREFIX) {
        return Err(SignatureError::InvalidPublicKey);
    }
    let raw = decode_32_byte_key(public_key, PUBLIC_KEY_PREFIX)
        .ok_or(SignatureError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| SignatureError::InvalidPublicKey)
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in lhs.iter().zip(rhs.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Signs a `ReviewedBundle` with an Ed25519 secret key, producing a detached `BundleSignature`.
pub fn sign_reviewed_bundle(
    bundle: &ReviewedBundle,
    secret_key: &str,
    signed_at: &str,
) -> Result<BundleSignature, SignatureError> {
    validate_canonical_timestamp(signed_at, "signed_at")
        .map_err(|_| SignatureError::InvalidTimestamp)?;
    let signing = parse_signing_key(secret_key)?;
    let verifying = signing.verifying_key();
    let key_id = derive_key_id(&verifying);
    let public_key = format!(
        "{PUBLIC_KEY_PREFIX}{}",
        BASE64_STD.encode(verifying.as_bytes())
    );
    let bundle_sha256 = canonical_bundle_sha256(bundle)?;

    let message = build_signing_message(
        SIGNATURE_SCHEMA_VERSION,
        &key_id,
        &bundle.id,
        &bundle_sha256,
        signed_at,
    );
    let sig: Signature = signing.sign(&message);

    Ok(BundleSignature {
        schema_version: SIGNATURE_SCHEMA_VERSION,
        algorithm: SIGNATURE_ALGORITHM.to_owned(),
        key_id,
        public_key,
        bundle_id: bundle.id.clone(),
        bundle_sha256,
        signed_at: signed_at.to_owned(),
        signature: BASE64_STD.encode(sig.to_bytes()),
    })
}

/// Signs a `ReviewedBundle` into a self-contained `SignedReviewedBundle` envelope.
pub fn sign_reviewed_bundle_inline(
    bundle: ReviewedBundle,
    secret_key: &str,
    signed_at: &str,
) -> Result<SignedReviewedBundle, SignatureError> {
    let signature = sign_reviewed_bundle(&bundle, secret_key, signed_at)?;
    Ok(SignedReviewedBundle { bundle, signature })
}

/// Verifies an Ed25519 `BundleSignature` against `bundle` and an optional pinned public key.
pub fn verify_bundle_signature(
    bundle: &ReviewedBundle,
    sig: &BundleSignature,
    pinned_public_key: Option<&str>,
) -> Result<SignatureVerificationReport, SignatureError> {
    if sig.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(SignatureError::UnsupportedSchemaVersion(sig.schema_version));
    }
    if sig.algorithm != SIGNATURE_ALGORITHM {
        return Err(SignatureError::UnsupportedAlgorithm(sig.algorithm.clone()));
    }
    validate_canonical_timestamp(&sig.signed_at, "signed_at")
        .map_err(|_| SignatureError::InvalidTimestamp)?;

    let verifying = parse_verifying_key(&sig.public_key)?;
    if verifying.is_weak() {
        return Err(SignatureError::InvalidPublicKey);
    }

    let derived_key_id = derive_key_id(&verifying);
    if !constant_time_eq(derived_key_id.as_bytes(), sig.key_id.as_bytes()) {
        return Err(SignatureError::KeyIdMismatch {
            expected: derived_key_id,
            actual: sig.key_id.clone(),
        });
    }

    let mut pinned_verified = false;
    if let Some(pinned_str) = pinned_public_key {
        let pinned_vk = parse_verifying_key(pinned_str)?;
        if !constant_time_eq(verifying.as_bytes(), pinned_vk.as_bytes()) {
            return Err(SignatureError::PinnedKeyMismatch {
                expected_key_id: derive_key_id(&pinned_vk),
                actual_key_id: derived_key_id,
            });
        }
        pinned_verified = true;
    }

    if sig.bundle_id != bundle.id {
        return Err(SignatureError::BundleIdMismatch {
            expected: bundle.id.clone(),
            actual: sig.bundle_id.clone(),
        });
    }

    let computed_sha256 = canonical_bundle_sha256(bundle)?;
    if !constant_time_eq(computed_sha256.as_bytes(), sig.bundle_sha256.as_bytes()) {
        return Err(SignatureError::DigestMismatch {
            expected: sig.bundle_sha256.clone(),
            actual: computed_sha256,
        });
    }

    let sig_bytes = BASE64_STD
        .decode(sig.signature.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(sig.signature.trim()))
        .map_err(|_| SignatureError::InvalidSignatureEncoding)?;
    let ed_sig =
        Signature::from_slice(&sig_bytes).map_err(|_| SignatureError::InvalidSignatureEncoding)?;

    let message = build_signing_message(
        sig.schema_version,
        &sig.key_id,
        &sig.bundle_id,
        &sig.bundle_sha256,
        &sig.signed_at,
    );

    verifying
        .verify_strict(&message, &ed_sig)
        .map_err(|_| SignatureError::CryptographicVerificationFailed)?;

    Ok(SignatureVerificationReport {
        bundle_id: bundle.id.clone(),
        key_id: derived_key_id,
        bundle_sha256: computed_sha256,
        signed_at: sig.signed_at.clone(),
        pinned_key_verified: pinned_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceSource, ExportedClaim, ExportedProvenance};
    use foliora_domain::{Sensitivity, SourceLocator};

    fn sample_bundle() -> ReviewedBundle {
        ReviewedBundle {
            schema_version: 1,
            domain_schema_version: 1,
            id: "bundle:sig-test-1".into(),
            purpose: "Cryptographic attestation test".into(),
            exported_at: "2026-11-18T00:00:00Z".into(),
            expires_at: Some("2027-01-01T00:00:00Z".into()),
            claims: vec![ExportedClaim {
                id: "claim:tls".into(),
                claim_type: "security.tls".into(),
                subject: "gateway".into(),
                value: Value::String("TLS 1.3 enforced".into()),
                sensitivity: Sensitivity::Internal,
                provenance: ExportedProvenance {
                    source_id: Some("source:cfg".into()),
                    locator: Some(SourceLocator::Span { start: 10, end: 42 }),
                    user_entered_at: None,
                },
            }],
            evidence: vec![EvidenceSource {
                id: "source:cfg".into(),
                fingerprint:
                    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
                media_type: "text/plain".into(),
                title: Some("gateway.conf".into()),
                captured_at: "2026-11-18T00:00:00Z".into(),
            }],
        }
    }

    #[test]
    fn keygen_sign_and_verify_detached_and_pinned_roundtrip() {
        let kp = generate_signing_keypair().unwrap();
        let bundle = sample_bundle();
        let sig = sign_reviewed_bundle(&bundle, &kp.secret_key, "2026-11-18T01:00:00Z").unwrap();

        assert_eq!(sig.key_id, kp.key_id);
        assert_eq!(sig.algorithm, "ed25519");

        let unpinned = verify_bundle_signature(&bundle, &sig, None).unwrap();
        assert!(!unpinned.pinned_key_verified);
        assert_eq!(unpinned.key_id, kp.key_id);

        let pinned = verify_bundle_signature(&bundle, &sig, Some(&kp.public_key)).unwrap();
        assert!(pinned.pinned_key_verified);
    }

    #[test]
    fn canonical_digest_is_invariant_across_pretty_and_compact_json() {
        let kp = generate_signing_keypair().unwrap();
        let bundle = sample_bundle();
        let sig = sign_reviewed_bundle(&bundle, &kp.secret_key, "2026-11-18T01:00:00Z").unwrap();

        let compact = serde_json::to_string(&bundle).unwrap();
        let reparsed: ReviewedBundle = serde_json::from_str(&compact).unwrap();
        assert!(verify_bundle_signature(&reparsed, &sig, Some(&kp.public_key)).is_ok());
    }

    #[test]
    fn tampering_with_claim_metadata_or_key_fails_closed() {
        let kp1 = generate_signing_keypair().unwrap();
        let kp2 = generate_signing_keypair().unwrap();
        let bundle = sample_bundle();
        let sig = sign_reviewed_bundle(&bundle, &kp1.secret_key, "2026-11-18T01:00:00Z").unwrap();

        // 1. Mutated claim value
        let mut mutated = bundle.clone();
        mutated.claims[0].value = Value::String("TLS 1.0 allowed".into());
        assert!(matches!(
            verify_bundle_signature(&mutated, &sig, Some(&kp1.public_key)),
            Err(SignatureError::DigestMismatch { .. })
        ));

        // 2. Mutated signed_at timestamp
        let mut tampered_time = sig.clone();
        tampered_time.signed_at = "2026-11-19T01:00:00Z".into();
        assert_eq!(
            verify_bundle_signature(&bundle, &tampered_time, Some(&kp1.public_key)),
            Err(SignatureError::CryptographicVerificationFailed)
        );

        // 3. Pinned key mismatch (attacker re-signs with kp2)
        let attacker_sig =
            sign_reviewed_bundle(&bundle, &kp2.secret_key, "2026-11-18T01:00:00Z").unwrap();
        assert!(matches!(
            verify_bundle_signature(&bundle, &attacker_sig, Some(&kp1.public_key)),
            Err(SignatureError::PinnedKeyMismatch { .. })
        ));
    }
}
