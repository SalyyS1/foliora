//! Merkle-tree selective context-pack inclusion proofs.
//!
//! Generates and verifies cryptographic inclusion proofs for individual claims
//! within a `ReviewedBundle`, allowing verifiable selective disclosure without
//! revealing or transmitting the entire context pack.

use crate::{hex_digest, ExportedClaim, ReviewedBundle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling_hash: String,
    pub is_left: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    pub bundle_id: String,
    pub root_sha256: String,
    pub claim_id: String,
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub leaf_hash: String,
    pub audit_path: Vec<MerkleProofStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveBundleProof {
    pub schema_version: u16,
    pub bundle_id: String,
    pub root_sha256: String,
    pub total_claims: usize,
    pub claims: Vec<ExportedClaim>,
    pub proofs: Vec<MerkleInclusionProof>,
}

pub const MERKLE_PROOF_SCHEMA_VERSION: u16 = 1;

/// Computes the deterministic leaf hash for an `ExportedClaim`.
pub fn compute_claim_leaf_hash(claim: &ExportedClaim) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"foliora:claim:v1:");
    hasher.update(claim.id.as_bytes());
    hasher.update(b":");
    hasher.update(claim.claim_type.as_bytes());
    hasher.update(b":");
    hasher.update(claim.subject.as_bytes());
    hasher.update(b":");
    if let Ok(bytes) = serde_json::to_vec(&claim.value) {
        hasher.update(&bytes);
    }
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

/// Hashes two Merkle nodes together with positional prefixes.
pub fn hash_merkle_nodes(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"foliora:merkle:node:v1:");
    hasher.update(left.as_bytes());
    hasher.update(b":");
    hasher.update(right.as_bytes());
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub levels: Vec<Vec<String>>,
}

impl MerkleTree {
    /// Builds a balanced binary Merkle tree from claims.
    pub fn from_claims(claims: &[ExportedClaim]) -> Self {
        if claims.is_empty() {
            let empty_root = format!(
                "sha256:{}",
                hex_digest(&Sha256::digest(b"foliora:empty:bundle"))
            );
            return Self {
                leaves: Vec::new(),
                levels: vec![vec![empty_root]],
            };
        }

        let leaves: Vec<String> = claims.iter().map(compute_claim_leaf_hash).collect();
        let mut levels = vec![leaves.clone()];
        let mut current = leaves.clone();

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_merkle_nodes(&chunk[0], &chunk[1]));
                } else {
                    // Duplicate odd node to balance tree
                    next.push(hash_merkle_nodes(&chunk[0], &chunk[0]));
                }
            }
            levels.push(next.clone());
            current = next;
        }

        Self { leaves, levels }
    }

    /// Returns the root SHA-256 digest of the tree.
    pub fn root(&self) -> String {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .cloned()
            .unwrap_or_else(|| {
                format!(
                    "sha256:{}",
                    hex_digest(&Sha256::digest(b"foliora:empty:bundle"))
                )
            })
    }

    /// Generates an inclusion proof for a specific leaf index.
    pub fn proof_for_index(
        &self,
        bundle_id: &str,
        claim_id: &str,
        leaf_index: usize,
    ) -> Option<MerkleInclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut audit_path = Vec::new();
        let mut idx = leaf_index;

        for level in &self.levels[..self.levels.len() - 1] {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right {
                idx - 1
            } else if idx + 1 < level.len() {
                idx + 1
            } else {
                idx // odd element duplicated with itself
            };

            audit_path.push(MerkleProofStep {
                sibling_hash: level[sibling_idx].clone(),
                is_left: is_right,
            });

            idx /= 2;
        }

        Some(MerkleInclusionProof {
            bundle_id: bundle_id.to_string(),
            root_sha256: self.root(),
            claim_id: claim_id.to_string(),
            leaf_index,
            total_leaves: self.leaves.len(),
            leaf_hash: self.leaves[leaf_index].clone(),
            audit_path,
        })
    }
}

/// Verifies a single Merkle inclusion proof against an expected root hash.
pub fn verify_merkle_proof(proof: &MerkleInclusionProof, expected_root: &str) -> bool {
    let mut current = proof.leaf_hash.clone();
    for step in &proof.audit_path {
        if step.is_left {
            current = hash_merkle_nodes(&step.sibling_hash, &current);
        } else {
            current = hash_merkle_nodes(&current, &step.sibling_hash);
        }
    }
    current == expected_root
}

/// Verifies that a specific `ExportedClaim` matches its inclusion proof and connects to `expected_root`.
pub fn verify_claim_inclusion(
    claim: &ExportedClaim,
    proof: &MerkleInclusionProof,
    expected_root: &str,
) -> bool {
    if claim.id != proof.claim_id {
        return false;
    }
    let computed_leaf = compute_claim_leaf_hash(claim);
    if computed_leaf != proof.leaf_hash {
        return false;
    }
    verify_merkle_proof(proof, expected_root)
}

/// Generates a `SelectiveBundleProof` for selected claim IDs from a `ReviewedBundle`.
pub fn generate_selective_bundle_proof(
    bundle: &ReviewedBundle,
    selected_claim_ids: &[String],
) -> Result<SelectiveBundleProof, String> {
    if bundle.claims.is_empty() {
        return Err("cannot generate Merkle proof for empty bundle".to_string());
    }

    let tree = MerkleTree::from_claims(&bundle.claims);
    let mut verified_claims = Vec::new();
    let mut proofs = Vec::new();

    let target_ids: BTreeSet<&str> = selected_claim_ids.iter().map(|s| s.as_str()).collect();

    for (idx, claim) in bundle.claims.iter().enumerate() {
        if target_ids.is_empty() || target_ids.contains(claim.id.as_str()) {
            let proof = tree
                .proof_for_index(&bundle.id, &claim.id, idx)
                .ok_or_else(|| format!("failed to generate proof for leaf index {idx}"))?;
            verified_claims.push(claim.clone());
            proofs.push(proof);
        }
    }

    if verified_claims.is_empty() {
        return Err("no matching claims found in bundle".to_string());
    }

    Ok(SelectiveBundleProof {
        schema_version: MERKLE_PROOF_SCHEMA_VERSION,
        bundle_id: bundle.id.clone(),
        root_sha256: tree.root(),
        total_claims: bundle.claims.len(),
        claims: verified_claims,
        proofs,
    })
}

/// Verifies a complete `SelectiveBundleProof`.
pub fn verify_selective_bundle_proof(
    proof: &SelectiveBundleProof,
    expected_root: Option<&str>,
) -> Result<bool, String> {
    if proof.claims.len() != proof.proofs.len() {
        return Err(format!(
            "mismatch between claims count ({}) and proofs count ({})",
            proof.claims.len(),
            proof.proofs.len()
        ));
    }

    let target_root = expected_root.unwrap_or(&proof.root_sha256);

    for (claim, p) in proof.claims.iter().zip(&proof.proofs) {
        if !verify_claim_inclusion(claim, p, target_root) {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use foliora_domain::{Sensitivity, SourceLocator};
    use serde_json::Value;

    fn make_test_claims() -> Vec<ExportedClaim> {
        vec![
            ExportedClaim {
                id: "claim:1".to_string(),
                claim_type: "sla.uptime".to_string(),
                subject: "api".to_string(),
                value: Value::String("99.95% monthly uptime".to_string()),
                sensitivity: Sensitivity::Public,
                provenance: crate::ExportedProvenance {
                    source_id: Some("src:1".to_string()),
                    locator: Some(SourceLocator::Span { start: 0, end: 10 }),
                    user_entered_at: None,
                },
            },
            ExportedClaim {
                id: "claim:2".to_string(),
                claim_type: "sla.latency".to_string(),
                subject: "api".to_string(),
                value: Value::String("45 ms median latency".to_string()),
                sensitivity: Sensitivity::Internal,
                provenance: crate::ExportedProvenance {
                    source_id: Some("src:1".to_string()),
                    locator: Some(SourceLocator::Span { start: 11, end: 20 }),
                    user_entered_at: None,
                },
            },
            ExportedClaim {
                id: "claim:3".to_string(),
                claim_type: "sec.encryption".to_string(),
                subject: "vault".to_string(),
                value: Value::String("AES-256-GCM data at rest".to_string()),
                sensitivity: Sensitivity::Private,
                provenance: crate::ExportedProvenance {
                    source_id: Some("src:2".to_string()),
                    locator: Some(SourceLocator::Span { start: 0, end: 15 }),
                    user_entered_at: None,
                },
            },
        ]
    }

    #[test]
    fn merkle_tree_leaf_and_root_deterministic() {
        let claims = make_test_claims();
        let tree1 = MerkleTree::from_claims(&claims);
        let tree2 = MerkleTree::from_claims(&claims);

        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.leaves.len(), 3);
        assert!(tree1.root().starts_with("sha256:"));
    }

    #[test]
    fn inclusion_proof_verifies_each_claim() {
        let claims = make_test_claims();
        let tree = MerkleTree::from_claims(&claims);
        let root = tree.root();

        for (idx, claim) in claims.iter().enumerate() {
            let proof = tree.proof_for_index("bundle:test", &claim.id, idx).unwrap();
            assert!(verify_claim_inclusion(claim, &proof, &root));
        }
    }

    #[test]
    fn inclusion_proof_rejects_tampered_claim_value() {
        let claims = make_test_claims();
        let tree = MerkleTree::from_claims(&claims);
        let root = tree.root();

        let proof = tree.proof_for_index("bundle:test", "claim:1", 0).unwrap();

        let mut tampered_claim = claims[0].clone();
        tampered_claim.value = Value::String("100% fake uptime".to_string());

        assert!(!verify_claim_inclusion(&tampered_claim, &proof, &root));
    }

    #[test]
    fn selective_bundle_proof_roundtrip() {
        let claims = make_test_claims();
        let bundle = ReviewedBundle {
            schema_version: 1,
            domain_schema_version: 1,
            id: "bundle:sel-test".to_string(),
            purpose: "selective disclosure test".to_string(),
            exported_at: "2026-11-19T00:00:00Z".to_string(),
            expires_at: None,
            claims: claims.clone(),
            evidence: Vec::new(),
        };

        // Selectively prove only claim:2
        let sel_proof = generate_selective_bundle_proof(&bundle, &["claim:2".to_string()]).unwrap();
        assert_eq!(sel_proof.claims.len(), 1);
        assert_eq!(sel_proof.claims[0].id, "claim:2");
        assert_eq!(sel_proof.proofs.len(), 1);

        let valid = verify_selective_bundle_proof(&sel_proof, None).unwrap();
        assert!(valid);
    }
}
