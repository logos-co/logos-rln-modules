//! Per-membership Merkle proof-path cache, maintained by the poller's
//! refresh pass and `start`'s warm-up so `generate_proof` normally serves
//! its witness path with no registry I/O.
//!
//! Entries are keyed by `membership_hash` and record the decoded, validated
//! path plus the `leaf_index` it was fetched against. A `leaf_index` is
//! provisional until the pending→active re-read, and a proof over a
//! stale-leaf path would silently burn a persisted `message_id` slot — so
//! [`hit`] misses on any leaf_index mismatch; callers fall back to an
//! on-demand fetch and the next poller refresh overwrites the entry.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::provider::RegistryProvider;
use crate::registry_id::CanonicalRegistryId;
use crate::util::lock;
use crate::error::{ApiError, ErrorKind};

struct CachedPath {
    path_elements_hex: Vec<String>,
    path_indices: Vec<u8>,
    leaf_index: u64,
}

static PATHS: Mutex<Option<HashMap<String, CachedPath>>> = Mutex::new(None);


/// A provider `get_merkle_proof` reply, decoded in one place so a cache hit
/// and a cache miss build identically-shaped witnesses.
#[derive(serde::Deserialize)]
struct MerkleProofReply {
    path_elements: Vec<String>,
    path_indices: Vec<u8>,
    depth: Option<u64>,
    valid_roots: Option<Vec<String>>,
}

fn decode_merkle_proof(merkle: serde_json::Value) -> Result<MerkleProofReply, ApiError> {
    serde_json::from_value(merkle).map_err(|e| {
        ApiError::new(ErrorKind::ProviderFailure, &format!("merkle proof reply: {e}"))
    })
}

/// The cached path for `hash`, or `None` on a cold cache or a leaf_index
/// mismatch (the stale-leaf guard). Miss fallback: [`fill_path_cache`].
pub(crate) fn hit(hash: &str, current_leaf_index: u64) -> Option<(Vec<String>, Vec<u8>)> {
    let guard = lock(&PATHS);
    let entry = guard.as_ref()?.get(hash)?;
    (entry.leaf_index == current_leaf_index)
        .then(|| (entry.path_elements_hex.clone(), entry.path_indices.clone()))
}

/// Fetch `hash`'s Merkle path from `registry` at `leaf_index` and cache it.
/// Shared by the poller's background refresh and `generate_proof`'s
/// on-demand miss fallback.
pub(crate) fn fill_path_cache(
    registry: &CanonicalRegistryId,
    hash: &str,
    leaf_index: u64,
    prov: &dyn RegistryProvider,
) -> Result<(), ApiError> {
    let merkle = prov.get_merkle_proof(registry, leaf_index)?;
    let MerkleProofReply { path_elements: mut path_elements_hex, mut path_indices, depth, valid_roots } =
        decode_merkle_proof(merkle)?;

    // The registry's tree is shallower than the circuit, so its path and every
    // root it reports are lifted to the circuit's depth together — see
    // `proof::depth_bridge`. The reply carries the depth it was built at; a
    // registry that already matches the circuit is padded by nothing.
    let depth = depth.unwrap_or(path_elements_hex.len() as u64) as usize;
    crate::proof::depth_bridge::pad_path(&mut path_elements_hex, &mut path_indices, depth);

    // Adopt the snapshot's valid_roots into the root window (see
    // roots::adopt); older providers may omit the field.
    if let Some(roots_hex) = valid_roots {
        let roots: Vec<[u8; 32]> = roots_hex
            .iter()
            .map(|h| crate::proof::depth_bridge::fold_root(h, depth))
            .filter_map(|h| crate::registry_id::hex_to_bytes32(&h))
            .collect();
        crate::roots::adopt(&registry.canonical, roots);
    }
    lock(&PATHS).get_or_insert_with(HashMap::new).insert(
        hash.to_string(),
        CachedPath { path_elements_hex, path_indices, leaf_index },
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_path_for_test(
    hash: &str,
    path_elements_hex: Vec<String>,
    path_indices: Vec<u8>,
    leaf_index: u64,
) {
    lock(&PATHS).get_or_insert_with(HashMap::new).insert(
        hash.to_string(),
        CachedPath { path_elements_hex, path_indices, leaf_index },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_merkle_proof_is_a_provider_failure() {
        let ok = decode_merkle_proof(serde_json::json!({
            "path_elements": ["ab"], "path_indices": [1], "depth": 1
        }))
        .expect("a well-formed reply decodes");
        assert_eq!(ok.path_indices, vec![1]);
        assert!(ok.valid_roots.is_none());

        for bad in [
            serde_json::json!({ "path_elements": ["ab"], "path_indices": [256] }),
            serde_json::json!({ "path_elements": ["ab", 7], "path_indices": [1, 0] }),
            serde_json::json!({ "path_elements": ["ab"] }),
        ] {
            let err = decode_merkle_proof(bad).err().expect("refused");
            assert_eq!(err.kind, ErrorKind::ProviderFailure);
        }
    }

    #[test]
    fn cold_hash_misses() {
        assert!(hit("path-cache-test-cold", 0).is_none());
    }

    #[test]
    fn fresh_entry_hits_leaf_mismatch_misses() {
        let hash = "path-cache-test-fresh";
        set_path_for_test(hash, vec!["ab".repeat(32)], vec![1], 5);
        let (elements, indices) = hit(hash, 5).expect("fresh entry served");
        assert_eq!(elements, vec!["ab".repeat(32)]);
        assert_eq!(indices, vec![1]);

        assert!(hit(hash, 6).is_none(), "leaf_index mismatch must miss, never serve a stale path");
    }

    #[test]
    fn refresh_overwrites_the_prior_entry() {
        let hash = "path-cache-test-refresh";
        set_path_for_test(hash, vec!["00".repeat(32)], vec![0], 1);
        set_path_for_test(hash, vec!["11".repeat(32)], vec![1], 2);

        let (elements, indices) = hit(hash, 2).expect("refreshed entry served");
        assert_eq!(elements, vec!["11".repeat(32)]);
        assert_eq!(indices, vec![1]);
        assert!(hit(hash, 1).is_none(), "the old leaf_index's path is gone once the refresh overwrote it");
    }
}
