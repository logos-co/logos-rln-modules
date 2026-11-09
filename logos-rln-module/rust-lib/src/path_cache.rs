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

use crate::error::ApiError;
use crate::registry_id::CanonicalRegistryId;
use crate::tree::TreeSource;
use crate::util::lock;

struct CachedPath {
    path_elements_hex: Vec<String>,
    path_indices: Vec<u8>,
    leaf_index: u64,
}

// OWNERSHIP: filled by the warm worker and generate handlers, read per generate.
static PATHS: Mutex<Option<HashMap<String, CachedPath>>> = Mutex::new(None);

/// The cached path for `hash`, or `None` on a cold cache or a leaf_index
/// mismatch (the stale-leaf guard). Miss fallback: [`fill_path_cache`].
pub(crate) fn hit(hash: &str, current_leaf_index: u64) -> Option<(Vec<String>, Vec<u8>)> {
    let guard = lock(&PATHS);
    let entry = guard.as_ref()?.get(hash)?;
    (entry.leaf_index == current_leaf_index)
        // OWNERSHIP: copied out of the lock: the witness owns (and wipes) its path.
        .then(|| (entry.path_elements_hex.clone(), entry.path_indices.clone()))
}

/// Fetch `hash`'s Merkle path from `registry` at `leaf_index` and cache it.
/// Shared by the poller's background refresh and `generate_proof`'s
/// on-demand miss fallback.
pub(crate) fn fill_path_cache(
    registry: &CanonicalRegistryId,
    hash: &str,
    leaf_index: u64,
    tree: &dyn TreeSource,
) -> Result<(), ApiError> {
    let witness = tree.merkle_proof(registry, leaf_index)?.lifted();
    // A snapshot's roots become the window (see roots::adopt); a lone root
    // joins it (see roots::admit).
    match witness.window {
        Some(window) => crate::roots::adopt(&registry.canonical, window),
        None => crate::roots::admit(&registry.canonical, witness.root),
    }
    let (path_elements_hex, path_indices) = (witness.path_elements_hex, witness.path_indices);
    lock(&PATHS).get_or_insert_with(HashMap::new).insert(
        hash.to_string(), // OWNERSHIP: the map owns its key.
        CachedPath {
            path_elements_hex,
            path_indices,
            leaf_index,
        },
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
        hash.to_string(), // OWNERSHIP: the map owns its key.
        CachedPath {
            path_elements_hex,
            path_indices,
            leaf_index,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // A source without a snapshot window: the proof's root joins the window
    // in front, and the window keeps its size.
    #[test]
    fn a_proof_without_valid_roots_admits_its_root() {
        use crate::provider::fake::FakeTree;
        let _serial = lock(&crate::test_support::TEST_GLOBAL_LOCK);
        let registry = crate::registry_id::parse("fakens:local:admit-path").unwrap();
        let proof = serde_json::json!({
            "depth": 2, "leaf": "aa".repeat(32), "leaf_index": 3,
            "path_elements": ["cc".repeat(32), "dd".repeat(32)], "path_indices": [1, 0],
            "root": "bb".repeat(32),
        });
        let expected = crate::tree::MerkleProof::from_provider_json(&proof)
            .unwrap()
            .lifted()
            .root;
        let tree = FakeTree {
            proof: Some(proof),
            roots: None,
        };
        crate::roots::adopt(&registry.canonical, (1..=5).map(|n| [n; 32]).collect());

        fill_path_cache(&registry, "path-cache-test-admit", 3, &tree).expect("proof cached");

        let window = crate::roots::window(&registry.canonical).expect("window kept");
        assert_eq!(window.len(), 5);
        assert_eq!((window[0], window[1]), (expected, [1; 32]));
        assert!(hit("path-cache-test-admit", 3).is_some());
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

        assert!(
            hit(hash, 6).is_none(),
            "leaf_index mismatch must miss, never serve a stale path"
        );
    }

    #[test]
    fn refresh_overwrites_the_prior_entry() {
        let hash = "path-cache-test-refresh";
        set_path_for_test(hash, vec!["00".repeat(32)], vec![0], 1);
        set_path_for_test(hash, vec!["11".repeat(32)], vec![1], 2);

        let (elements, indices) = hit(hash, 2).expect("refreshed entry served");
        assert_eq!(elements, vec!["11".repeat(32)]);
        assert_eq!(indices, vec![1]);
        assert!(
            hit(hash, 1).is_none(),
            "the old leaf_index's path is gone once the refresh overwrote it"
        );
    }
}
