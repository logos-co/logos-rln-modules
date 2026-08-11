//! Per-membership Merkle proof-path cache: background-maintained (fed by
//! `poller.rs`'s refresh pass and `start`'s warm-up) so `generate_proof`
//! normally serves its witness path with ZERO registry I/O — the third of
//! `start()`'s spec-mandated maintenance tasks, alongside the valid-root
//! window (`roots.rs`) and membership state (`poller.rs`): "starts the tasks
//! that maintain the Module's local registry view: the valid-root window,
//! each membership's Merkle proof path, and each membership's state."
//!
//! Keyed by `membership_hash`, storing the DECODED, already-validated path
//! (not raw provider JSON) — the same shape [`json_str_array`]/
//! [`json_u8_array`](crate) decode for `generate_proof`'s own witness, via
//! the shared [`fill_path_cache`] fetch both the poller and the on-demand
//! miss fallback call.
//!
//! A membership's `leaf_index` is provisional until the pending→active
//! re-read (spec MUST), so every entry also records the leaf_index it was
//! fetched against; [`hit`] only serves an entry whose leaf_index still
//! equals the caller's CURRENT one. A stale path — fetched against a leaf the
//! membership no longer occupies — would silently burn a persisted
//! `message_id` slot on an unverifiable proof, so the cache must never be
//! trusted across a leaf change: the poller's next refresh overwrites the
//! entry once the authoritative leaf is known, and until then a mismatch
//! just falls back to an on-demand fetch. Nothing needs to explicitly
//! invalidate.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::provider::RegistryProvider;
use crate::registry_id::CanonicalRegistryId;
use crate::{json_str_array, json_u8_array, lock, ApiError};

struct CachedPath {
    path_elements_hex: Vec<String>,
    path_indices: Vec<u8>,
    leaf_index: u64,
}

static PATHS: Mutex<Option<HashMap<String, CachedPath>>> = Mutex::new(None);

/// The cached path for `hash`, or `None` on a cold cache or an entry fetched
/// against a leaf_index other than `current_leaf_index` — the stale-leaf
/// guard described in the module docs. Callers on a miss fall back to
/// [`fill_path_cache`].
pub(crate) fn hit(hash: &str, current_leaf_index: u64) -> Option<(Vec<String>, Vec<u8>)> {
    let guard = lock(&PATHS);
    let entry = guard.as_ref()?.get(hash)?;
    (entry.leaf_index == current_leaf_index)
        .then(|| (entry.path_elements_hex.clone(), entry.path_indices.clone()))
}

/// Fetch `hash`'s Merkle path from `registry` at `leaf_index` and cache it —
/// the ONE fetch+decode shared by the poller's background refresh (every
/// USABLE membership, each refresh tick) and `generate_proof`'s on-demand
/// miss fallback, so both populate the identical validated representation
/// [`hit`] serves.
pub(crate) fn fill_path_cache(
    registry: &CanonicalRegistryId,
    hash: &str,
    leaf_index: u64,
    prov: &dyn RegistryProvider,
) -> Result<(), ApiError> {
    let merkle = prov.get_merkle_proof(registry, leaf_index)?;
    let path_elements_hex = json_str_array(&merkle, "path_elements")?;
    let path_indices = json_u8_array(&merkle, "path_indices")?;
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

        // The membership's authoritative leaf changed underneath (a
        // pending→active re-read) — the cache must not serve a path fetched
        // against the OLD leaf.
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
