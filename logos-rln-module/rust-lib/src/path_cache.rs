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
use crate::{lock, ApiError, ErrorKind};

struct CachedPath {
    path_elements_hex: Vec<String>,
    path_indices: Vec<u8>,
    leaf_index: u64,
}

static PATHS: Mutex<Option<HashMap<String, CachedPath>>> = Mutex::new(None);


/// Decode one field of a provider `get_merkle_proof` reply, so a cache hit
/// and a cache miss build identically-shaped witnesses.
fn json_str_array(v: &serde_json::Value, key: &str) -> Result<Vec<String>, ApiError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
        .ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("merkle proof missing {key}"))
        })
}

fn json_u8_array(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, ApiError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_u64().map(|n| n as u8)).collect())
        .ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("merkle proof missing {key}"))
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
/// on-demand miss fallback. `expected_leaf` is the membership's own leaf
/// (`proof::rate_commitment`): the index is the claim the registry module
/// recorded when it sent the registration, and a path to any other leaf would
/// prove against another membership after burning a message-id slot.
pub(crate) fn fill_path_cache(
    registry: &CanonicalRegistryId,
    hash: &str,
    leaf_index: u64,
    expected_leaf: &[u8; 32],
    prov: &dyn RegistryProvider,
) -> Result<(), ApiError> {
    let merkle = prov.get_merkle_proof(registry, leaf_index)?;
    let leaf = merkle
        .get("leaf")
        .and_then(serde_json::Value::as_str)
        .and_then(crate::registry_id::hex_to_bytes32);
    if leaf.as_ref() != Some(expected_leaf) {
        return Err(ApiError::new(
            ErrorKind::ProviderFailure,
            &format!(
                "leaf {leaf_index} of {} is not this membership's leaf — the recorded index is wrong",
                registry.canonical
            ),
        ));
    }
    let mut path_elements_hex = json_str_array(&merkle, "path_elements")?;
    let mut path_indices = json_u8_array(&merkle, "path_indices")?;

    // The registry's tree is shallower than the circuit, so its path and every
    // root it reports are lifted to the circuit's depth together — see
    // `proof::depth_bridge`. The reply carries the depth it was built at; a
    // registry that already matches the circuit is padded by nothing.
    let depth = merkle
        .get("depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(path_elements_hex.len() as u64) as usize;
    crate::proof::depth_bridge::pad_path(&mut path_elements_hex, &mut path_indices, depth);

    // Adopt the snapshot's valid_roots into the root window (see
    // roots::adopt); a zone proof carries only the root it hashes to, which
    // is admitted beside the window instead (roots::admit).
    if let Ok(roots_hex) = json_str_array(&merkle, "valid_roots") {
        let roots: Vec<[u8; 32]> = roots_hex
            .iter()
            .map(|h| crate::proof::depth_bridge::fold_root(h, depth))
            .filter_map(|h| crate::registry_id::hex_to_bytes32(&h))
            .collect();
        crate::roots::adopt(&registry.canonical, roots);
    } else if let Some(root) = merkle
        .get("root")
        .and_then(serde_json::Value::as_str)
        .and_then(|h| crate::registry_id::hex_to_bytes32(&crate::proof::depth_bridge::fold_root(h, depth)))
    {
        crate::roots::admit(&registry.canonical, root);
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

    /// A provider whose proofs come from an in-memory zone tree.
    struct ZoneProvider(crate::zone::fake::FakeZone);

    impl RegistryProvider for ZoneProvider {
        fn get_merkle_proof(&self, _: &CanonicalRegistryId, leaf_index: u64) -> Result<serde_json::Value, ApiError> {
            crate::zone::proof_reply_for_test(&|q| self.0.respond(q), leaf_index)
        }
        fn get_membership(&self, _: &CanonicalRegistryId, _: &str) -> Result<crate::provider::ProviderMembership, ApiError> {
            unimplemented!()
        }
        fn register_async(&self, _: &CanonicalRegistryId, _: &str, _: &str, _: u64, _: crate::provider::RegisterCallback) -> Result<(), ApiError> {
            unimplemented!()
        }
        fn get_valid_roots(&self, _: &CanonicalRegistryId) -> Result<Vec<String>, ApiError> {
            unimplemented!()
        }
        fn get_registry_bounds(&self, _: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
            unimplemented!()
        }
        fn wallet_status(&self) -> Result<serde_json::Value, ApiError> {
            unimplemented!()
        }
        fn payer_balance(&self) -> Result<u128, ApiError> {
            unimplemented!()
        }
        fn fee_state(&self) -> Result<serde_json::Value, ApiError> {
            unimplemented!()
        }
        fn check_registry(&self, _: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
            unimplemented!()
        }
    }

    fn leaf(n: u8) -> [u8; 32] {
        crate::proof::rate_commitment(&format!("{n:02x}{}", "00".repeat(31)), 100).expect("leaf")
    }

    /// The recorded index is the registry module's claim; a path to someone
    /// else's leaf is refused before it is cached, and the right one is cached
    /// with its root admitted into the window.
    #[test]
    fn only_the_memberships_own_leaf_is_cached() {
        let registry =
            crate::registry_id::parse(&format!("logos:path-cache-test:{}", "ee".repeat(32))).unwrap();
        let zone = crate::zone::fake::FakeZone::new((1..=4).map(leaf).collect());
        let root = zone.root();
        let prov = ZoneProvider(zone);
        let hash = "path-cache-test-own-leaf";
        let err = fill_path_cache(&registry, hash, 1, &leaf(1), &prov).unwrap_err();
        assert!(err.message.contains("not this membership's leaf"), "{}", err.message);
        assert!(hit(hash, 1).is_none(), "a wrong leaf's path is never cached");
        fill_path_cache(&registry, hash, 0, &leaf(1), &prov).unwrap();
        assert!(hit(hash, 0).is_some());
        assert_eq!(crate::roots::window(&registry.canonical), Some(vec![root]), "the proof's root, at the circuit's depth");
    }
}
