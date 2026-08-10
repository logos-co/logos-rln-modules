//! Valid-root window: a locally-maintained cache of each tracked registry's
//! acceptable Merkle roots, refreshed on a background thread so
//! `verify_proof` can serve the hot path without ever touching the registry
//! (spec: "SHALL NOT perform registry access on the verification path").
//!
//! A membership is not required to verify — a validator that only checks
//! messages never registers — so the window is maintained per *registry*,
//! independent of the keystore, and warmed from the sibling's
//! `get_valid_roots` provider read (which returns the current root plus the
//! registry's short root history).
//!
//! Cold vs stale: a registry that has never been refreshed reports `None`
//! (the caller returns `NOT_READY` rather than serve from a cold view, per
//! the spec). A window whose last refresh is older than `STALE_AFTER_SECS`
//! is also treated as cold — better to answer `NOT_READY` than to accept a
//! proof against a root the registry may have already rotated out (the
//! refresher runs every `REFRESH_INTERVAL`, so staleness means it stalled).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::registry_id::{hex_to_bytes32, CanonicalRegistryId};
use crate::{lock, provider, ApiError, ErrorKind};

/// How often the background thread pulls each tracked registry's roots. Roots
/// rotate over seconds–minutes and the window carries several historical
/// roots (lez-rln ROOT_HISTORY_SIZE = 4), so a 10s refresh keeps a proof
/// generated against a freshly published root from being falsely rejected.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// A window older than this is treated as cold (NOT_READY): the refresher has
/// stalled, and serving its roots risks accepting an already-rotated root.
const STALE_AFTER_SECS: u64 = 60;

struct Window {
    roots: Vec<[u8; 32]>,
    updated_at: u64,
}

static WINDOWS: Mutex<Option<HashMap<String, Window>>> = Mutex::new(None);
static TRACKED: Mutex<Option<HashMap<String, CanonicalRegistryId>>> = Mutex::new(None);

/// Track a registry's roots and make sure the background refresher is running.
/// Non-blocking and hot-path-safe: it registers interest and returns, never
/// performing a registry read itself. Warming happens on the refresher worker.
/// After `stop()` the ensure is a no-op — interest is still recorded, and the
/// next `start()`'s respawn + warm pass picks the registry up.
pub(crate) fn track(registry: &CanonicalRegistryId) {
    {
        let mut guard = lock(&TRACKED);
        guard
            .get_or_insert_with(HashMap::new)
            .entry(registry.canonical.clone())
            .or_insert_with(|| registry.clone());
    }
    ensure_refresher();
}

/// The fresh valid-root window for a registry, or `None` if it has never been
/// refreshed or has gone stale — the cold view that maps to `NOT_READY`.
pub(crate) fn window(canonical: &str) -> Option<Vec<[u8; 32]>> {
    let guard = lock(&WINDOWS);
    let w = guard.as_ref()?.get(canonical)?;
    if crate::now_unix().saturating_sub(w.updated_at) > STALE_AFTER_SECS {
        return None;
    }
    Some(w.roots.clone())
}

/// Idempotently spawn the background refresher; spawn permission lives in
/// the supervisor, so nothing spawns after `stop()`. Runs off the owner
/// thread, so its provider calls take the async lp path (the poller's model).
pub(crate) fn ensure_refresher() {
    crate::worker::ensure_refresher();
}

/// The refresher worker body, owned by the supervisor: an interruptible tick
/// loop that exits when its run is superseded (`stop()`, or a restart's
/// generation bump); each tick is wrapped so a transient failure never kills
/// the worker.
pub(crate) fn run_loop(my_gen: u64) {
    loop {
        if !crate::worker::wait_tick(my_gen, REFRESH_INTERVAL) {
            return;
        }
        if let Err(payload) = std::panic::catch_unwind(refresh_all) {
            eprintln!("roots refresher: refresh panicked: {payload:?}");
        }
    }
}

/// Refresh every tracked registry once (the refresher tick body). Also
/// reachable synchronously from a non-hot path (e.g. `start`) to warm the
/// cache before the first verify.
pub(crate) fn refresh_all() {
    if crate::worker::is_stopped() {
        return;
    }
    for registry in tracked_snapshot() {
        if let Err(e) = refresh_one(&registry) {
            eprintln!("roots: refresh {} failed: {}", registry.canonical, e.message);
        }
        // Re-checked after every registry read so a worker abandoned by
        // stop() does at most one more read before exiting.
        if crate::worker::is_stopped() {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) fn tracked_contains(canonical: &str) -> bool {
    lock(&TRACKED).as_ref().is_some_and(|m| m.contains_key(canonical))
}

fn tracked_snapshot() -> Vec<CanonicalRegistryId> {
    lock(&TRACKED)
        .as_ref()
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default()
}

fn refresh_one(registry: &CanonicalRegistryId) -> Result<(), ApiError> {
    let prov = provider::provider_for(&registry.namespace).ok_or_else(|| {
        ApiError::new(
            ErrorKind::UnknownRegistry,
            &format!("no registry provider for namespace {}", registry.namespace),
        )
    })?;
    let roots_hex = prov.get_valid_roots(registry)?;
    let roots: Vec<[u8; 32]> = roots_hex.iter().filter_map(|h| hex_to_bytes32(h)).collect();
    lock(&WINDOWS).get_or_insert_with(HashMap::new).insert(
        registry.canonical.clone(),
        Window {
            roots,
            updated_at: crate::now_unix(),
        },
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_window_for_test(canonical: &str, roots: Vec<[u8; 32]>, updated_at: u64) {
    lock(&WINDOWS).get_or_insert_with(HashMap::new).insert(
        canonical.to_string(),
        Window { roots, updated_at },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_registry_has_no_window() {
        assert!(window("logos:local:never-refreshed").is_none());
    }

    #[test]
    fn fresh_window_is_served_stale_window_is_cold() {
        let canonical = "logos:local:roots-test";
        let now = crate::now_unix();
        set_window_for_test(canonical, vec![[1u8; 32], [2u8; 32]], now);
        let served = window(canonical).expect("fresh window served");
        assert_eq!(served, vec![[1u8; 32], [2u8; 32]]);

        // Backdate past the staleness bound → treated as cold (NOT_READY).
        set_window_for_test(canonical, vec![[1u8; 32]], now - STALE_AFTER_SECS - 1);
        assert!(window(canonical).is_none());
    }
}
