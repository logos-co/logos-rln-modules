//! Confirmation + lifecycle poller: one supervisor-owned worker (see
//! `worker.rs`) that
//!
//! 1. every tick (15s), re-reads each `pending` membership from its
//!    registry: observed ⇒ pending→active with the AUTHORITATIVE
//!    leaf_index + rate_limit re-read into the store (spec MUST — the
//!    submit-time values are estimates); not observed past the
//!    confirmation window ⇒ pending→failed. A provider failure leaves the
//!    record pending — an unreachable registry proves nothing about the
//!    submission.
//! 2. every 4th tick (60s), refreshes non-terminal states
//!    (active/grace_period/expired transitions come from the registry's
//!    chain clock; a previously-observed record the registry no longer has
//!    ⇒ erased — the involuntary-removal signal consumers must see).
//! 3. on that same 60s cadence, refreshes each USABLE (active/grace_period)
//!    membership's Merkle proof path into `path_cache.rs`, so `generate_proof`
//!    normally serves it with zero registry I/O (spec start(): "maintain …
//!    each membership's Merkle proof path"). A failed refresh is logged and
//!    the previous cache entry is kept — slightly stale but still verifiable
//!    beats nothing.
//!
//! Runs whether or not the keystore is unlocked: everything here touches
//! only plaintext-safe sidecar metadata. Provider calls from this worker go
//! out through `provider.rs`'s async twin + channel wait, like every other
//! caller — the module is concurrency "multi", so a slow registry read holds
//! up nothing else. A failed read is logged and the tick moves on; only the
//! supervisor retires the worker (`stop()`, or a restart's generation bump).
//! A panic aborts the host process (`panic = "abort"`).

use std::time::Duration;

use crate::lifecycle::{self, confirmation_deadline, MembershipRecord, MembershipState};
use crate::path_cache;
use crate::provider::{backend_for, ProviderMembership, Registry};
use crate::registry_id;
use crate::sealed_store::store as sealed;
use crate::worker;

const TICK: Duration = Duration::from_secs(15);
const REFRESH_EVERY: u32 = 4;

/// Idempotent: the first call (register's Pending write, or
/// `on_context_ready` when persisted pending records exist) spawns the
/// worker; later calls are no-ops. Spawn permission lives in the supervisor
/// — nothing spawns after `stop()`.
pub(crate) fn ensure_running() {
    worker::ensure(worker::Slot::Poller, "rln-poller", run_loop);
}

/// The poller worker body, owned by the supervisor: an interruptible tick
/// loop that exits when its run is superseded (`stop()`, or a restart's
/// generation bump).
pub(crate) fn run_loop(my_gen: u64) {
    let mut tick_no: u32 = 0;
    loop {
        if !worker::wait_tick(my_gen, TICK) {
            return;
        }
        tick_no = tick_no.wrapping_add(1);
        let refresh = tick_no.is_multiple_of(REFRESH_EVERY);
        tick(refresh);
    }
}

/// One registry read for one record: `Some(Some(_))` = the registry holds
/// it, `Some(None)` = the registry authoritatively does not, `None` = no
/// answer (provider failure), leave the record untouched.
fn observe(record: &MembershipRecord) -> Option<Option<ProviderMembership>> {
    let registry = match registry_id::parse(&record.identity.registry_id) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "membership poller: bad stored registry_id {}: {e}",
                record.identity.registry_id
            );
            return None;
        }
    };
    observe_with(record, &registry, backend_for(&registry.namespace)?.registry)
}

fn observe_with(
    record: &MembershipRecord,
    registry: &registry_id::CanonicalRegistryId,
    source: &dyn Registry,
) -> Option<Option<ProviderMembership>> {
    match source.get_membership(registry, &record.identity.identity_commitment) {
        Ok(pm) => Some(pm),
        Err(e) => {
            eprintln!(
                "membership poller: {} read failed: {}",
                record.identity.registry_id, e.message
            );
            None
        }
    }
}

/// What a record the registry does not hold becomes: one that was on the
/// registry (state ∈ active/grace/expired, or ever active) is erased or
/// slashed and consumers MUST stop using it; one the cache knows nothing
/// about (`Unknown` after a lost sidecar, never seen active) was never
/// registered as far as anyone can tell, and reads `failed`, retryable, so
/// it is not mistaken for a removal.
pub(crate) fn absent_verdict(record: &MembershipRecord) -> (MembershipState, &'static str) {
    if record.cache.state == MembershipState::Unknown && record.cache.first_active_at.is_none() {
        (MembershipState::Failed, "not_on_registry")
    } else {
        (MembershipState::Erased, "removed_from_registry")
    }
}

/// A cache write that yields to a fresher writer: `f` runs only while the
/// record's state is still `expected`, the state the caller read before its
/// (possibly ~70 s) registry round-trip. `Ok(Some(prior))` = written;
/// `Ok(None)` = another writer moved the record meanwhile, nothing changed.
pub(crate) fn write_if_still(
    hash: &str,
    expected: MembershipState,
    f: impl FnOnce(&mut lifecycle::CacheState),
) -> Result<Option<MembershipState>, crate::error::ApiError> {
    let prior = sealed::current_or_uninit()?.update_cache(hash, |m| {
        if m.state == expected {
            f(m);
        }
    })?;
    Ok((prior == expected).then_some(prior))
}

/// Confirm/refresh write shared by both observed branches: record the
/// registry's authoritative state/leaf_index/rate_limit and clear any
/// failed_reason/retryable — unless the record already moved on.
fn apply_observed(
    hash: &str,
    expected: MembershipState,
    pm: &ProviderMembership,
) -> Result<Option<MembershipState>, crate::error::ApiError> {
    write_if_still(hash, expected, |m| {
        m.state = pm.state;
        if let Some(l) = pm.leaf_index {
            m.leaf_index = Some(l);
        }
        m.rate_limit = Some(pm.rate_limit);
        m.failed_reason = None;
        m.retryable = None;
    })
}

fn tick(refresh_states: bool) {
    if crate::worker::is_stopped() {
        return;
    }
    let pending = match sealed::current() {
        Some(store) => store.pending_records(),
        // Store not initialized (no persistence path) — nothing to poll.
        None => return,
    };
    let now = crate::util::now_unix();
    for record in pending {
        let hash = &record.hash;
        let expected = record.cache.state;
        match observe(&record) {
            Some(Some(pm)) => match apply_observed(hash, expected, &pm) {
                Err(e) => {
                    eprintln!("membership poller: confirm update failed: {}", e.message)
                }
                Ok(Some(prior)) => {
                    lifecycle::emit_transition(hash, &record, prior, pm.state);
                    eprintln!(
                        "membership poller: {hash} confirmed {:?} at leaf {:?}",
                        pm.state, pm.leaf_index
                    )
                }
                Ok(None) => {}
            },
            Some(None) if now > confirmation_deadline(&record) => {
                let result = write_if_still(hash, expected, |m| {
                    m.state = MembershipState::Failed;
                    m.failed_reason = Some("confirmation_window_elapsed".to_string());
                    // Re-registration can be attempted (spec: a failed
                    // submission SHALL report whether it is retryable).
                    m.retryable = Some(true);
                });
                match result {
                    Err(e) => eprintln!("membership poller: fail update failed: {}", e.message),
                    Ok(Some(prior)) => {
                        crate::lifecycle::forget_granted_by(hash);
                        lifecycle::emit_transition(hash, &record, prior, MembershipState::Failed);
                        eprintln!("membership poller: {hash} failed (window elapsed)");
                    }
                    Ok(None) => {}
                }
            }
            _ => {}
        }
    }

    if !refresh_states {
        return;
    }
    let refreshable = match sealed::current() {
        Some(store) => store.refreshable_records(),
        None => return,
    };
    for record in refreshable {
        let hash = &record.hash;
        let expected = record.cache.state;
        match observe(&record) {
            Some(Some(pm)) => {
                if let Ok(Some(prior)) = apply_observed(hash, expected, &pm) {
                    lifecycle::emit_transition(hash, &record, prior, pm.state);
                }
            }
            Some(None) => {
                let (state, reason) = absent_verdict(&record);
                let updated = write_if_still(hash, expected, |m| {
                    m.state = state;
                    m.failed_reason = Some(reason.to_string());
                    if state == MembershipState::Failed {
                        m.retryable = Some(true);
                    }
                });
                if let Ok(Some(prior)) = updated {
                    crate::lifecycle::forget_granted_by(hash);
                    lifecycle::emit_transition(hash, &record, prior, state);
                    eprintln!("membership poller: {hash} not on the registry — {reason}");
                }
            }
            None => {}
        }
    }

    refresh_paths();
}

/// One Merkle-path refresh pass over every USABLE (active/grace_period)
/// membership — the poller's third maintenance job (module docs point 3).
/// Called from the refresh tick and from `start`'s warm-up; does its own
/// stopped check so it is safe to call off the warm thread.
pub(crate) fn refresh_paths() {
    if crate::worker::is_stopped() {
        return;
    }
    let usable = match sealed::current() {
        Some(store) => store.refreshable_records(),
        None => return,
    };
    for record in usable.into_iter().filter(|r| r.cache.state.is_usable()) {
        let hash = &record.hash;
        let registry = match registry_id::parse(&record.identity.registry_id) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "membership poller: bad stored registry_id {}: {e}",
                    record.identity.registry_id
                );
                continue;
            }
        };
        let Some(backend) = backend_for(&registry.namespace) else { continue };
        // Leaf 0 is a VALID leaf, so a usable row without one cannot be
        // defaulted — that would cache the wrong membership's path. The cache
        // is deliberately unauthenticated (see lifecycle.rs), so this pairing
        // is reachable by tampering, never by the module's own writers.
        let Some(leaf_index) = record.cache.leaf_index else {
            eprintln!("membership poller: {hash} is usable but carries no leaf_index — path refresh skipped");
            continue;
        };
        if let Err(e) = path_cache::fill_path_cache(&registry, hash, leaf_index, backend.tree) {
            // Keep the previous cache entry — a slightly-stale but still
            // verifiable path beats none.
            eprintln!("membership poller: {hash} path refresh failed: {}", e.message);
        }
        // Re-checked after every record's read so a worker abandoned by
        // stop() does at most one more read before exiting.
        if crate::worker::is_stopped() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lifecycle::MembershipState;
    use crate::poller;
    use crate::test_support::{imp_with_store, seed_membership, TEST_GLOBAL_LOCK};

    // A pending record the registry holds is confirmed with the registry's
    // leaf; a read that names no leaf keeps the stored one.
    #[test]
    fn a_pending_record_is_confirmed_through_the_registry() {
        use crate::provider::fake::{self, FakePayer, FakeRegistry, FakeTree};
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-poller-confirm-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = "fakens:local:confirm";
        seed_membership(&store, "conf", registry, &"56".repeat(32), "", &"e6".repeat(32), MembershipState::Pending, 0, 100);
        store.update_cache("conf", |m| m.leaf_index = None).unwrap();

        let install = |leaf: Option<u64>| {
            crate::test_support::install_backend(fake::backend(
                FakeTree::default(),
                FakeRegistry { membership: Some(Some((MembershipState::Active, leaf, 100))), bounds: None },
                FakePayer::default(),
            ))
        };
        install(Some(4));
        poller::tick(false);
        let rec = store.membership("conf").unwrap();
        assert_eq!((rec.cache.state, rec.cache.leaf_index), (MembershipState::Active, Some(4)));

        install(None);
        store.update_cache("conf", |m| m.state = MembershipState::Pending).unwrap();
        poller::tick(false);
        let rec = store.membership("conf").unwrap();
        assert_eq!((rec.cache.state, rec.cache.leaf_index), (MembershipState::Active, Some(4)));

        crate::sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A record the registry does not hold: one that was active is erased;
    // one the cache never saw active (a lost sidecar) is failed, retryable.
    #[test]
    fn an_absent_record_is_erased_only_if_it_was_ever_on_the_registry() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-absent-verdict-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "7c".repeat(32));
        seed_membership(&store, "was", &registry, &"54".repeat(32), "", &"e4".repeat(32), MembershipState::Active, 1, 100);
        seed_membership(&store, "never", &registry, &"55".repeat(32), "", &"e5".repeat(32), MembershipState::Unknown, 0, 100);
        assert_eq!(poller::absent_verdict(&store.membership("was").unwrap()), (MembershipState::Erased, "removed_from_registry"));
        assert_eq!(poller::absent_verdict(&store.membership("never").unwrap()), (MembershipState::Failed, "not_on_registry"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
