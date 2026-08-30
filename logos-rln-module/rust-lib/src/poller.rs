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
//! only plaintext-safe sidecar metadata. All provider calls from this
//! worker take `provider_call`'s async+channel path automatically (owner
//! -thread contract). A transient failure never kills the worker: each tick
//! body runs under `catch_unwind` (pure Rust, no FFI frames — safe to
//! catch); only the supervisor retires it (`stop()`, or a restart's
//! generation bump).

use std::time::Duration;

use crate::lifecycle::{self, MembershipRecord, MembershipState, CONFIRMATION_WINDOW_SECS};
use crate::path_cache;
use crate::provider::provider_for;
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
    worker::ensure_poller();
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
        if let Err(payload) = std::panic::catch_unwind(|| tick(refresh)) {
            eprintln!("membership poller: tick panicked: {payload:?}");
        }
    }
}

/// One registry read for one record; returns the update to apply, or None
/// to leave the record untouched (provider failure).
fn observe(record: &MembershipRecord) -> Option<RecordUpdate> {
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
    let provider = provider_for(&registry.namespace)?;
    match provider.get_membership(&registry, &record.identity.identity_commitment) {
        Ok(pm) if pm.registered => Some(RecordUpdate::Observed {
            state: pm.state,
            leaf_index: pm.leaf_index,
            rate_limit: pm.rate_limit,
        }),
        Ok(_) => Some(RecordUpdate::Absent),
        Err(e) => {
            eprintln!(
                "membership poller: {} read failed: {}",
                record.identity.registry_id, e.message
            );
            None
        }
    }
}

enum RecordUpdate {
    Observed {
        state: MembershipState,
        leaf_index: u64,
        rate_limit: u64,
    },
    Absent,
}

/// Confirm/refresh write shared by both Observed branches: record the
/// registry's authoritative state/leaf_index/rate_limit and clear any
/// failed_reason/retryable.
fn apply_observed(
    hash: &str,
    state: MembershipState,
    leaf_index: u64,
    rate_limit: u64,
) -> Result<MembershipState, crate::ApiError> {
    sealed::current_or_uninit()?.update_cache(hash, |m| {
        m.state = state;
        m.leaf_index = Some(leaf_index);
        m.rate_limit = Some(rate_limit);
        m.failed_reason = None;
        m.retryable = None;
    })
}

/// Fire `membership_state_changed` (module docs: LIDL events section) after
/// a successful, change-gated store write — called with no store lock held.
/// `record` is the pre-transition snapshot the caller already had in hand
/// from `pending_records`/`refreshable_records`;
/// `lifecycle::transition_event` no-ops when `new_state` didn't actually
/// change anything.
fn emit_transition(
    hash: &str,
    record: &MembershipRecord,
    prior: MembershipState,
    new_state: MembershipState,
) {
    if let Some((registry_id, rln_identifier, membership_hash, state, previous)) =
        lifecycle::transition_event(hash, record, prior, new_state)
    {
        crate::emit_membership_state_changed(
            &registry_id,
            &rln_identifier,
            &membership_hash,
            &state,
            &previous,
        );
    }
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
    let now = crate::now_unix();
    for record in pending {
        let hash = &record.hash;
        match observe(&record) {
            Some(RecordUpdate::Observed {
                state,
                leaf_index,
                rate_limit,
            }) => match apply_observed(hash, state, leaf_index, rate_limit) {
                Err(e) => {
                    eprintln!("membership poller: confirm update failed: {}", e.message)
                }
                Ok(prior) => {
                    emit_transition(hash, &record, prior, state);
                    eprintln!("membership poller: {hash} confirmed {state:?} at leaf {leaf_index}")
                }
            },
            Some(RecordUpdate::Absent)
                if now.saturating_sub(record.identity.submitted_at)
                    > CONFIRMATION_WINDOW_SECS =>
            {
                let result = sealed::current_or_uninit().and_then(|s| {
                    s.update_cache(hash, |m| {
                        m.state = MembershipState::Failed;
                        m.failed_reason = Some("confirmation_window_elapsed".to_string());
                        // Re-registration can be attempted (spec: a failed
                        // submission SHALL report whether it is retryable).
                        m.retryable = Some(true);
                    })
                });
                match result {
                    Err(e) => eprintln!("membership poller: fail update failed: {}", e.message),
                    Ok(prior) => {
                        emit_transition(hash, &record, prior, MembershipState::Failed);
                        eprintln!("membership poller: {hash} failed (window elapsed)");
                    }
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
        match observe(&record) {
            Some(RecordUpdate::Observed { state, leaf_index, rate_limit }) => {
                if let Ok(prior) = apply_observed(hash, state, leaf_index, rate_limit) {
                    emit_transition(hash, &record, prior, state);
                }
            }
            Some(RecordUpdate::Absent) => {
                // Was on the registry (state ∈ active/grace/expired), now
                // gone: erased/slashed. Consumers MUST stop using it.
                let updated = sealed::current_or_uninit().and_then(|s| {
                    s.update_cache(hash, |m| {
                        m.state = MembershipState::Erased;
                        m.failed_reason = Some("removed_from_registry".to_string());
                    })
                });
                if let Ok(prior) = updated {
                    emit_transition(hash, &record, prior, MembershipState::Erased);
                }
                eprintln!("membership poller: {hash} vanished from registry — erased");
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
        let Some(provider) = provider_for(&registry.namespace) else { continue };
        if let Err(e) = path_cache::fill_path_cache(
            &registry,
            hash,
            record.cache.leaf_index.unwrap_or(0),
            provider,
        ) {
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
