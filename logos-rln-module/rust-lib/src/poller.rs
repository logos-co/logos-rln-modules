//! Confirmation + lifecycle poller: one supervisor-owned worker (see
//! `worker.rs`; no SDK timer exists) that
//!
//! 1. every tick (15s), re-reads each `pending` membership from its
//!    registry: observed ⇒ pending→active with the AUTHORITATIVE
//!    leaf_index + rate_limit re-read into the store (spec MUST — the
//!    submit-time values are estimates); not observed past the
//!    confirmation window ⇒ pending→failed. A provider failure leaves the
//!    record pending — an unreachable registry proves nothing about the
//!    submission, and idempotent re-registration keeps the failure path
//!    safe either way.
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

use crate::path_cache;
use crate::provider::provider_for;
use crate::registry_id;
use crate::store::{self, MembershipMeta, MembershipState, CONFIRMATION_WINDOW_SECS};
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
fn observe(meta: &MembershipMeta) -> Option<RecordUpdate> {
    let registry = match registry_id::parse(&meta.registry_id) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("membership poller: bad stored registry_id {}: {e}", meta.registry_id);
            return None;
        }
    };
    let provider = provider_for(&registry.namespace)?;
    match provider.get_membership(&registry, &meta.identity_commitment) {
        Ok(pm) if pm.registered => Some(RecordUpdate::Observed {
            state: pm.state,
            leaf_index: pm.leaf_index,
            rate_limit: pm.rate_limit,
        }),
        Ok(_) => Some(RecordUpdate::Absent),
        Err(e) => {
            eprintln!(
                "membership poller: {} read failed: {}",
                meta.registry_id, e.message
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
/// failed_reason/retryable. On the refresh path both are already None
/// (records there are active/grace/expired), so clearing them is
/// behavior-neutral.
fn apply_observed(
    hash: &str,
    state: MembershipState,
    leaf_index: u64,
    rate_limit: u64,
) -> Result<(), crate::ApiError> {
    store::with_store(|s| {
        s.update(hash, |m| {
            m.state = state;
            m.leaf_index = leaf_index;
            m.rate_limit = rate_limit;
            m.failed_reason = None;
            m.retryable = None;
        })
    })
}

/// Fire `membership_state_changed` (module docs: LIDL events section) after
/// a successful, change-gated store write — called OUTSIDE any
/// `store::with_store` closure, holding no locks. `meta` is the
/// pre-transition snapshot the caller already had in hand from
/// `pending_records`/`refreshable_records`; `store::transition_event`
/// no-ops when `new_state` didn't actually change anything.
fn emit_transition(hash: &str, meta: &MembershipMeta, new_state: MembershipState) {
    if let Some((registry_id, rln_identifier, membership_hash, state, previous)) =
        store::transition_event(hash, meta, new_state)
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
    let pending = match store::with_store(|s| Ok(s.pending_records())) {
        Ok(records) => records,
        // Store not initialized (no persistence path) — nothing to poll.
        Err(_) => return,
    };
    let now = crate::now_unix();
    for (hash, meta) in pending {
        match observe(&meta) {
            Some(RecordUpdate::Observed {
                state,
                leaf_index,
                rate_limit,
            }) => match apply_observed(&hash, state, leaf_index, rate_limit) {
                Err(e) => {
                    eprintln!("membership poller: confirm update failed: {}", e.message)
                }
                Ok(()) => {
                    emit_transition(&hash, &meta, state);
                    eprintln!("membership poller: {hash} confirmed {state:?} at leaf {leaf_index}")
                }
            },
            Some(RecordUpdate::Absent)
                if now.saturating_sub(meta.submitted_at) > CONFIRMATION_WINDOW_SECS =>
            {
                let result = store::with_store(|s| {
                    s.update(&hash, |m| {
                        m.state = MembershipState::Failed;
                        m.failed_reason = Some("confirmation_window_elapsed".to_string());
                        // Re-registration can be attempted (spec: a failed
                        // submission SHALL report whether it is retryable).
                        m.retryable = Some(true);
                    })
                });
                if let Err(e) = result {
                    eprintln!("membership poller: fail update failed: {}", e.message);
                } else {
                    emit_transition(&hash, &meta, MembershipState::Failed);
                    eprintln!("membership poller: {hash} failed (window elapsed)");
                }
            }
            _ => {}
        }
    }

    if !refresh_states {
        return;
    }
    let refreshable = match store::with_store(|s| Ok(s.refreshable_records())) {
        Ok(records) => records,
        Err(_) => return,
    };
    for (hash, meta) in refreshable {
        match observe(&meta) {
            Some(RecordUpdate::Observed { state, leaf_index, rate_limit }) => {
                if apply_observed(&hash, state, leaf_index, rate_limit).is_ok() {
                    emit_transition(&hash, &meta, state);
                }
            }
            Some(RecordUpdate::Absent) => {
                // Was on the registry (state ∈ active/grace/expired), now
                // gone: erased/slashed. Consumers MUST stop using it.
                let updated = store::with_store(|s| {
                    s.update(&hash, |m| {
                        m.state = MembershipState::Erased;
                        m.failed_reason = Some("removed_from_registry".to_string());
                    })
                })
                .is_ok();
                if updated {
                    emit_transition(&hash, &meta, MembershipState::Erased);
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
/// Shared by the refresh tick and `start`'s warm-up, so both feed
/// `path_cache.rs` through the identical fetch+decode
/// (`path_cache::fill_path_cache`). Self-contained stopped check (mirrors
/// `roots::refresh_all`) so it is safe to call directly off the warm thread,
/// not just from `tick`.
pub(crate) fn refresh_paths() {
    if crate::worker::is_stopped() {
        return;
    }
    let usable = match store::with_store(|s| Ok(s.refreshable_records())) {
        Ok(records) => records,
        Err(_) => return,
    };
    for (hash, meta) in usable.into_iter().filter(|(_, m)| m.state.is_usable()) {
        let registry = match registry_id::parse(&meta.registry_id) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("membership poller: bad stored registry_id {}: {e}", meta.registry_id);
                continue;
            }
        };
        let Some(provider) = provider_for(&registry.namespace) else { continue };
        if let Err(e) = path_cache::fill_path_cache(&registry, &hash, meta.leaf_index, provider) {
            // Keep the previous cache entry — a slightly-stale but still
            // verifiable path beats none, the same trade-off the root window
            // makes (module docs point 3).
            eprintln!("membership poller: {hash} path refresh failed: {}", e.message);
        }
        // Re-checked after every record's read so a worker abandoned by
        // stop() does at most one more read before exiting.
        if crate::worker::is_stopped() {
            return;
        }
    }
}
