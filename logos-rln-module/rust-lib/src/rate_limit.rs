//! Rate-limit tracking: epoch derivation and per-application `message_id`
//! allocation — the security-critical state the spec's rate-limiting portion
//! rests on.
//!
//! Two proofs that reuse an `(epoch, message_id)` pair under one external
//! nullifier expose Shamir shares that reconstruct the identity secret (which,
//! on a slashing registry, burns the credential). So the allocator MUST never
//! hand out the same slot twice — including across a process restart, a
//! backwards wall-clock step, or a `max_epoch_gap` reconfiguration. This
//! module owns the pure allocation algorithm; the store durably persists the
//! result **before** the proof is returned (see `store::reserve_message_id`),
//! so a crash after issuing a proof but before persisting can only ever
//! *waste* a slot, never reuse one.
//!
//! Granularity: the external nullifier is `poseidon(epoch, rln_identifier)`,
//! so the same `message_id` is safe to reuse across different applications
//! (distinct `rln_identifier`s) but never within one. Allocation is therefore
//! keyed by `(rln_identifier, epoch)`. The epoch derives from the caller's
//! message timestamp and `generate_proof` accepts anything within
//! `now ± max_epoch_gap`, so several epochs are live at once and each keeps its
//! own counter; rows below the window floor are pruned to bound growth. Pruning
//! destroys the only record that a pruned epoch's slots were spent, so every
//! prune is recorded in a persisted, monotonically non-decreasing floor
//! (`MembershipMeta::prune_floor`, capped at one past the highest allocated
//! epoch so a spiked clock cannot brick the future): once an epoch falls below
//! it, reservation there is refused forever (`AllocError::EpochBelowFloor`) —
//! even when the wall clock rewinds past the window or a widened
//! `max_epoch_gap` would re-admit it. The index's wire encoding (the spec's `epoch[32]`) lives in
//! the proof engine (`proof::epoch_to_bytes`); this module deals only in the
//! `u64`.

use serde::{Deserialize, Serialize};

/// One application's slot usage within one epoch, persisted in the membership
/// sidecar (plaintext-safe — counters, no secret). `used` is both the count
/// issued and the next unused `message_id`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct EpochAllocation {
    /// The application scope, lowercase hex of the 32-byte `rln_identifier`.
    pub(crate) rln_identifier: String,
    /// The epoch index these slots were issued in.
    pub(crate) epoch: u64,
    /// Next unused `message_id` (== slots already issued this epoch).
    pub(crate) used: u64,
}

/// Outcome of a reservation attempt that did not yield a slot.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AllocError {
    /// The epoch's `rate_limit` slots are all spent; retry next epoch.
    BudgetExhausted,
    /// The requested epoch is below the persisted monotone floor — its row
    /// was (or may have been) pruned, so reissuing could double-spend a slot
    /// and leak the identity secret. Permanent for this epoch: a backwards
    /// clock step or a widened `max_epoch_gap` re-admitted it, and the
    /// allocator must answer an error rather than silently mint a colliding
    /// proof.
    EpochBelowFloor,
}

/// The current epoch index: `floor(now_unix / epoch_size_sec)` — the ONE
/// place the division (and its zero-size guard) lives.
///
/// Wall-clock based. Verifiers MUST share the same `epoch_size` and time base
/// — per the spec's Appendix A the `logos` time base is the on-chain clock;
/// which time source feeds this is a `start()` configuration item.
pub(crate) fn current_epoch(now_unix: u64, epoch_size_sec: u64) -> u64 {
    now_unix / epoch_size_sec.max(1)
}

/// Reserve the next `message_id` for `(rln_identifier, epoch)` within
/// `rate_limit`, mutating `allocations` and `floor` in place ONLY on success.
/// Returns the slot, `BudgetExhausted` when that epoch's budget is spent, or
/// `EpochBelowFloor` when `epoch` is below the effective floor.
///
/// `retain_floor_candidate` is the oldest epoch the CURRENT window claims to
/// serve (`now_epoch - max_epoch_gap`) — a wall-clock-derived value that can
/// move backwards (NTP step, suspend/resume, VM restore), drop when
/// `max_epoch_gap` is reconfigured wider, or SPIKE forward on a bad clock.
/// `floor` is the persisted monotone floor: everything strictly below it may
/// have had its row pruned, so a reservation there is refused forever —
/// reissuing a pruned epoch's slot would expose the Shamir shares that
/// reconstruct the identity secret.
///
/// The prune threshold each call may advance to is
/// `max(*floor, min(candidate, highest allocated epoch + 1))`:
/// - `max(*floor, ..)` keeps the floor monotone against a rewound candidate;
/// - capping the candidate at one past the highest allocated row means a
///   forward clock spike can never persist a far-future floor that bricks
///   the membership once the clock is corrected — only epochs whose rows
///   actually existed (and are now pruned) become unservable, which is
///   exactly the set at risk of reissue;
/// - with no rows there is nothing to prune and the floor stays put.
///
/// Every error path leaves `allocations` and `floor` EXACTLY as found: the
/// store restamps the sidecar MAC only on success, so an error must not
/// diverge the in-memory state from its persisted MAC. Pruning likewise never
/// drops an in-window epoch: interleaving timestamps can revisit a
/// neighboring epoch, which must continue its counter.
///
/// The caller MUST durably persist `allocations` AND `floor` before using the
/// returned slot.
pub(crate) fn reserve_slot(
    allocations: &mut Vec<EpochAllocation>,
    floor: &mut u64,
    rln_identifier_hex: &str,
    epoch: u64,
    retain_floor_candidate: u64,
    rate_limit: u64,
) -> Result<u64, AllocError> {
    let highest = allocations.iter().map(|a| a.epoch.saturating_add(1)).max();
    let threshold = match highest {
        Some(h) => (*floor).max(retain_floor_candidate.min(h)),
        None => *floor,
    };
    if epoch < threshold {
        return Err(AllocError::EpochBelowFloor);
    }

    // Allocate first — rows for several in-window epochs coexist, so the slot
    // is looked up by `(rln_identifier, epoch)`, never by application alone —
    // and only then advance the floor and prune, so both error returns above
    // and below mutate nothing.
    let slot = if let Some(row) = allocations
        .iter_mut()
        .find(|a| a.rln_identifier == rln_identifier_hex && a.epoch == epoch)
    {
        if row.used >= rate_limit {
            return Err(AllocError::BudgetExhausted);
        }
        let slot = row.used;
        row.used += 1;
        slot
    } else {
        if rate_limit == 0 {
            return Err(AllocError::BudgetExhausted);
        }
        allocations.push(EpochAllocation {
            rln_identifier: rln_identifier_hex.to_string(),
            epoch,
            used: 1,
        });
        0
    };
    *floor = threshold;
    allocations.retain(|a| a.epoch >= threshold);
    Ok(slot)
}

/// Remaining slots for `(rln_identifier, epoch)` under `rate_limit` — the
/// quota read's current-epoch budget.
pub(crate) fn remaining(
    allocations: &[EpochAllocation],
    rln_identifier_hex: &str,
    epoch: u64,
    rate_limit: u64,
) -> u64 {
    let used = allocations
        .iter()
        .find(|a| a.rln_identifier == rln_identifier_hex && a.epoch == epoch)
        .map(|a| a.used)
        .unwrap_or(0);
    rate_limit.saturating_sub(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_A: &str = "aa";
    const APP_B: &str = "bb";

    #[test]
    fn epoch_is_floor_division() {
        assert_eq!(current_epoch(0, 600), 0);
        assert_eq!(current_epoch(599, 600), 0);
        assert_eq!(current_epoch(600, 600), 1);
        assert_eq!(current_epoch(1_250, 600), 2);
        // A zero size never divides by zero.
        assert_eq!(current_epoch(5, 0), 5);
    }

    #[test]
    fn slots_increment_from_zero_then_exhaust() {
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 3), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 3), Ok(1));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 3), Ok(2));
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 3),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!(remaining(&allocs, APP_A, 1, 3), 0);
    }

    #[test]
    fn below_floor_epochs_are_pruned_but_in_window_ones_survive() {
        let mut allocs = Vec::new();
        let mut floor = 0;
        // Window floor 4: epochs 4 and 5 are both live and keep independent
        // budgets — reserving 4 does NOT evict epoch 5's row.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 5, 4, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 4, 4, 2), Ok(0));
        assert_eq!(allocs.len(), 2);
        // Revisiting epoch 5 continues its counter — slot 1, never a reissued 0.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 5, 4, 2), Ok(1));
        assert_eq!(remaining(&allocs, APP_A, 5, 2), 0);
        assert_eq!(remaining(&allocs, APP_A, 4, 2), 1);
        // Advancing the floor past 4 finally prunes it.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 6, 5, 2), Ok(0));
        assert!(allocs.iter().all(|a| a.epoch >= 5));
        assert_eq!(floor, 5);
    }

    #[test]
    fn interleaved_in_window_epochs_never_reissue_a_slot() {
        // now_epoch 10, max_epoch_gap 1 -> floor 9. A caller stamps timestamps
        // that map to epochs 10, 9, then 10 again. If reserving epoch 9 evicted
        // epoch 10's row, the second epoch-10 proof would reuse spent slot 0 —
        // the (epoch, message_id) collision that leaks the identity secret.
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 9, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 5), Ok(1));
        assert_eq!(remaining(&allocs, APP_A, 10, 5), 3);
        assert_eq!(remaining(&allocs, APP_A, 9, 5), 4);
    }

    #[test]
    fn applications_are_independent_within_an_epoch() {
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_B, 1, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 2), Ok(1));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_B, 1, 1, 2), Ok(1));
        assert_eq!(allocs.len(), 2);
        assert_eq!(remaining(&allocs, APP_A, 1, 2), 0);
        assert_eq!(remaining(&allocs, APP_B, 1, 2), 0);
    }

    #[test]
    fn zero_rate_limit_never_allocates() {
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 1, 1, 0),
            Err(AllocError::BudgetExhausted)
        );
    }

    #[test]
    fn rewound_clock_never_reissues_a_pruned_epoch() {
        // Audit cause B: epoch 10 is spent; the window then advances
        // (candidate 11), pruning 10's row and recording floor 11. A later
        // backwards clock step re-admits epoch 10 at the window check — the
        // persisted floor must answer an error, never a reissued slot 0.
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 11, 5), Ok(0));
        assert_eq!(floor, 11, "pruning epoch 10 must be recorded in the floor");
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 5),
            Err(AllocError::EpochBelowFloor)
        );
        assert_eq!(floor, 11, "a rewound candidate must never lower the floor");
        // An epoch at/above the floor still continues its own counter.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 9, 5), Ok(1));
    }

    #[test]
    fn forward_clock_spike_cannot_brick_future_epochs() {
        // A spiked clock supplies an enormous candidate floor (and possibly a
        // spiked reservation). The threshold is capped one past the highest
        // allocated epoch, so after the clock is corrected only epochs whose
        // rows actually existed are refused — not months of future epochs.
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 5), Ok(0));
        // Spike: the candidate leaps far ahead; the floor advances only past
        // the allocated row (10 -> pruned, floor 11), never to the spike.
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 1_000_000, 999_999, 5),
            Ok(0)
        );
        assert_eq!(floor, 11, "the spike must not persist a far-future floor");
        // Clock corrected: normal epochs keep allocating.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 11, 5), Ok(0));
        // The genuinely pruned epoch stays refused.
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 10, 11, 5),
            Err(AllocError::EpochBelowFloor)
        );
    }

    #[test]
    fn failed_reservations_mutate_nothing() {
        // The store restamps the sidecar MAC only on success, so every error
        // path must leave allocations and the floor exactly as persisted —
        // otherwise a later unrelated persist writes state under a stale MAC
        // and the next unlock falsely quarantines an honest entry.
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 10, 9, 1), Ok(0));
        let before = (allocs.clone(), floor);
        // Budget exhausted, with a candidate that would otherwise advance the
        // floor and prune.
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 10, 10, 1),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!((allocs.clone(), floor), before);
        // Zero-limit no-row path: same guarantee.
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 11, 10, 0),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!((allocs.clone(), floor), before);
        // Below-floor path: same guarantee.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 11, 1), Ok(0));
        let after_prune = (allocs.clone(), floor);
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 10, 11, 1),
            Err(AllocError::EpochBelowFloor)
        );
        assert_eq!((allocs.clone(), floor), after_prune);
    }

    #[test]
    fn widened_epoch_gap_never_resurrects_pruned_epochs() {
        // Audit cause D: a gap=1 run reaches epoch 12 (candidate floor 11,
        // capped at highest-row+1 = 10), pruning spent epoch 9 and recording
        // floor 10. A restart (or live start()) with gap=10 lowers the
        // candidate to 2 — epoch 9 passes the wall-clock window check but its
        // spent row is gone. The persisted floor must refuse it.
        let mut allocs = Vec::new();
        let mut floor = 0;
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 9, 8, 5), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 11, 5), Ok(0));
        assert!(allocs.iter().all(|a| a.epoch >= 10), "epoch 9's row is pruned");
        assert_eq!(floor, 10);
        assert_eq!(
            reserve_slot(&mut allocs, &mut floor, APP_A, 9, 2, 5),
            Err(AllocError::EpochBelowFloor)
        );
        // Epochs at/above the floor keep allocating normally under the wider gap.
        assert_eq!(reserve_slot(&mut allocs, &mut floor, APP_A, 12, 2, 5), Ok(1));
    }

    #[test]
    fn remaining_before_any_allocation_is_full() {
        let allocs = Vec::new();
        assert_eq!(remaining(&allocs, APP_A, 1, 100), 100);
    }
}
