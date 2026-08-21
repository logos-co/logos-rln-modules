//! Rate-limit tracking: epoch derivation and per-application `message_id`
//! allocation.
//!
//! Two proofs reusing an `(epoch, message_id)` pair under one external
//! nullifier expose Shamir shares that reconstruct the identity secret, so a
//! slot is NEVER reissued — across a restart, a backwards clock step, or a
//! `max_epoch_gap` reconfiguration. The store persists a reservation durably
//! BEFORE the proof is returned, so a crash can only waste a slot, never
//! reuse one. The external nullifier is `poseidon(epoch, rln_identifier)`,
//! so allocation is keyed by `(rln_identifier, epoch)`; several epochs are
//! live at once (`now ± max_epoch_gap`), and rows below the window floor are
//! pruned to bound growth. A pruned row was the only record its slots were
//! spent, so every prune is recorded in a persisted, monotone floor — capped
//! at one past the highest allocated epoch at or below the retain candidate,
//! so a spiked clock cannot brick the future — below which reservation is
//! refused forever, even when the wall clock rewinds or a widened gap would
//! re-admit the epoch.

use serde::{Deserialize, Serialize};

/// One application's slot usage within one epoch. Plaintext-safe: counters,
/// no secret.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct EpochAllocation {
    /// Lowercase hex of the 32-byte `rln_identifier`.
    pub(crate) rln_identifier: String,
    pub(crate) epoch: u64,
    /// Next unused `message_id` (== slots already issued this epoch).
    pub(crate) used: u64,
}

/// The MAC-covered reservation-critical state; this struct IS the covered
/// set — a field added here is authenticated, a field added elsewhere is
/// not. Local security state with NO authoritative source to re-read,
/// tamper-bound by the allocations ledger's section MAC.
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct AllocationState {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allocations: Vec<EpochAllocation>,
    /// Epoch length (seconds) the counters and floor are denominated in.
    /// 0 = unset; adopted at the first successful reservation. A DIFFERENT
    /// configured size fails `permanent`: it rebases the epoch numbering
    /// that keys spent slots, which no floor conversion can make safe.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) epoch_size_sec: u64,
    /// Monotone NON-DECREASING floor: epochs below it may have had rows
    /// pruned, so reservation there is permanently refused — even after a
    /// clock rewind or a widened `max_epoch_gap`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) prune_floor: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AllocError {
    BudgetExhausted,
    /// Below the persisted floor — the row may have been pruned, so
    /// reissuing could double-spend a slot. Permanent for this epoch.
    EpochBelowFloor,
}

/// `floor(now_unix / epoch_size_sec)` — the ONE place the division (and its
/// zero-size guard) lives. Verifiers must share the same `epoch_size` and
/// time base.
pub(crate) fn current_epoch(now_unix: u64, epoch_size_sec: u64) -> u64 {
    now_unix / epoch_size_sec.max(1)
}

/// Reserve the next `message_id` for `(rln_identifier, epoch)` within
/// `rate_limit`, mutating `alloc` ONLY on success — every error path leaves
/// it EXACTLY as found. `retain_floor_candidate` is wall-clock-derived and
/// untrusted (it can rewind, drop, or spike forward); the floor may advance
/// to `max(floor, min(candidate, highest allocated epoch + 1))`. The caller
/// MUST durably persist `alloc` before using the returned slot.
pub(crate) fn reserve_slot(
    alloc: &mut AllocationState,
    rln_identifier_hex: &str,
    epoch: u64,
    retain_floor_candidate: u64,
    rate_limit: u64,
) -> Result<u64, AllocError> {
    // Cap the advance at one past the highest allocated epoch AT OR BELOW
    // the candidate: rows above it are future allocations, and excluding
    // them stops a single spiked clock reading — which creates such a row —
    // from dragging the floor to that far-future value on a later
    // reservation and bricking every real epoch below it.
    let highest = alloc
        .allocations
        .iter()
        .filter(|a| a.epoch <= retain_floor_candidate)
        .map(|a| a.epoch.saturating_add(1))
        .max();
    let threshold = match highest {
        Some(h) => alloc.prune_floor.max(retain_floor_candidate.min(h)),
        None => alloc.prune_floor,
    };
    if epoch < threshold {
        return Err(AllocError::EpochBelowFloor);
    }

    // Allocate first — the slot is looked up by `(rln_identifier, epoch)` —
    // and only then advance the floor and prune, so every error return
    // mutates nothing.
    let slot = if let Some(row) = alloc
        .allocations
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
        alloc.allocations.push(EpochAllocation {
            rln_identifier: rln_identifier_hex.to_string(),
            epoch,
            used: 1,
        });
        0
    };
    alloc.prune_floor = threshold;
    alloc.allocations.retain(|a| a.epoch >= threshold);
    Ok(slot)
}

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
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1, 1, 3), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1, 1, 3), Ok(1));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1, 1, 3), Ok(2));
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 1, 1, 3),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!(remaining(&alloc.allocations, APP_A, 1, 3), 0);
    }

    #[test]
    fn below_floor_epochs_are_pruned_but_in_window_ones_survive() {
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 5, 4, 2), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 4, 4, 2), Ok(0));
        assert_eq!(alloc.allocations.len(), 2);
        assert_eq!(reserve_slot(&mut alloc, APP_A, 5, 4, 2), Ok(1));
        assert_eq!(remaining(&alloc.allocations, APP_A, 5, 2), 0);
        assert_eq!(remaining(&alloc.allocations, APP_A, 4, 2), 1);
        assert_eq!(reserve_slot(&mut alloc, APP_A, 6, 5, 2), Ok(0));
        assert!(alloc.allocations.iter().all(|a| a.epoch >= 5));
        assert_eq!(alloc.prune_floor, 5);
    }

    #[test]
    fn interleaved_in_window_epochs_never_reissue_a_slot() {
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 9, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 5), Ok(1));
        assert_eq!(remaining(&alloc.allocations, APP_A, 10, 5), 3);
        assert_eq!(remaining(&alloc.allocations, APP_A, 9, 5), 4);
    }

    #[test]
    fn applications_are_independent_within_an_epoch() {
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_B, 1, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1, 1, 2), Ok(1));
        assert_eq!(reserve_slot(&mut alloc, APP_B, 1, 1, 2), Ok(1));
        assert_eq!(alloc.allocations.len(), 2);
        assert_eq!(remaining(&alloc.allocations, APP_A, 1, 2), 0);
        assert_eq!(remaining(&alloc.allocations, APP_B, 1, 2), 0);
    }

    #[test]
    fn zero_rate_limit_never_allocates() {
        let mut alloc = AllocationState::default();
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 1, 1, 0),
            Err(AllocError::BudgetExhausted)
        );
    }

    #[test]
    fn rewound_clock_never_reissues_a_pruned_epoch() {
        // Audit cause B: a rewound clock re-admits pruned epoch 10 at the
        // window check; the persisted floor must refuse it.
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 11, 5), Ok(0));
        assert_eq!(alloc.prune_floor, 11, "pruning epoch 10 must be recorded in the floor");
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 10, 9, 5),
            Err(AllocError::EpochBelowFloor)
        );
        assert_eq!(alloc.prune_floor, 11, "a rewound candidate must never lower the floor");
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 9, 5), Ok(1));
    }

    #[test]
    fn forward_clock_spike_cannot_brick_future_epochs() {
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 1_000_000, 999_999, 5),
            Ok(0)
        );
        assert_eq!(alloc.prune_floor, 11, "the spike must not persist a far-future floor");
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 11, 5), Ok(0));
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 10, 11, 5),
            Err(AllocError::EpochBelowFloor)
        );
    }

    #[test]
    fn two_forward_spikes_do_not_brick_future_epochs() {
        // The regression: with a naive `highest`-over-all-rows cap, the first
        // spike's far-future row lets the SECOND spike drag the floor up to
        // the spiked clock value.
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1_000_000, 999_999, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 1_000_000, 999_999, 5), Ok(1));
        assert_eq!(alloc.prune_floor, 11, "a second spike must not drag the floor to the spiked clock");
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 11, 5), Ok(0));
    }

    #[test]
    fn failed_reservations_mutate_nothing() {
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 10, 9, 1), Ok(0));
        let before = (alloc.allocations.clone(), alloc.prune_floor);
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 10, 10, 1),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!((alloc.allocations.clone(), alloc.prune_floor), before);
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 11, 10, 0),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!((alloc.allocations.clone(), alloc.prune_floor), before);
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 11, 1), Ok(0));
        let after_prune = (alloc.allocations.clone(), alloc.prune_floor);
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 10, 11, 1),
            Err(AllocError::EpochBelowFloor)
        );
        assert_eq!((alloc.allocations.clone(), alloc.prune_floor), after_prune);
    }

    #[test]
    fn widened_epoch_gap_never_resurrects_pruned_epochs() {
        // Audit cause D: a restart with a wider gap re-admits pruned epoch 9
        // past the window check; the persisted floor must refuse it.
        let mut alloc = AllocationState::default();
        assert_eq!(reserve_slot(&mut alloc, APP_A, 9, 8, 5), Ok(0));
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 11, 5), Ok(0));
        assert!(alloc.allocations.iter().all(|a| a.epoch >= 10), "epoch 9's row is pruned");
        assert_eq!(alloc.prune_floor, 10);
        assert_eq!(
            reserve_slot(&mut alloc, APP_A, 9, 2, 5),
            Err(AllocError::EpochBelowFloor)
        );
        assert_eq!(reserve_slot(&mut alloc, APP_A, 12, 2, 5), Ok(1));
    }

    #[test]
    fn remaining_before_any_allocation_is_full() {
        let allocs = Vec::new();
        assert_eq!(remaining(&allocs, APP_A, 1, 100), 100);
    }
}
