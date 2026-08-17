//! Per-epoch nullifier log: the in-memory record of every nullifier
//! `verify_proof` has accepted. Keyed epoch → nullifier → the accepted
//! proof's `(share_x, share_y)`, it turns a second proof reusing a nullifier
//! into a verdict: the same `share_x` is a retransmission (duplicate), a
//! different `share_x` is a double-signal (rate-limit violation) whose two
//! Shamir shares reconstruct the violator's identity secret.
//!
//! Crypto-free by design — it stores and compares raw 32-byte values only, so
//! it stays on `verify_proof`'s hot path: no registry access, no disk, no
//! field arithmetic. Retention is bounded to the freshness window: an epoch
//! that can no longer host a fresh proof (below `now − max_epoch_gap`) is
//! pruned, since a collision there is already undetectable.
//!
//! Known limit: this DETECTION-side log is in-memory and its prune floor
//! tracks the wall clock, so a verifier restart or a backwards clock step
//! forgets recorded nullifiers and a collision spanning that gap goes
//! unobserved. That weakens detection, not the slot-uniqueness invariant;
//! hardening it (persistence + a monotone floor, as in `rate_limit`) is
//! deliberately out of scope.

use std::collections::HashMap;
use std::sync::Mutex;

/// The verdict `record_verified` reaches for a proof that has already passed
/// every validity check — the log's sole output. `Fresh` is the first sighting
/// of `(epoch, nullifier)`; `Duplicate` and `Collision` are repeat sightings
/// split by `share_x` (the signal-bound coordinate): equal means the same
/// message re-sent, different means two distinct messages under one slot.
pub(crate) enum RecordOutcome {
    /// First time this `(epoch, nullifier)` is seen — the proof is accepted and
    /// its shares are now on record for future collision checks.
    Fresh,
    /// A prior proof carried this nullifier AND the identical `share_x`: the
    /// same signal re-transmitted, not a rate-limit breach.
    Duplicate,
    /// A prior proof carried this nullifier under a DIFFERENT `share_x`: a
    /// double-signal. Carries the recorded prior share so the caller can
    /// reconstruct the double-signaller's identity secret from the two shares.
    Collision { prior_x: [u8; 32], prior_y: [u8; 32] },
}

/// One accepted proof's `(share_x, share_y)` — the Shamir point a later
/// collision reconstructs the secret against.
type Shares = ([u8; 32], [u8; 32]);
/// One epoch's bucket: nullifier → the first accepted proof's shares.
type EpochBucket = HashMap<[u8; 32], Shares>;

/// epoch → nullifier → the first accepted proof's shares. `Option` so the map
/// is `const`-initializable (`HashMap::new` is not `const`); reached only
/// through the poison-recovering [`crate::lock`].
static LOG: Mutex<Option<HashMap<u64, EpochBucket>>> = Mutex::new(None);

/// Record a proof that has ALREADY passed validity + root-window checks, and
/// judge its nullifier against the epoch's log in one atomic step under the
/// lock — a check-and-insert that can never interleave with another verify.
///
/// `retain_floor` is `now − max_epoch_gap`: epochs strictly below it are pruned
/// first, because a proof for such an epoch can no longer be fresh (it fails
/// the freshness window before ever reaching here), so its bucket can host no
/// future detectable collision and pruning it loses nothing. The classification
/// is then exact: absent nullifier ⇒ `Fresh` (and inserted); present with equal
/// `share_x` ⇒ `Duplicate`; present with a different `share_x` ⇒ `Collision`
/// carrying the prior share — the entry is LEFT in place so every later
/// double-signal on the same slot is still caught.
pub(crate) fn record_verified(
    epoch: u64,
    nullifier: [u8; 32],
    share_x: [u8; 32],
    share_y: [u8; 32],
    retain_floor: u64,
) -> RecordOutcome {
    let mut guard = crate::lock(&LOG);
    let log = guard.get_or_insert_with(HashMap::new);
    log.retain(|&e, _| e >= retain_floor);
    let bucket = log.entry(epoch).or_default();
    match bucket.get(&nullifier).copied() {
        None => {
            bucket.insert(nullifier, (share_x, share_y));
            RecordOutcome::Fresh
        }
        Some((prior_x, _)) if prior_x == share_x => RecordOutcome::Duplicate,
        Some((prior_x, prior_y)) => RecordOutcome::Collision { prior_x, prior_y },
    }
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    *crate::lock(&LOG) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialized on the crate's global-state lock and reset first: verdicts
    // depend on log contents, and the lib verify tests wipe this same static
    // under that lock.
    #[test]
    fn fresh_then_duplicate_then_collision() {
        let _serial = crate::lock(&crate::store::TEST_STORE_LOCK);
        reset_for_test();
        let n = [0xa1u8; 32];
        let (x1, y1) = ([0x11u8; 32], [0x21u8; 32]);
        let (x2, y2) = ([0x12u8; 32], [0x22u8; 32]);

        assert!(matches!(record_verified(100, n, x1, y1, 0), RecordOutcome::Fresh));
        assert!(matches!(record_verified(100, n, x1, y1, 0), RecordOutcome::Duplicate));
        match record_verified(100, n, x2, y2, 0) {
            RecordOutcome::Collision { prior_x, prior_y } => {
                assert_eq!(prior_x, x1);
                assert_eq!(prior_y, y1);
            }
            _ => panic!("expected collision carrying the prior share"),
        }
    }

    #[test]
    fn prunes_below_retain_floor() {
        let _serial = crate::lock(&crate::store::TEST_STORE_LOCK);
        reset_for_test();
        let n = [0xb2u8; 32];
        let (x1, y1) = ([0x31u8; 32], [0x41u8; 32]);

        assert!(matches!(record_verified(100, n, x1, y1, 0), RecordOutcome::Fresh));
        // Recording at 102 with retain_floor 101 drops epoch 100 first.
        assert!(matches!(record_verified(102, n, x1, y1, 101), RecordOutcome::Fresh));
        // Epoch 100 is empty again → Fresh, proving the earlier entry was pruned.
        assert!(matches!(record_verified(100, n, x1, y1, 0), RecordOutcome::Fresh));
    }
}
