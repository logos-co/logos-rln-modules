//! Membership lifecycle semantics, storage-agnostic: the pure state machine
//! shared by the sealed store and its consumers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The module-local lifecycle state, persisted in the cache sidecar.
/// `#[serde(rename_all = "snake_case")]` serializes
/// each variant to the EXACT wire string logos-lez-rln-module's
/// `rln_core::membership_status` returns (`GracePeriod → "grace_period"`);
/// the crates deliberately share no type — the `membership_state_wire_strings`
/// test anchors the contract. No `#[serde(other)]`: a stray persisted string
/// loud-fails deserialize rather than silently degrading.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipState {
    Unknown,
    Pending,
    Failed,
    Active,
    GracePeriod,
    Expired,
    Erased,
}

impl MembershipState {
    /// The usable ("selectable") states: a membership that can currently back
    /// a proof — the one predicate selection, scope resolution, and the quota
    /// read all share.
    pub(crate) fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }

    /// The live states (spec): a membership that blocks a new registration for
    /// its scope — usable, or still awaiting confirmation. Terminal states
    /// (failed, expired, erased, unknown) never block a fresh registration.
    pub(crate) fn is_live(self) -> bool {
        matches!(self, Self::Pending) || self.is_usable()
    }

    /// Ever observed on the registry — the "was Active, now gone → erased"
    /// removal signal's building block (see `merge_state`).
    pub(crate) fn is_active_like(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::Expired | Self::Erased)
    }
}

/// The decrypted credential plaintext.
/// Alphabetical field order = the encrypted JSON's key order.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct StoredCredential {
    pub(crate) identity_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity_nullifier: Option<String>,
    pub(crate) identity_secret_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity_trapdoor: Option<String>,
    /// Authoritative copy for post-decrypt cross-checks against the sidecar.
    pub(crate) registry_id: String,
}

/// Pending→Failed bound (spec MUST). Testnet confirmation runs 60–90s;
/// 300s leaves margin.
pub const CONFIRMATION_WINDOW_SECS: u64 = 300;

// ------------------------------------------------------------------- records

/// Registry-derived, poller-healed cache state, deliberately outside the
/// authenticated surface — tampering it is self-DoS, not disclosure; the
/// poller heals it from the registry. Unlike the old sidecar cache this
/// carries no `submitted_at` (it lives in `IdentityBlock`) and no
/// `state_history` — the monotone `first_active_at` stamp is the one
/// ever-active signal `merge_state` needs.
#[derive(Serialize, Deserialize, Clone)]
pub struct CacheState {
    pub state: MembershipState,
    /// Provisional while pending (pre-submit estimate); authoritative after
    /// the pending→active re-read (spec MUST).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_reason: Option<String>,
    /// Whether a `failed` state is worth retrying (spec: a failed submission
    /// SHALL report whether it is retryable). `None` outside the failed
    /// state (never set, or cleared on the next successful observation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_result: Option<String>,
    /// Stamped at the first active-like observation and never cleared —
    /// monotone, so a later `failed` still remembers the membership was once
    /// on the registry (the "was Active, now gone → erased" inference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_active_at: Option<u64>,
}

impl Default for CacheState {
    // Hand-written: MembershipState deliberately has no Default.
    fn default() -> CacheState {
        CacheState {
            state: MembershipState::Unknown,
            leaf_index: None,
            rate_limit: None,
            failed_reason: None,
            retryable: None,
            tx_result: None,
            first_active_at: None,
        }
    }
}

impl CacheState {
    /// Records a failed submission: state → Failed, the "submit_failed: "
    /// failure-reason prefix consumers key on, and the spec's retryable flag.
    pub(crate) fn mark_submit_failed(&mut self, message: &str, retryable: bool) {
        self.state = MembershipState::Failed;
        self.failed_reason = Some(format!("submit_failed: {message}"));
        self.retryable = Some(retryable);
    }

    /// Record a late/async submission error without clobbering a state already
    /// advanced past `Pending` (the registry may have confirmed the submission).
    /// Only a non-retryable error fails a still-`Pending` record; retryable
    /// ones stay `Pending` for `merge_state` to confirm or time out.
    pub(crate) fn record_async_submit_error(&mut self, message: &str, retryable: bool) {
        if self.state != MembershipState::Pending || retryable {
            return;
        }
        self.mark_submit_failed(message, retryable);
    }
}

/// One registry's local record as consumers see it: the membership_hash, the
/// sealed entry's plaintext identity header, the cache sidecar, the
/// MAC-covered allocation state, and whether the load-time tamper scan
/// quarantined it. In-memory only — never persisted as a unit.
#[derive(Clone)]
pub struct MembershipRecord {
    pub hash: String,
    pub identity: crate::sealed_store::format::IdentityBlock,
    pub cache: CacheState,
    pub alloc: crate::rate_limit::AllocationState,
    pub quarantined: bool,
}

// -------------------------------------------------------------- merged state

/// True once a record has ever been observed on the registry — the spec's
/// "state becomes Unknown after having been Active" removal signal.
fn has_been_active(record: &MembershipRecord) -> bool {
    record.cache.first_active_at.is_some() || record.cache.state.is_active_like()
}

/// The spec's merged view, as a pure function: the registry's report
/// (`Some(state)` / `None` = not present) overlaid on the local record.
/// Callers persist any transition this implies (pending→failed, →erased).
pub fn merge_state(
    local: Option<&MembershipRecord>,
    registry_state: Option<MembershipState>,
    now: u64,
) -> MembershipState {
    match (local, registry_state) {
        (None, None) => MembershipState::Unknown,
        // The registry has it: its chain-clock view wins outright.
        (_, Some(state)) => state,
        (Some(record), None) => {
            if record.cache.state == MembershipState::Pending {
                // submitted_at 0 = unset: maximally stale, so a pending
                // record with no submission time fails once now passes the
                // window — exactly the old plain-u64 arithmetic.
                if now.saturating_sub(record.identity.submitted_at) > CONFIRMATION_WINDOW_SECS {
                    MembershipState::Failed
                } else {
                    MembershipState::Pending
                }
            } else if has_been_active(record) {
                MembershipState::Erased
            } else {
                // failed stays failed (visible until re-registered).
                record.cache.state
            }
        }
    }
}

/// The `membership_state_changed` event's args, or `None` when `new_state`
/// equals the current state (re-observations — every poller tick and read —
/// must NOT emit). `record` is the PRE-transition record, so `previous` is
/// the state held just before the change; an empty (legacy) `rln_identifier`
/// carries through verbatim.
pub fn transition_event(
    hash: &str,
    record: &MembershipRecord,
    new_state: MembershipState,
) -> Option<(String, String, String, String, String)> {
    if new_state == record.cache.state {
        return None;
    }
    // Enum→wire string: serde's `rename_all = "snake_case"` on
    // MembershipState is the single source of truth for the wire strings.
    let wire = |s: MembershipState| {
        serde_json::to_value(s)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };
    Some((
        record.identity.registry_id.clone(),
        record.identity.rln_identifier.clone(),
        hash.to_string(),
        wire(new_state),
        wire(record.cache.state),
    ))
}

// --------------------------------------------------------------- cache file

pub const FORMAT_CACHE: &str = "rln-sealed-cache";

/// The plaintext cache sidecar's on-disk shape (`CACHE_FILE`), keyed by
/// membership_hash.
#[derive(Serialize, Deserialize, Clone)]
pub struct CacheFile {
    pub format: String,
    pub version: u32,
    pub entries: BTreeMap<String, CacheState>,
}

impl CacheFile {
    pub fn new() -> CacheFile {
        CacheFile {
            format: FORMAT_CACHE.to_string(),
            version: crate::sealed_store::format::FORMAT_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

impl Default for CacheFile {
    fn default() -> CacheFile {
        CacheFile::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(state: MembershipState, submitted_at: u64) -> MembershipRecord {
        MembershipRecord {
            hash: "h".to_string(),
            identity: crate::sealed_store::format::IdentityBlock {
                registry_id: format!("logos:local:{}", "ab".repeat(32)),
                rln_identifier: String::new(),
                identity_commitment: "11".repeat(32),
                submitted_at,
            },
            cache: CacheState {
                state,
                leaf_index: Some(7),
                rate_limit: Some(300),
                ..CacheState::default()
            },
            alloc: crate::rate_limit::AllocationState::default(),
            quarantined: false,
        }
    }

    #[test]
    fn merge_state_matrix() {
        use MembershipState::*;
        let now = 10_000;
        // No local record.
        assert_eq!(merge_state(None, None, now), Unknown);
        assert_eq!(merge_state(None, Some(Active), now), Active);
        // Pending inside/outside the confirmation window.
        let fresh = rec(Pending, now - 10);
        assert_eq!(merge_state(Some(&fresh), None, now), Pending);
        let stale = rec(Pending, now - CONFIRMATION_WINDOW_SECS - 1);
        assert_eq!(merge_state(Some(&stale), None, now), Failed);
        // submitted_at 0 = unset behaves as maximally stale.
        let unset = rec(Pending, 0);
        assert_eq!(merge_state(Some(&unset), None, now), Failed);
        // Registry view wins when present.
        assert_eq!(merge_state(Some(&stale), Some(GracePeriod), now), GracePeriod);
        // Failed stays failed while absent.
        let failed = rec(Failed, now - 1_000);
        assert_eq!(merge_state(Some(&failed), None, now), Failed);
        // Was active, now gone from the registry → inferred erased.
        let was_active = rec(Active, now - 1_000);
        assert_eq!(merge_state(Some(&was_active), None, now), Erased);
        // Ever-active is remembered via first_active_at (old: state_history).
        let mut ever_active = rec(Failed, now - 1_000);
        ever_active.cache.first_active_at = Some(now - 500);
        assert_eq!(merge_state(Some(&ever_active), None, now), Erased);
    }

    #[test]
    fn transition_event_gates_on_actual_state_change() {
        use MembershipState::*;
        // A mere re-observation of the same state must not emit.
        let active = rec(Active, 0);
        assert!(transition_event("h", &active, Active).is_none());

        // pending -> active: previous carries the pre-transition state.
        let pending = rec(Pending, 0);
        let (registry_id, rln_identifier, hash, state, previous) =
            transition_event("h1", &pending, Active).expect("real transition");
        assert_eq!(registry_id, pending.identity.registry_id);
        assert_eq!(rln_identifier, "");
        assert_eq!(hash, "h1");
        assert_eq!(state, "active");
        assert_eq!(previous, "pending");

        // A scoped record's rln_identifier is carried through verbatim.
        let mut scoped = rec(Pending, 0);
        scoped.identity.rln_identifier = "ab".repeat(32);
        let (_, rln_identifier, ..) =
            transition_event("h2", &scoped, Failed).expect("real transition");
        assert_eq!(rln_identifier, scoped.identity.rln_identifier);
    }

    #[test]
    fn first_active_at_semantics() {
        use MembershipState::*;
        let now = 10_000;
        // Some(first_active_at) marks ever-active even from a failed state:
        // absent from the registry ⇒ the erased inference.
        let mut once_active = rec(Failed, now - 1_000);
        once_active.cache.first_active_at = Some(now - 500);
        assert_eq!(merge_state(Some(&once_active), None, now), Erased);
        // None + a state never seen on the registry ⇒ not ever-active.
        let never_active = rec(Failed, now - 1_000);
        assert_eq!(merge_state(Some(&never_active), None, now), Failed);
    }

    #[test]
    fn async_submit_error_policy() {
        use MembershipState::*;
        // A late error never clobbers a state already past Pending.
        let mut confirmed = rec(Active, 0).cache;
        confirmed.record_async_submit_error("boom", false);
        assert_eq!(confirmed.state, Active);
        assert!(confirmed.failed_reason.is_none());
        // A retryable error leaves Pending for merge_state to confirm or
        // time out.
        let mut retryable = rec(Pending, 0).cache;
        retryable.record_async_submit_error("boom", true);
        assert_eq!(retryable.state, Pending);
        assert!(retryable.failed_reason.is_none());
        // A non-retryable error fails a still-Pending record, with the
        // "submit_failed: " prefix consumers key on.
        let mut fatal = rec(Pending, 0).cache;
        fatal.record_async_submit_error("boom", false);
        assert_eq!(fatal.state, Failed);
        assert_eq!(fatal.failed_reason.as_deref(), Some("submit_failed: boom"));
        assert_eq!(fatal.retryable, Some(false));
    }
}
