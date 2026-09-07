//! Membership lifecycle semantics, storage-agnostic: the pure state machine
//! shared by the sealed store and its consumers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The module-local lifecycle state, persisted in the cache sidecar.
/// `rename_all = "snake_case"` yields the EXACT wire strings
/// logos-lez-rln-module's `rln_core::membership_status` returns
/// (`GracePeriod → "grace_period"`); the crates deliberately share no type.
/// No `#[serde(other)]`: a stray persisted string loud-fails deserialize
/// rather than silently degrading.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipState {
    Unknown,
    Pending,
    Failed,
    Active,
    GracePeriod,
    Expired,
    /// Spec MEMBERSHIP_ERASED_AWAITS_WITHDRAWAL: removed, deposit still
    /// recoverable. In the vocabulary for spec completeness — the logos
    /// registry exposes no recoverable-deposit state, so the provider never
    /// reports it today.
    ErasedAwaitsWithdrawal,
    Erased,
    /// Spec MEMBERSHIP_SLASHED: removed by slashing, identity secret
    /// publicly revealed. In the vocabulary for spec completeness — the
    /// logos registry does not expose slashing as a removal cause, so
    /// removals surface as `Erased` (spec-sanctioned) and the provider
    /// never reports this today.
    Slashed,
}

impl MembershipState {
    /// Can currently back a proof — the ONE predicate selection, scope
    /// resolution, and the quota read all share.
    pub(crate) fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }

    /// The spec's live states: blocks a new registration for its scope;
    /// terminal states never do.
    pub(crate) fn is_live(self) -> bool {
        matches!(self, Self::Pending) || self.is_usable()
    }

    /// Ever observed on the registry — the "was Active, now gone → erased"
    /// inference's building block (see `merge_state`). The removal states
    /// (`ErasedAwaitsWithdrawal`, `Erased`, `Slashed`) all imply a prior
    /// registry sighting.
    pub(crate) fn is_active_like(self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::GracePeriod
                | Self::Expired
                | Self::ErasedAwaitsWithdrawal
                | Self::Erased
                | Self::Slashed
        )
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
    /// Authenticated by the credential AEAD's AAD — no separate cross-check.
    pub(crate) registry_id: String,
}

/// Pending→Failed bound (spec MUST). Testnet confirmation runs 60–90s;
/// 300s leaves margin.
pub const CONFIRMATION_WINDOW_SECS: u64 = 300;

// ------------------------------------------------------------------- records

/// Registry-derived cache state, deliberately outside the authenticated
/// surface — tampering it is self-DoS, not disclosure; the poller heals it
/// from the registry.
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
    /// Spec: a failed submission SHALL report whether it is retryable.
    /// `None` outside the failed state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_result: Option<String>,
    /// Stamped at the first active-like observation, never cleared: a later
    /// `failed` still remembers the membership was once on the registry.
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
    /// The "submit_failed: " failure-reason prefix is a consumer contract.
    pub(crate) fn mark_submit_failed(&mut self, message: &str, retryable: bool) {
        self.state = MembershipState::Failed;
        self.failed_reason = Some(format!("submit_failed: {message}"));
        self.retryable = Some(retryable);
    }

    /// A late/async submission error must not clobber a state already past
    /// `Pending` (the registry may have confirmed); a retryable one leaves
    /// `Pending` for `merge_state` to confirm or time out.
    pub(crate) fn record_async_submit_error(&mut self, message: &str, retryable: bool) {
        if self.state != MembershipState::Pending || retryable {
            return;
        }
        self.mark_submit_failed(message, retryable);
    }
}

/// One membership's local record as consumers see it. In-memory only —
/// never persisted as a unit.
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
        (_, Some(state)) => state,
        (Some(record), None) => {
            if record.cache.state == MembershipState::Pending {
                // submitted_at 0 = unset behaves as maximally stale.
                if now.saturating_sub(record.identity.submitted_at) > CONFIRMATION_WINDOW_SECS {
                    MembershipState::Failed
                } else {
                    MembershipState::Pending
                }
            } else if has_been_active(record) {
                MembershipState::Erased
            } else {
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
    prior: MembershipState,
    new_state: MembershipState,
) -> Option<(String, String, String, String, String)> {
    if new_state == prior {
        return None;
    }
    // Serde's `rename_all` on MembershipState is the single source of truth
    // for the wire strings.
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
        wire(prior),
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
        assert_eq!(merge_state(None, None, now), Unknown);
        assert_eq!(merge_state(None, Some(Active), now), Active);
        let fresh = rec(Pending, now - 10);
        assert_eq!(merge_state(Some(&fresh), None, now), Pending);
        let stale = rec(Pending, now - CONFIRMATION_WINDOW_SECS - 1);
        assert_eq!(merge_state(Some(&stale), None, now), Failed);
        let unset = rec(Pending, 0);
        assert_eq!(merge_state(Some(&unset), None, now), Failed);
        assert_eq!(merge_state(Some(&stale), Some(GracePeriod), now), GracePeriod);
        let failed = rec(Failed, now - 1_000);
        assert_eq!(merge_state(Some(&failed), None, now), Failed);
        let was_active = rec(Active, now - 1_000);
        assert_eq!(merge_state(Some(&was_active), None, now), Erased);
        let mut ever_active = rec(Failed, now - 1_000);
        ever_active.cache.first_active_at = Some(now - 500);
        assert_eq!(merge_state(Some(&ever_active), None, now), Erased);
    }

    #[test]
    fn transition_event_gates_on_actual_state_change() {
        use MembershipState::*;
        let active = rec(Active, 0);
        assert!(transition_event("h", &active, active.cache.state, Active).is_none());

        let pending = rec(Pending, 0);
        let (registry_id, rln_identifier, hash, state, previous) =
            transition_event("h1", &pending, pending.cache.state, Active).expect("real transition");
        assert_eq!(registry_id, pending.identity.registry_id);
        assert_eq!(rln_identifier, "");
        assert_eq!(hash, "h1");
        assert_eq!(state, "active");
        assert_eq!(previous, "pending");

        let mut scoped = rec(Pending, 0);
        scoped.identity.rln_identifier = "ab".repeat(32);
        let (_, rln_identifier, ..) =
            transition_event("h2", &scoped, scoped.cache.state, Failed).expect("real transition");
        assert_eq!(rln_identifier, scoped.identity.rln_identifier);
    }

    #[test]
    fn first_active_at_semantics() {
        use MembershipState::*;
        let now = 10_000;
        // Ever-active survives via first_active_at even from a failed state.
        let mut once_active = rec(Failed, now - 1_000);
        once_active.cache.first_active_at = Some(now - 500);
        assert_eq!(merge_state(Some(&once_active), None, now), Erased);
        let never_active = rec(Failed, now - 1_000);
        assert_eq!(merge_state(Some(&never_active), None, now), Failed);
    }

    #[test]
    fn async_submit_error_policy() {
        use MembershipState::*;
        let mut confirmed = rec(Active, 0).cache;
        confirmed.record_async_submit_error("boom", false);
        assert_eq!(confirmed.state, Active);
        assert!(confirmed.failed_reason.is_none());
        let mut retryable = rec(Pending, 0).cache;
        retryable.record_async_submit_error("boom", true);
        assert_eq!(retryable.state, Pending);
        assert!(retryable.failed_reason.is_none());
        let mut fatal = rec(Pending, 0).cache;
        fatal.record_async_submit_error("boom", false);
        assert_eq!(fatal.state, Failed);
        assert_eq!(fatal.failed_reason.as_deref(), Some("submit_failed: boom"));
        assert_eq!(fatal.retryable, Some(false));
    }
}
