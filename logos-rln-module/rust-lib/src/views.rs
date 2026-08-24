//! Typed reply shapes: `#[derive(Serialize)]` mirrors of the wire objects
//! `lib.rs` hands back. Each struct's doc comment names the `.lidl` record
//! (or method-comment shape) it mirrors.
//!
//! Fields are declared in alphabetical order as a preview of the wire shape.
//! Actual key order comes from `serde_json::to_value`: without the
//! `preserve_order` feature `serde_json`'s `Map` is a `BTreeMap`, so keys
//! sort alphabetically regardless of field order. Call sites must convert
//! through `to_value` — `serde_json::to_string` directly on a struct would
//! emit declaration order.
//!
//! `Option` fields use `skip_serializing_if = "Option::is_none"`: `None`
//! omits the key entirely, never a JSON `null`.

use serde::Serialize;

use crate::store::{MembershipMeta, MembershipState};

/// The `credential` object inside [`MembershipView`] — mirrors the nested
/// shape inside the `.lidl` `Membership` record. Exposes only the
/// commitment; no method releases the identity secret across this
/// interface.
#[derive(Serialize)]
pub(crate) struct CredentialView {
    identity_commitment: String,
}

/// The public Membership view (spec Membership minus secrets) — mirrors the
/// `.lidl` `Membership` record. Shared by `register`, `select_membership`,
/// and `get_memberships`.
#[derive(Serialize)]
pub(crate) struct MembershipView {
    credential: CredentialView,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_reason: Option<String>,
    leaf_index: u64,
    membership_hash: String,
    rate_limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit_mismatch: Option<bool>,
    registry_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rln_identifier: Option<String>,
    state: MembershipState,
    submitted_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_result: Option<String>,
}

impl MembershipView {
    /// `quarantined` (metadata tamper-check failed) forces `state:"failed"`
    /// and `failed_reason:"metadata_tamper"` and suppresses `retryable` — a
    /// tamper verdict is never retriable. `rate_limit_mismatch` is emitted
    /// only as `true`, never `false`.
    pub(crate) fn new(
        hash: &str,
        meta: &MembershipMeta,
        quarantined: bool,
        rate_limit_mismatch: bool,
    ) -> Self {
        let (failed_reason, retryable) = if quarantined {
            (Some("metadata_tamper".to_string()), None)
        } else {
            (meta.failed_reason.clone(), meta.failed_reason.as_ref().and(meta.retryable))
        };
        MembershipView {
            credential: CredentialView { identity_commitment: meta.identity_commitment.clone() },
            failed_reason,
            leaf_index: meta.leaf_index,
            membership_hash: hash.to_string(),
            rate_limit: meta.rate_limit,
            rate_limit_mismatch: rate_limit_mismatch.then_some(true),
            registry_id: meta.registry_id.clone(),
            retryable,
            rln_identifier: (!meta.rln_identifier.is_empty()).then(|| meta.rln_identifier.clone()),
            state: if quarantined { MembershipState::Failed } else { meta.state },
            submitted_at: meta.submitted_at,
            tx_result: meta.tx_result.clone(),
        }
    }
}

/// `get_membership_state`'s reply — mirrors the `.lidl` `MembershipState`
/// record. `registry_id`/`state` are always present; `membership_hash` /
/// `leaf_index` / `rate_limit` only once a single membership resolves for
/// the scope. `state:"unknown"` when none does; more than one candidate is
/// an `ambiguous_selection` error, not this shape.
#[derive(Serialize)]
pub(crate) struct MembershipStateView {
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit: Option<u64>,
    registry_id: String,
    state: MembershipState,
}

impl MembershipStateView {
    pub(crate) fn unknown(registry_id: &str) -> Self {
        MembershipStateView {
            leaf_index: None,
            membership_hash: None,
            rate_limit: None,
            registry_id: registry_id.to_string(),
            state: MembershipState::Unknown,
        }
    }

    pub(crate) fn resolved(
        hash: &str,
        registry_id: &str,
        state: MembershipState,
        leaf_index: u64,
        rate_limit: u64,
    ) -> Self {
        MembershipStateView {
            leaf_index: Some(leaf_index),
            membership_hash: Some(hash.to_string()),
            rate_limit: Some(rate_limit),
            registry_id: registry_id.to_string(),
            state,
        }
    }
}

/// `get_epoch_quota`'s reply — mirrors the `.lidl` `EpochQuota` record. All
/// three fields derive from ONE epoch observation (spec MUST) and are
/// always present.
#[derive(Serialize)]
pub(crate) struct EpochQuotaView {
    epoch_index: u64,
    rate_limit: u64,
    remaining: u64,
}

impl EpochQuotaView {
    pub(crate) fn new(epoch_index: u64, rate_limit: u64, remaining: u64) -> Self {
        EpochQuotaView { epoch_index, rate_limit, remaining }
    }
}

/// `start`'s reply. Not a `.lidl` record; all fields are always present.
#[derive(Serialize)]
pub(crate) struct StartReply {
    epoch_size_sec: u64,
    max_epoch_gap: u64,
    registries: Vec<String>,
    started: bool,
}

impl StartReply {
    pub(crate) fn new(epoch_size_sec: u64, max_epoch_gap: u64, registries: Vec<String>) -> Self {
        StartReply { epoch_size_sec, max_epoch_gap, registries, started: true }
    }
}

/// `stop`'s reply.
#[derive(Serialize)]
pub(crate) struct StopReply {
    stopped: bool,
}

impl StopReply {
    pub(crate) fn new() -> Self {
        StopReply { stopped: true }
    }
}

/// `get_registry_parameters`'s reply — mirrors the `.lidl`
/// `RegistryParameters` record. `epoch_size_sec` is always present (the
/// `start()`-configured value); the registry-declared bounds appear only
/// when `get_registry_bounds` carried them. `price_per_unit` passes through
/// opaquely (documented upstream as a decimal string).
#[derive(Serialize)]
pub(crate) struct RegistryParametersView {
    epoch_size_sec: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_rate_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_total_rate_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_rate_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price_per_unit: Option<serde_json::Value>,
}

impl RegistryParametersView {
    pub(crate) fn from_bounds(epoch_size_sec: u64, bounds: &serde_json::Value) -> Self {
        RegistryParametersView {
            epoch_size_sec,
            max_rate_limit: bounds.get("max_rate_limit").and_then(|v| v.as_u64()),
            max_total_rate_limit: bounds.get("max_total_rate_limit").and_then(|v| v.as_u64()),
            min_rate_limit: bounds.get("min_rate_limit").and_then(|v| v.as_u64()),
            price_per_unit: bounds.get("price_per_unit").cloned(),
        }
    }
}

/// `validate_proof`'s reply — mirrors the `.lidl` `VerificationResult` record.
/// `recovered_secret` is present only for the `"rate_limit_violation"`
/// verdict.
#[derive(Serialize)]
pub(crate) struct VerdictReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    recovered_secret: Option<String>,
    verdict: String,
}

impl VerdictReply {
    pub(crate) fn verdict(verdict: &str) -> Self {
        VerdictReply { recovered_secret: None, verdict: verdict.to_string() }
    }

    pub(crate) fn rate_limit_violation(recovered_secret: String) -> Self {
        VerdictReply {
            recovered_secret: Some(recovered_secret),
            verdict: "rate_limit_violation".to_string(),
        }
    }
}

/// `unlock_keystore`'s reply. Not a `.lidl` record; both fields are always
/// present.
#[derive(Serialize)]
pub(crate) struct UnlockKeystoreReply {
    membership_count: u64,
    unlocked: bool,
}

impl UnlockKeystoreReply {
    pub(crate) fn new(membership_count: u64) -> Self {
        UnlockKeystoreReply { membership_count, unlocked: true }
    }
}

/// The typed error envelope's body — mirrors `ApiError::body`'s
/// `{"class":…,"kind":…,"message":…}`. Not a `.lidl` record.
#[derive(Serialize)]
pub(crate) struct ErrorBody {
    class: &'static str,
    kind: &'static str,
    message: String,
}

impl ErrorBody {
    pub(crate) fn new(class: &'static str, kind: &'static str, message: String) -> Self {
        ErrorBody { class, kind, message }
    }
}
