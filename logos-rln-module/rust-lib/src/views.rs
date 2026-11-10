//! Typed reply shapes: `#[derive(Serialize)]` mirrors of the wire objects
//! the method handlers hand back. Each struct's doc comment names the
//! `.lidl` record (or method-comment shape) it mirrors.
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

use crate::lifecycle::{MembershipRecord, MembershipState};

/// The `credential` object inside [`MembershipView`] — mirrors the nested
/// shape inside the `.lidl` `Membership` record. Exposes only the
/// commitment; no method releases the identity secret across this
/// interface.
#[derive(Serialize)]
pub(crate) struct CredentialView<'a> {
    identity_commitment: &'a str,
}

/// The public Membership view (spec Membership minus secrets) — mirrors the
/// `.lidl` `Membership` record. Shared by `register`, `select_membership`,
/// and `get_memberships`.
#[derive(Serialize)]
pub(crate) struct MembershipView<'a> {
    credential: CredentialView<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_size_mismatch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_reason: Option<&'a str>,
    leaf_index: u64,
    membership_hash: &'a str,
    rate_limit: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit_mismatch: Option<bool>,
    registry_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rln_identifier: Option<&'a str>,
    state: MembershipState,
    submitted_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_result: Option<&'a str>,
}

impl<'a> MembershipView<'a> {
    /// `quarantined` (metadata tamper-check failed) forces `state:"failed"`
    /// and `failed_reason:"metadata_tamper"` and suppresses `retryable` — a
    /// tamper verdict is never retriable. `rate_limit_mismatch` and
    /// `epoch_size_mismatch` are emitted only as `true`, never `false` —
    /// the latter marks a live membership whose allocation ledger is bound
    /// to a different epoch size than the module's current configuration
    /// (its reservations will fail Permanent until re-registered).
    pub(crate) fn new(
        hash: &'a str,
        record: &'a MembershipRecord,
        quarantined: bool,
        rate_limit_mismatch: bool,
        epoch_size_mismatch: bool,
    ) -> Self {
        let cache = &record.cache;
        let identity = &record.identity;
        let (failed_reason, retryable) = if quarantined {
            (Some("metadata_tamper"), None)
        } else {
            (
                cache.failed_reason.as_deref(),
                cache.failed_reason.as_ref().and(cache.retryable),
            )
        };
        MembershipView {
            credential: CredentialView {
                identity_commitment: &identity.identity_commitment,
            },
            epoch_size_mismatch: epoch_size_mismatch.then_some(true),
            failed_reason,
            leaf_index: cache.leaf_index.unwrap_or(0),
            membership_hash: hash,
            rate_limit: cache.rate_limit.unwrap_or(0),
            rate_limit_mismatch: rate_limit_mismatch.then_some(true),
            registry_id: &identity.registry_id,
            retryable,
            rln_identifier: (!identity.rln_identifier.is_empty())
                .then_some(identity.rln_identifier.as_str()),
            state: if quarantined {
                MembershipState::Failed
            } else {
                cache.state
            },
            submitted_at: identity.submitted_at,
            tx_result: cache.tx_result.as_deref(),
        }
    }
}

/// The public Membership view (spec Membership minus secrets): the
/// `credential` object exposes only the commitment; the identity secret
/// never crosses this interface.
pub(crate) fn public_membership(
    hash: &str,
    record: &MembershipRecord,
    quarantined: bool,
    rate_limit_mismatch: bool,
    epoch_size_mismatch: bool,
) -> serde_json::Value {
    serde_json::to_value(MembershipView::new(
        hash,
        record,
        quarantined,
        rate_limit_mismatch,
        epoch_size_mismatch,
    ))
    .unwrap_or(serde_json::Value::Null)
}

/// `get_membership_state`'s reply — mirrors the `.lidl` `MembershipState`
/// record. `registry_id`/`state` are always present; `membership_hash` /
/// `leaf_index` / `rate_limit` only once a single membership resolves for
/// the scope. `state:"unknown"` when none does; more than one candidate is
/// an `ambiguous_selection` error, not this shape.
#[derive(Serialize)]
pub(crate) struct MembershipStateView<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit: Option<u64>,
    /// What automatic provisioning is doing, when it is doing anything.
    /// Additive and omitted otherwise, so a caller that does not know about
    /// it is unaffected — but `state:"unknown"` is the same answer for "this
    /// node was never given a membership" and "this node is three minutes
    /// into acquiring one", and those want different reactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningView>,
    registry_id: &'a str,
    state: MembershipState,
    /// Why a `failed` or `erased` record is what it is, and whether a fresh
    /// registration may be attempted (spec: a failed submission SHALL report
    /// whether it is retryable). Present only on those states.
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
}

/// The provisioning task's current step, a human-readable detail, and — on
/// `awaiting_funding` only — the numbers behind it as decimal strings (the
/// same convention as balances on this wire: u128 does not survive JSON
/// number parsing everywhere). `balance` appears once the first balance read
/// has happened. Keys stay alphabetical.
#[derive(Serialize)]
pub(crate) struct ProvisioningView {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(skip_serializing_if = "str::is_empty")]
    detail: String,
    /// Why the allocator the registry was configured with did not deliver,
    /// while the funded fallback runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_reserve: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required: Option<String>,
    step: &'static str,
}

impl ProvisioningView {
    pub(crate) fn new(step: &'static str, detail: String) -> Self {
        ProvisioningView {
            balance: None,
            detail,
            fallback_reason: None,
            fee_reserve: None,
            payer: None,
            price: None,
            required: None,
            step,
        }
    }

    pub(crate) fn with_fallback_reason(mut self, reason: Option<String>) -> Self {
        self.fallback_reason = reason;
        self
    }

    /// Attach the funding snapshot's fields.
    pub(crate) fn with_funding(
        mut self,
        payer: impl Into<String>,
        required: u128,
        price: u128,
        fee_reserve: u128,
        balance: Option<u128>,
    ) -> Self {
        self.payer = Some(payer.into());
        self.required = Some(required.to_string());
        self.price = Some(price.to_string());
        self.fee_reserve = Some(fee_reserve.to_string());
        self.balance = balance.map(|b| b.to_string());
        self
    }
}

impl<'a> MembershipStateView<'a> {
    pub(crate) fn unknown(registry_id: &'a str) -> Self {
        MembershipStateView {
            leaf_index: None,
            membership_hash: None,
            rate_limit: None,
            provisioning: None,
            registry_id,
            state: MembershipState::Unknown,
            failed_reason: None,
            retryable: None,
        }
    }

    /// Attach a terminal record's reason and retryability.
    pub(crate) fn with_failure(mut self, reason: Option<&'a str>, retryable: Option<bool>) -> Self {
        self.failed_reason = reason;
        self.retryable = retryable;
        self
    }

    /// Attach provisioning progress, if any is recorded for this registry.
    pub(crate) fn with_provisioning(mut self, view: Option<ProvisioningView>) -> Self {
        self.provisioning = view;
        self
    }

    pub(crate) fn resolved(
        hash: &'a str,
        registry_id: &'a str,
        state: MembershipState,
        leaf_index: u64,
        rate_limit: u64,
    ) -> Self {
        MembershipStateView {
            provisioning: None,
            leaf_index: Some(leaf_index),
            membership_hash: Some(hash),
            rate_limit: Some(rate_limit),
            registry_id,
            state,
            failed_reason: None,
            retryable: None,
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
        EpochQuotaView {
            epoch_index,
            rate_limit,
            remaining,
        }
    }
}

/// `start`'s reply. Not a `.lidl` record. Every field but `overrides` is
/// always present; that one is the per-registry table in force (every
/// registry any `start()` named, with its epoch size and max gap), omitted
/// while no call has named a registry.
#[derive(Serialize)]
pub(crate) struct StartReply<'a> {
    epoch_size_sec: u64,
    max_epoch_gap: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    overrides: Option<serde_json::Value>,
    registries: &'a [String],
    started: bool,
}

impl<'a> StartReply<'a> {
    pub(crate) fn new(
        epoch_size_sec: u64,
        max_epoch_gap: u64,
        overrides: Option<serde_json::Value>,
        registries: &'a [String],
    ) -> Self {
        StartReply {
            epoch_size_sec,
            max_epoch_gap,
            overrides,
            registries,
            started: true,
        }
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
/// `start()`-configured value). `max_epoch_gap` uses the same registry override
/// resolution as proof validation; the registry-declared bounds appear only
/// when `get_registry_bounds` carried them. `price_per_unit` passes through
/// opaquely (documented upstream as a decimal string).
#[derive(Serialize)]
pub(crate) struct RegistryParametersView {
    epoch_size_sec: u64,
    max_epoch_gap: u64,
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
    pub(crate) fn from_bounds(
        epoch_size_sec: u64,
        max_epoch_gap: u64,
        mut bounds: serde_json::Value,
    ) -> Self {
        RegistryParametersView {
            epoch_size_sec,
            max_epoch_gap,
            max_rate_limit: bounds.get("max_rate_limit").and_then(|v| v.as_u64()),
            max_total_rate_limit: bounds.get("max_total_rate_limit").and_then(|v| v.as_u64()),
            min_rate_limit: bounds.get("min_rate_limit").and_then(|v| v.as_u64()),
            price_per_unit: bounds
                .get_mut("price_per_unit")
                .map(serde_json::Value::take),
        }
    }
}

/// `validate_proof`'s reply — mirrors the `.lidl` `VerificationResult` record.
/// `recovered_secret` is present only for the `"rate_limit_violation"`
/// verdict. `external_nullifier` is present when the verifier reconstructed
/// an omitted value for a cryptographically valid proof.
#[derive(Serialize)]
pub(crate) struct VerdictReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    external_nullifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovered_secret: Option<String>,
    verdict: &'static str,
}

impl VerdictReply {
    pub(crate) fn verdict(verdict: &'static str) -> Self {
        VerdictReply {
            external_nullifier: None,
            recovered_secret: None,
            verdict,
        }
    }

    pub(crate) fn rate_limit_violation(recovered_secret: String) -> Self {
        VerdictReply {
            external_nullifier: None,
            recovered_secret: Some(recovered_secret),
            verdict: "rate_limit_violation",
        }
    }

    pub(crate) fn with_external_nullifier(mut self, external_nullifier: String) -> Self {
        self.external_nullifier = Some(external_nullifier);
        self
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
        UnlockKeystoreReply {
            membership_count,
            unlocked: true,
        }
    }
}

/// The typed error envelope's body — mirrors `ApiError::body`'s
/// `{"class":…,"kind":…,"message":…}`. Not a `.lidl` record.
#[derive(Serialize)]
pub(crate) struct ErrorBody<'a> {
    class: &'static str,
    kind: &'static str,
    message: &'a str,
}

impl<'a> ErrorBody<'a> {
    pub(crate) fn new(class: &'static str, kind: &'static str, message: &'a str) -> Self {
        ErrorBody {
            class,
            kind,
            message,
        }
    }
}

#[cfg(test)]
mod provisioning_view_tests {
    use super::*;

    /// Pins the wire shape a UI reads: alphabetical keys, u128s as decimal
    /// strings, the funding fields absent on every step but awaiting_funding,
    /// and `balance` absent until something read it.
    #[test]
    fn provisioning_funding_fields_are_strings_and_optional() {
        let bare = MembershipStateView::unknown("logos:test:r").with_provisioning(Some(
            ProvisioningView::new("waiting_for_wallet", String::new()),
        ));
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            r#"{"provisioning":{"step":"waiting_for_wallet"},"registry_id":"logos:test:r","state":"unknown"}"#
        );

        let payer = "ab".repeat(32);
        let quoted = ProvisioningView::new("awaiting_funding", "needs 183000000".into())
            .with_funding(&payer, 183_000_000, 1_000_000, 182_000_000, None);
        assert_eq!(
            serde_json::to_string(&quoted).unwrap(),
            format!(
                r#"{{"detail":"needs 183000000","fee_reserve":"182000000","payer":"{payer}","price":"1000000","required":"183000000","step":"awaiting_funding"}}"#
            )
        );

        let read = ProvisioningView::new("awaiting_funding", String::new()).with_funding(
            &payer,
            u128::MAX,
            1,
            u128::MAX - 1,
            Some(7),
        );
        let json = serde_json::to_value(read).unwrap();
        assert_eq!(json["balance"], "7");
        assert_eq!(
            json["required"],
            u128::MAX.to_string(),
            "u128 travels as a string"
        );
        assert!(json.get("detail").is_none(), "empty detail is omitted");
    }
}

#[cfg(test)]
mod registry_parameters_tests {
    use super::*;

    #[test]
    fn registry_parameters_include_epoch_window_without_registry_bounds() {
        let view = RegistryParametersView::from_bounds(10, 3, serde_json::json!({}));
        assert_eq!(
            serde_json::to_value(view).unwrap(),
            serde_json::json!({
                "epoch_size_sec": 10, "max_epoch_gap": 3
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle;
    use crate::rate_limit;
    use crate::sealed_store;

    // Pins views::MembershipView's exact wire shape (alphabetical keys) with
    // every optional field populated — the reply of register /
    // select_membership / get_memberships.
    #[test]
    fn membership_view_serializes_alphabetical_keys() {
        let commitment = "11".repeat(32);
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let rln_identifier = "ef".repeat(32);
        let record = MembershipRecord {
            hash: "fixture-hash".to_string(),
            identity: sealed_store::format::IdentityBlock {
                registry_id: registry.clone(),
                rln_identifier: rln_identifier.clone(),
                identity_commitment: commitment.clone(),
                submitted_at: 1_234_567_890,
            },
            cache: lifecycle::CacheState {
                state: MembershipState::Failed,
                leaf_index: Some(7),
                rate_limit: Some(300),
                failed_reason: Some("submit_failed: boom".to_string()),
                retryable: Some(true),
                tx_result: Some("tx-result-blob".to_string()),
                first_active_at: None,
                confirm_deadline: None,
            },
            alloc: rate_limit::AllocationState::default(),
            quarantined: false,
        };
        let out = public_membership("fixture-hash", &record, false, true, false);
        assert_eq!(
            out.to_string(),
            format!(
                r#"{{"credential":{{"identity_commitment":"{commitment}"}},"failed_reason":"submit_failed: boom","leaf_index":7,"membership_hash":"fixture-hash","rate_limit":300,"rate_limit_mismatch":true,"registry_id":"{registry}","retryable":true,"rln_identifier":"{rln_identifier}","state":"failed","submitted_at":1234567890,"tx_result":"tx-result-blob"}}"#
            )
        );

        // Quarantined forces state:"failed"/failed_reason:"metadata_tamper"
        // and SUPPRESSES retryable — never "just retry" a tamper verdict.
        // rate_limit_mismatch is only ever true or absent, never false.
        let quarantined = public_membership("fixture-hash", &record, true, false, false);
        assert_eq!(
            quarantined.to_string(),
            format!(
                r#"{{"credential":{{"identity_commitment":"{commitment}"}},"failed_reason":"metadata_tamper","leaf_index":7,"membership_hash":"fixture-hash","rate_limit":300,"registry_id":"{registry}","rln_identifier":"{rln_identifier}","state":"failed","submitted_at":1234567890,"tx_result":"tx-result-blob"}}"#
            )
        );

        // The absent case is pinned by the exact-shape asserts above.
        let bound_elsewhere = public_membership("fixture-hash", &record, false, false, true);
        assert!(
            bound_elsewhere
                .to_string()
                .contains(r#""epoch_size_mismatch":true"#),
            "got: {bound_elsewhere}"
        );
    }

    // Pins MembershipStateView's and VerdictReply's exact bytes with every
    // field populated: serialized directly (declaration order) and through
    // `to_value` (the wire's alphabetical order).
    #[test]
    fn state_and_verdict_views_serialize_every_field() {
        let state =
            MembershipStateView::resolved("h-1", "logos:local:r", MembershipState::Failed, 7, 300)
                .with_failure(Some("confirmation_window_elapsed"), Some(true))
                .with_provisioning(Some(ProvisioningView::new(
                    "registering",
                    "step detail".into(),
                )));
        assert_eq!(
            serde_json::to_string(&state).unwrap(),
            r#"{"leaf_index":7,"membership_hash":"h-1","rate_limit":300,"provisioning":{"detail":"step detail","step":"registering"},"registry_id":"logos:local:r","state":"failed","failed_reason":"confirmation_window_elapsed","retryable":true}"#
        );
        assert_eq!(
            serde_json::to_value(&state).unwrap().to_string(),
            r#"{"failed_reason":"confirmation_window_elapsed","leaf_index":7,"membership_hash":"h-1","provisioning":{"detail":"step detail","step":"registering"},"rate_limit":300,"registry_id":"logos:local:r","retryable":true,"state":"failed"}"#
        );

        let (secret, nullifier) = ("5e".repeat(32), "e7".repeat(32));
        let expected = format!(
            r#"{{"external_nullifier":"{nullifier}","recovered_secret":"{secret}","verdict":"rate_limit_violation"}}"#
        );
        let violation =
            VerdictReply::rate_limit_violation(secret).with_external_nullifier(nullifier);
        assert_eq!(serde_json::to_string(&violation).unwrap(), expected);
        assert_eq!(
            serde_json::to_value(&violation).unwrap().to_string(),
            expected
        );
        assert_eq!(
            serde_json::to_value(VerdictReply::verdict("duplicate"))
                .unwrap()
                .to_string(),
            r#"{"verdict":"duplicate"}"#
        );
    }
}
