//! The rate-limiting methods: proof generation and validation in both signal
//! dialects, the epoch freshness and binding rules they share, the epoch
//! quota read, and the registry parameters read.

use std::sync::Arc;

use crate::config::epoch_params_for;
use crate::error::{ApiError, ErrorKind};
use crate::nullifier_log;
use crate::ok_json;
use crate::path_cache;
use crate::proof;
use crate::rate_limit;
use crate::registry_id;
use crate::roots;
use crate::scope::{backend_of, parse_scope, records_for_registry, scope_candidates};
use crate::sealed_store::store::Store;
use crate::select;
use crate::util::now_unix;
use crate::views;

pub(crate) fn proof_error(e: proof::ProofError) -> ApiError {
    match e {
        proof::ProofError::BadInput(m) => ApiError::new(ErrorKind::InvalidArgument, m),
        proof::ProofError::Engine(m) => ApiError::new(ErrorKind::Transient, m),
    }
}

/// Spec generate_proof(scope, signal, timestamp): pick the scope's usable
/// membership, serve its Merkle path (cache when warm, on-demand fetch on a
/// miss), reserve + DURABLY PERSIST the next message_id, and prove — the
/// identity secret never leaves the module. The proof's epoch derives from
/// the caller-supplied `timestamp` (Unix seconds), NOT this module's clock,
/// and must land within now ± `max_epoch_gap`. Returns the `RateLimitProof`
/// (spec shape: `proof` = compressed Groth16 proof[128], `epoch` = epoch[32]
/// LE hex) plus the spent `message_id`, the u64 `epoch_index`, the
/// `membership_hash`, and `proof_canonical`.
pub(crate) fn generate_proof_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal_hex: &str,
    timestamp: &str,
) -> Result<serde_json::Value, ApiError> {
    generate_proof_with(
        store,
        registry_id_raw,
        rln_identifier_hex,
        SignalArg::Raw(signal_hex),
        timestamp,
    )
}

/// The signal argument of the two generate/validate wire dialects: the raw
/// message bytes as hex (`signal_hex`, the spec shape — hashed here), or the
/// consumer-hashed `x` as its canonical 32-byte LE hex (`signal_hash_hex`,
/// the `_prehashed` methods). Both resolve to the circuit's `x`; the
/// pre-hashed form is decoded strictly (a non-canonical value is refused,
/// never reduced), so one `x` has exactly one wire spelling.
#[derive(Clone, Copy)]
// OWNERSHIP: borrows the request's hex text for the call.
pub(crate) enum SignalArg<'a> {
    Raw(&'a str),
    Prehashed(&'a str),
}

impl SignalArg<'_> {
    pub(crate) fn resolve(self) -> Result<rln_signal::Fr, ApiError> {
        match self {
            SignalArg::Raw(hex) => registry_id::hex_to_vec(hex)
                .map(|bytes| proof::signal_to_x(&bytes))
                .ok_or_else(|| ApiError::new(ErrorKind::InvalidArgument, "signal must be hex")),
            SignalArg::Prehashed(hex) => proof::x_from_hash_hex(hex).map_err(|_| {
                ApiError::new(
                    ErrorKind::InvalidArgument,
                    "signal_hash must be the 32-byte LE hex of a canonical field element",
                )
            }),
        }
    }
}

pub(crate) fn generate_proof_with(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal: SignalArg<'_>,
    timestamp: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, rln_identifier, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let backend = backend_of(&registry)?;
    // Readiness gate FIRST (spec: not_ready before anything else). The epoch
    // derives from the CONSUMER's timestamp — the value stamped on the
    // message — so the receiver's timestamp->epoch check lines up by
    // construction, and a stale or future one fails fast instead of minting
    // a proof the verifier would reject as not fresh.
    let (epoch, size, gap, now_epoch) = fresh_epoch_for(&registry.canonical, timestamp)?;
    let x = signal.resolve()?;

    // Keep this registry's root window warm (this node may verify too).
    roots::track(&registry);

    // Pick THE usable membership backing this scope; base generate_proof
    // requires a single candidate (AmbiguousSelection otherwise).
    let store = store?;
    let records = records_for_registry(&store, &registry);
    let candidates = scope_candidates(&records, &rln_id_hex);
    let selected = select::select(
        &candidates,
        (&registry.canonical, &rln_id_hex),
        &select::Selector::None,
    )?;
    let hash = selected.hash.as_str();
    // Re-read by hash for the freshest leaf_index and rate_limit: a poller
    // write, a concurrent reservation or a registration may have swapped the
    // store's snapshot since `records` was taken.
    let record = store.membership(hash).ok_or_else(|| {
        ApiError::new(ErrorKind::UnknownMembership, "selected membership vanished")
    })?;
    // Leaf 0 is a VALID leaf: defaulting here would prove against the wrong
    // membership and burn a message-id slot doing it. The cache is
    // deliberately unauthenticated (lifecycle.rs), so refuse rather than
    // guess — and refuse BEFORE the reservation below.
    let leaf_index = record.cache.leaf_index.ok_or_else(|| {
        ApiError::new(
            ErrorKind::UnknownMembership,
            "the selected membership carries no leaf_index",
        )
    })?;
    let rate_limit = record.cache.rate_limit.unwrap_or(0);

    // Decrypt the credential in-module (requires an unlocked keystore).
    let mut credential = store.unseal_credential(hash)?;

    // Fetch the Merkle path first — it can fail without spending a slot. A
    // cache hit is ZERO registry I/O; a miss falls back to the on-demand
    // fetch, which also fills the cache. A cached entry is only trusted
    // when its leaf_index still matches — see path_cache.rs.
    let (path_elements_hex, path_indices) = match path_cache::hit(hash, leaf_index) {
        Some(path) => path,
        None => {
            path_cache::fill_path_cache(&registry, hash, leaf_index, backend.tree)?;
            path_cache::hit(hash, leaf_index)
                .ok_or_else(|| ApiError::internal("path cache: fetched path vanished before use"))?
        }
    };

    // Reserve + durably persist the slot BEFORE proving, so a crash can
    // waste a slot but never reissue one. `retain_floor` is only the
    // window's CANDIDATE; the store's persisted monotone floor decides what
    // may be pruned or served.
    let retain_floor = now_epoch.saturating_sub(gap);
    let message_id =
        store.reserve_message_id(hash, &rln_id_hex, epoch, retain_floor, rate_limit, size)?;

    // OWNERSHIP: the secret moves out of the credential (`mem::take`: its
    // Drop forbids a field move) into the material; both wipe on drop.
    let material = proof::WitnessMaterial {
        identity_secret_hash_hex: std::mem::take(&mut credential.identity_secret_hash),
        rate_limit,
        message_id,
        path_elements_hex,
        path_indices,
    };
    let rlp = proof::generate(&material, x, epoch, &rln_identifier).map_err(proof_error)?;

    let mut out = rlp.to_json();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("message_id".to_string(), message_id.into());
        obj.insert("epoch_index".to_string(), epoch.into());
        obj.insert("membership_hash".to_string(), hash.into());
        obj.insert("proof_canonical".to_string(), rlp.canonical_hex().into());
    }
    Ok(out)
}

/// Parse a wire `timestamp` argument (Unix seconds as a decimal string — a
/// tstr on purpose, so a numeric JSON arg cannot silently coerce to 0) into
/// its epoch index.
pub(crate) fn epoch_of_timestamp(timestamp: &str, epoch_size_sec: u64) -> Result<u64, ApiError> {
    Ok(rate_limit::current_epoch(
        timestamp.trim().parse::<u64>().map_err(|_| {
            ApiError::new(
                ErrorKind::InvalidArgument,
                "timestamp must be a Unix-seconds integer",
            )
        })?,
        epoch_size_sec,
    ))
}

/// The freshness window every rate-limiting method enforces: an epoch is
/// acceptable when within now ± max_epoch_gap of the module clock.
pub(crate) fn epoch_in_window(epoch: u64, now_epoch: u64, gap: u64) -> bool {
    (now_epoch.saturating_sub(gap)..=now_epoch.saturating_add(gap)).contains(&epoch)
}

/// The readiness + freshness gate `generate_proof` and `get_epoch_quota`
/// share: resolve the registry's epoch parameters, derive the caller's epoch
/// from its timestamp, and refuse a stale or future one. The two must agree
/// — a timestamp generate_proof would refuse is refused by the quota read
/// too (spec: permanent) — so the rule has one home. Returns the caller's
/// epoch and the observation it was checked against: `(epoch, size, gap,
/// now_epoch)`.
pub(crate) fn fresh_epoch_for(
    registry: &str,
    timestamp: &str,
) -> Result<(u64, u64, u64, u64), ApiError> {
    let (size, gap) = epoch_params_for(registry)?;
    let epoch = epoch_of_timestamp(timestamp, size)?;
    let now_epoch = rate_limit::current_epoch(now_unix(), size);
    if !epoch_in_window(epoch, now_epoch, gap) {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "timestamp is outside the acceptable epoch window (now ± max_epoch_gap)",
        ));
    }
    Ok((epoch, size, gap, now_epoch))
}

/// Whether a proof is bound to `expected_epoch` — the epoch derived from
/// the message's timestamp (spec: proof.epoch MUST equal it). Holds when
/// the expected epoch is fresh (within now ± max_epoch_gap), the proof's
/// carried epoch (spec epoch[32]), when present, equals it, and the proof's
/// external nullifier equals the one recomputed from that epoch + the
/// scope's rln_identifier. Any failure is a verdict-`invalid` condition,
/// never an error.
pub(crate) fn epoch_binding_holds(
    carried: Option<u64>,
    bound: &[u8; 32],
    rln_identifier: &[u8; 32],
    expected_epoch: u64,
    now_epoch: u64,
    gap: u64,
) -> bool {
    epoch_in_window(expected_epoch, now_epoch, gap)
        && carried.is_none_or(|e| e == expected_epoch)
        && proof::expected_external_nullifier(expected_epoch, rln_identifier) == *bound
}

/// Spec validate_proof(scope, signal, timestamp, proof): the message hot
/// path. Serves entirely from the locally maintained valid-root window and
/// NEVER reads the registry; a cold/stale window is `NOT_READY`, never a
/// false reject. No membership or unlocked keystore is required.
///
/// The expected epoch derives from the caller-supplied `timestamp` — the
/// value stamped on the message under validation — so the budget the proof
/// spends provably belongs to the epoch the message claims. Beyond
/// zk-validity and root-in-window, [`epoch_binding_holds`] requires that
/// epoch to be fresh, to equal the proof's carried epoch, and to recompute
/// the proof's external nullifier `poseidon(hash_to_field_le(epoch[32]),
/// hash_to_field_le(rln_identifier))` (epoch[32] = the index as 32-byte LE)
/// — a stale, epoch-shifted, or cross-application proof is
/// `verdict:invalid`.
///
/// The reply is a verdict, not a bool. A validated proof is judged against
/// the in-memory nullifier log (retention = `max_epoch_gap` epochs): fresh
/// → `valid`; a repeat under the SAME `share_x` → `duplicate`; a DIFFERENT
/// `share_x` → `rate_limit_violation`, whose `recovered_secret` is the
/// VIOLATOR'S OWN identity secret reconstructed from the colliding shares
/// (never one of this module's credentials). An invalid proof never mutates
/// the log. The log is in-memory with a wall-clock floor, so a restart or
/// clock rewind forgets nullifiers — detection is best-effort across those
/// events (see `nullifier_log` docs); slot uniqueness on the generation
/// side does not depend on it.
pub(crate) fn validate_proof_impl(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal_hex: &str,
    timestamp: &str,
    proof_json: &str,
) -> Result<serde_json::Value, ApiError> {
    validate_proof_with(
        registry_id_raw,
        rln_identifier_hex,
        SignalArg::Raw(signal_hex),
        timestamp,
        proof_json,
    )
}

pub(crate) fn validate_proof_with(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal: SignalArg<'_>,
    timestamp: &str,
    proof_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, rln_identifier, _) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    // Namespace support check only — no registry I/O on the verify path.
    backend_of(&registry)?;
    // Readiness gate FIRST (spec: not_ready before anything else).
    let (size, gap) = epoch_params_for(&registry.canonical)?;
    let now_epoch = rate_limit::current_epoch(now_unix(), size);
    let expected_epoch = epoch_of_timestamp(timestamp, size)?;
    let x = signal.resolve()?;
    let mut proof_value: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, format!("proof_json: {e}")))?;
    // Mix omits this derivable public input on the network. Reconstruct it
    // from the trusted request scope; cryptographic verification still binds
    // the received proof to this application and epoch.
    let derive_external_nullifier =
        proof_value.get("root").is_some() && proof_value.get("external_nullifier").is_none();
    if derive_external_nullifier {
        proof_value["external_nullifier"] = serde_json::Value::String(registry_id::bytes_to_hex(
            &proof::expected_external_nullifier(expected_epoch, &rln_identifier),
        ));
    }
    let rlp = proof::RateLimitProof::from_json(&proof_value).map_err(proof_error)?;

    // Application + epoch binding first — pure local computation, so a stale
    // or wrong-application proof rejects definitively even before the root
    // window is consulted.
    let bound = rlp.external_nullifier();
    if !epoch_binding_holds(
        rlp.epoch(),
        &bound,
        &rln_identifier,
        expected_epoch,
        now_epoch,
        gap,
    ) {
        return ok_json(views::VerdictReply::verdict("invalid"));
    }

    // Root window BEFORE any log touch: a cold/stale window is NOT_READY, never
    // a verdict, and must not leave a nullifier logged for an unservable proof.
    roots::track(&registry);
    let window = roots::window(&registry.canonical).ok_or_else(|| {
        ApiError::new(ErrorKind::NotReady, "valid-root window not warm yet; retry")
    })?;
    // A warm window lacking the proof's root is as often the freshly-
    // published-root race as a bad proof: answer `invalid`, and let
    // roots::nudge shorten it.
    if !window.contains(&rlp.root()) {
        roots::nudge();
        return ok_json(views::VerdictReply::verdict("invalid"));
    }
    if !proof::verify(&rlp, x, &window).map_err(proof_error)? {
        // Invalid proofs are NOT logged — only a validated nullifier counts.
        return ok_json(views::VerdictReply::verdict("invalid"));
    }

    // The retention floor stays wall-clock-derived: a caller-chosen
    // timestamp must never move the nullifier log's prune floor.
    let retain_floor = now_epoch.saturating_sub(gap);
    let view = match nullifier_log::record_verified(
        &registry.canonical,
        expected_epoch,
        rlp.nullifier(),
        rlp.share_x(),
        rlp.share_y(),
        retain_floor,
    ) {
        nullifier_log::RecordOutcome::Fresh => views::VerdictReply::verdict("valid"),
        nullifier_log::RecordOutcome::Duplicate => views::VerdictReply::verdict("duplicate"),
        nullifier_log::RecordOutcome::Collision { prior_x, prior_y } => {
            let recovered_secret = proof::recover_identity_secret_hex(
                (prior_x, prior_y),
                (rlp.share_x(), rlp.share_y()),
            )
            .map_err(proof_error)?;
            views::VerdictReply::rate_limit_violation(recovered_secret)
        }
    };
    let view = if derive_external_nullifier {
        view.with_external_nullifier(registry_id::bytes_to_hex(&bound))
    } else {
        view
    };
    ok_json(view)
}

/// Spec get_epoch_quota(scope, timestamp): the epoch of the supplied
/// timestamp, the membership's rate limit, and that epoch's unspent budget.
/// Purely local: no registry access, no unlock; `remaining` is advisory —
/// generate_proof stays the allocation authority. All three fields derive
/// from ONE epoch observation (spec MUST), so a snapshot never mixes epochs
/// across a rollover. A timestamp whose epoch generate_proof would refuse
/// is refused here too (spec: permanent), letting a consumer test a
/// timestamp before committing to it. No usable membership → zeros, not an
/// error (spec SHALL): rate_limit 0 always means "no usable membership",
/// never an exhausted budget.
pub(crate) fn get_epoch_quota_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    timestamp: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    // Namespace support check only — the quota is served from local state.
    backend_of(&registry)?;
    // Readiness gate FIRST. The single epoch observation is fixed by the
    // caller's timestamp: taken once, it keys the remaining lookup.
    let (epoch_index, size, ..) = fresh_epoch_for(&registry.canonical, timestamp)?;

    let store = store?;
    let records = records_for_registry(&store, &registry);
    let usable: Vec<_> = scope_candidates(&records, &rln_id_hex)
        .into_iter()
        .filter(|r| !r.quarantined && r.cache.state.is_usable())
        .collect();
    if usable.is_empty() {
        return ok_json(views::EpochQuotaView::new(epoch_index, 0, 0));
    }
    if usable.len() > 1 {
        return Err(ApiError::new(
            ErrorKind::AmbiguousSelection,
            "multiple memberships back this scope; use select_membership",
        ));
    }
    let record = &usable[0];
    let rate_limit = record.cache.rate_limit.unwrap_or(0);

    let remaining =
        store.remaining_budget(&record.hash, &rln_id_hex, epoch_index, rate_limit, size)?;
    ok_json(views::EpochQuotaView::new(
        epoch_index,
        rate_limit,
        remaining,
    ))
}

/// Registry parameters read (spec's optional extension): the
/// registry-declared bounds plus the module's configured epoch length. The
/// spec's SHOULD-check ("reject a configured epoch size that contradicts a
/// declared one") is vacuous here: `get_registry_bounds` declares no epoch
/// length (`active_duration`/`grace_period_duration` are the on-chain
/// membership-lifecycle clock, not the rate-limiting epoch).
pub(crate) fn get_registry_parameters_impl(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, _) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let backend = backend_of(&registry)?;

    let bounds = backend.registry.get_registry_bounds(&registry)?;
    let (epoch_size_sec, max_epoch_gap) = epoch_params_for(&registry.canonical)?;
    let view = views::RegistryParametersView::from_bounds(epoch_size_sec, max_epoch_gap, bounds);
    ok_json(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{epoch_size, reset_config_for_test};
    use crate::generated::LiblogosRlnModule;
    use crate::lifecycle::MembershipState;
    use crate::sealed_store;
    use crate::start_impl;
    use crate::test_support::{imp_with_store, no_store, seed_membership, TEST_GLOBAL_LOCK};

    // Spec: before start() configures the epoch size, the epoch-dependent
    // surface answers not_ready (RLN_ERR_NOT_READY).
    #[test]
    fn rate_limiting_before_start_is_not_ready() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        reset_config_for_test();
        let registry = format!("logos:local:{}", "ef".repeat(32));
        let rln_id_hex = "09".repeat(32);
        let signal_hex = "aa";

        let ts = now_unix().to_string();
        let err = get_epoch_quota_impl(no_store(), &registry, &rln_id_hex, &ts).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotReady);
        let err =
            generate_proof_impl(no_store(), &registry, &rln_id_hex, signal_hex, &ts).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotReady);
        let err = validate_proof_impl(&registry, &rln_id_hex, signal_hex, &ts, "{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotReady);

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // validate_proof end to end, entirely offline: a real synthetic proof, a
    // locally injected root window, no registry access. Proofs carry the
    // CURRENT epoch's external nullifier, so generate against the live epoch.
    #[test]
    fn validate_proof_impl_serves_from_local_window() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        // This scope's proof shares seed 7 / rln_id 9 / epoch-now (thus one
        // nullifier) with other verify tests; clear the shared log so the first
        // accepted proof reads `valid`, not a cross-test `duplicate`.
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let account = "ab".repeat(32);
        let registry = format!("logos:local:{account}");
        let canonical = registry.clone();
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"hot-path-signal";
        let signal_hex = registry_id::bytes_to_hex(signal);

        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());
        let ts = (epoch * 600).to_string();
        let rlp = proof::generate_for_test(&[7u8; 32], signal, epoch, &rln_id);
        let root = rlp.root();
        let proof_json = rlp.to_json().to_string();

        // Cold window → NOT_READY (never a false reject from an empty view).
        let cold =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &ts, &proof_json).unwrap_err();
        assert_eq!(cold.kind, ErrorKind::NotReady);

        // Warm the window with the proof's own root → valid.
        roots::set_window_for_test(&canonical, vec![root], now_unix());
        let ok =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &ts, &proof_json).unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        // A different signal is invalid, not an error.
        let other = registry_id::bytes_to_hex(b"another-signal");
        let bad = validate_proof_impl(&registry, &rln_id_hex, &other, &ts, &proof_json).unwrap();
        assert_eq!(bad, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // The pre-hashed dialect is interchangeable with the raw one over the same
    // proof: a verifier may hash the message itself and pass x — the reply's
    // own share_x — and the two dialects share one nullifier log.
    #[test]
    fn validate_proof_prehashed_is_interchangeable_with_raw() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "cd".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"prehashed-signal";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let hash_hex = registry_id::bytes_to_hex(&rln_signal::signal_hash(signal));

        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());
        let ts = (epoch * 600).to_string();
        let rlp = proof::generate_for_test(&[7u8; 32], signal, epoch, &rln_id);
        let proof_json = rlp.to_json().to_string();
        // The reply's share_x IS the pre-hashed wire value.
        assert_eq!(rlp.to_json()["share_x"].as_str().unwrap(), hash_hex);
        roots::set_window_for_test(&registry, vec![rlp.root()], now_unix());

        let prehashed = |hex: &str| {
            validate_proof_with(
                &registry,
                &rln_id_hex,
                SignalArg::Prehashed(hex),
                &ts,
                &proof_json,
            )
        };
        assert_eq!(
            prehashed(&hash_hex).unwrap(),
            serde_json::json!({ "verdict": "valid" })
        );
        // The same proof through the raw dialect is a retransmission.
        let dup =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &ts, &proof_json).unwrap();
        assert_eq!(dup, serde_json::json!({ "verdict": "duplicate" }));
        // Another message's hash: invalid, not an error.
        let other = registry_id::bytes_to_hex(&rln_signal::signal_hash(b"another"));
        assert_eq!(
            prehashed(&other).unwrap(),
            serde_json::json!({ "verdict": "invalid" })
        );
        // Malformed: non-canonical, short, or the raw bytes in the hash slot.
        for bad in ["ff".repeat(32), "ab".repeat(31), signal_hex, "zz".into()] {
            let err = prehashed(&bad).unwrap_err();
            assert_eq!(
                err.kind,
                ErrorKind::InvalidArgument,
                "{bad}: {}",
                err.message
            );
        }

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    #[test]
    fn root_window_miss_answers_invalid_and_nudges_the_refresher() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "bc".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"root-miss-check";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());
        let rlp = proof::generate_for_test(&[7u8; 32], signal, epoch, &rln_id);

        // Warm window WITHOUT the proof's root.
        roots::set_window_for_test(&registry, vec![[3u8; 32]], now_unix());
        roots::reset_nudge_for_test();
        let before = crate::worker::nudges_for_test();
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &(epoch * 600).to_string(),
            &rlp.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));
        assert_eq!(
            crate::worker::nudges_for_test(),
            before + 1,
            "a root miss must nudge"
        );

        // An in-window root that fails crypto is plain invalid — NO nudge.
        roots::set_window_for_test(&registry, vec![rlp.root()], now_unix());
        roots::reset_nudge_for_test();
        let before = crate::worker::nudges_for_test();
        let other = registry_id::bytes_to_hex(b"a-different-signal");
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &other,
            &(epoch * 600).to_string(),
            &rlp.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));
        assert_eq!(
            crate::worker::nudges_for_test(),
            before,
            "a crypto-invalid proof must not nudge"
        );
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // The application + epoch binding: a stale-epoch proof and a proof for a
    // DIFFERENT rln_identifier are both `invalid` (the window stays warm here
    // to prove the rejection comes from the binding, not the window).
    #[test]
    fn validate_proof_impl_rejects_stale_epoch_and_foreign_application() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "ba".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"binding-check";
        let signal_hex = registry_id::bytes_to_hex(signal);

        // Stale epoch: a message honestly stamped in an ancient epoch (with
        // its matching proof) can never fall in now ± tolerance.
        let stale = proof::generate_for_test(&[7u8; 32], signal, 1, &rln_id);
        let stale_ts = (600u64).to_string(); // a timestamp inside epoch 1
        roots::set_window_for_test(&registry, vec![stale.root()], now_unix());
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &stale_ts,
            &stale.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        // Foreign application: fresh epoch, but the proof binds another
        // rln_identifier than the verifying scope's.
        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());
        let foreign = proof::generate_for_test(&[7u8; 32], signal, epoch, &[8u8; 32]);
        roots::set_window_for_test(&registry, vec![foreign.root()], now_unix());
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &(epoch * 600).to_string(),
            &foreign.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // A carried epoch is authoritative but not self-certifying: rewrite the
    // wire "epoch" field to the verifier's current epoch (so it matches the
    // message timestamp and clears the gap window) while the proof's
    // external nullifier still reflects the OLD epoch it was actually
    // generated for — epoch_binding_holds' nullifier recomputation must
    // still catch the mismatch and reject.
    #[test]
    fn validate_proof_impl_rejects_tampered_carried_epoch() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "ca".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"tampered-epoch";
        let signal_hex = registry_id::bytes_to_hex(signal);

        // Generated for epoch 1 — its external_nullifier is bound to that
        // epoch, not to whatever the "epoch" field is later rewritten to.
        let rlp = proof::generate_for_test(&[7u8; 32], signal, 1, &rln_id);
        roots::set_window_for_test(&registry, vec![rlp.root()], now_unix());

        let now_epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());
        let mut epoch_bytes = [0u8; 32];
        epoch_bytes[..8].copy_from_slice(&now_epoch.to_le_bytes());
        let mut tampered = rlp.to_json();
        tampered["epoch"] = serde_json::json!(registry_id::bytes_to_hex(&epoch_bytes));

        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &(now_epoch * 600).to_string(),
            &tampered.to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // max_epoch_gap is a start() parameter, not a fixed constant: a proof
    // exactly at the configured gap still verifies, one epoch further does
    // not.
    #[test]
    fn validate_proof_impl_respects_configured_epoch_gap() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        // The `within` proof is accepted and logged; clear the shared log so it
        // reads `valid` rather than a `duplicate` left by a sibling verify test.
        nullifier_log::reset_for_test();
        let out = start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 2}"#).unwrap();
        assert_eq!(out["max_epoch_gap"], serde_json::json!(2));
        let registry = format!("logos:local:{}", "da".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"gap-check";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let now_epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        // Exactly at the configured gap → still valid. Distinct epochs (now−2
        // vs now−3) give the two proofs distinct external nullifiers, so the
        // `beyond` check never re-verifies the `within` nullifier. Each
        // message is stamped inside its proof's epoch, as an honest sender
        // would.
        let within = proof::generate_for_test(&[7u8; 32], signal, now_epoch - 2, &rln_id);
        roots::set_window_for_test(&registry, vec![within.root()], now_unix());
        let ok = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &((now_epoch - 2) * 600).to_string(),
            &within.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        // One epoch beyond the configured gap → rejected.
        let beyond = proof::generate_for_test(&[7u8; 32], signal, now_epoch - 3, &rln_id);
        roots::set_window_for_test(&registry, vec![beyond.root()], now_unix());
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &((now_epoch - 3) * 600).to_string(),
            &beyond.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // The spec MUST the timestamp argument exists for: the epoch the proof
    // spends must be the epoch the message claims. A fresh, zk-valid proof
    // correctly bound to ITS OWN epoch still reads `invalid` when the
    // message's timestamp names a different (also in-window) epoch.
    #[test]
    fn validate_proof_impl_requires_proof_epoch_to_match_timestamp() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 2}"#).unwrap();
        let registry = format!("logos:local:{}", "db".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"epoch-equality";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let now_epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        let rlp = proof::generate_for_test(&[7u8; 32], signal, now_epoch, &rln_id);
        roots::set_window_for_test(&registry, vec![rlp.root()], now_unix());
        let proof_json = rlp.to_json().to_string();

        // Message stamped one epoch earlier — inside the gap, so freshness
        // passes; the equality requirement is what rejects.
        let earlier = ((now_epoch - 1) * 600).to_string();
        let out = validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &earlier, &proof_json)
            .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        // The honest timestamp verifies.
        let honest = (now_epoch * 600).to_string();
        let ok =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &honest, &proof_json).unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        // Symmetric tamper: the proof's nullifier IS honestly bound to the
        // timestamp's epoch, but the carried "epoch" field was rewritten to a
        // different fresh epoch — the carried value must EQUAL the
        // timestamp's epoch, not merely be fresh.
        let bound = proof::generate_for_test(&[7u8; 32], signal, now_epoch - 1, &rln_id);
        roots::set_window_for_test(&registry, vec![bound.root()], now_unix());
        let mut rewritten = bound.to_json();
        rewritten["epoch"] = serde_json::json!(now_epoch);
        let out = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &signal_hex,
            &((now_epoch - 1) * 600).to_string(),
            &rewritten.to_string(),
        )
        .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    #[test]
    fn validate_proof_impl_reconstructs_mix_external_nullifier() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 10, "max_epoch_gap": 3}"#).unwrap();
        let registry = format!("logos:local:{}", "dc".repeat(32));
        let id = [9u8; 32];
        let scope = registry_id::bytes_to_hex(&id);
        let signal = b"mix packet";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let timestamp = now_unix();
        let epoch = timestamp / 10;
        let proof = proof::generate_for_test(&[7u8; 32], signal, epoch, &id);
        roots::set_window_for_test(&registry, vec![proof.root()], timestamp);
        let mut wire = proof.to_json();
        wire.as_object_mut().unwrap().remove("external_nullifier");
        let wire = wire.to_string();
        let time = timestamp.to_string();
        let wrong =
            validate_proof_impl(&registry, &"aa".repeat(32), &signal_hex, &time, &wire).unwrap();
        assert_eq!(wrong["verdict"], "invalid");
        assert!(wrong.get("external_nullifier").is_none());
        let wrong = validate_proof_impl(&registry, &scope, "00", &time, &wire).unwrap();
        assert_eq!(wrong["verdict"], "invalid");
        assert!(wrong.get("external_nullifier").is_none());
        let valid = validate_proof_impl(&registry, &scope, &signal_hex, &time, &wire).unwrap();
        assert_eq!(valid["verdict"], "valid");
        assert_eq!(
            valid["external_nullifier"],
            registry_id::bytes_to_hex(&proof.external_nullifier())
        );
        let duplicate = validate_proof_impl(&registry, &scope, &signal_hex, &time, &wire).unwrap();
        assert_eq!(duplicate["verdict"], "duplicate");
        assert_eq!(
            duplicate["external_nullifier"],
            registry_id::bytes_to_hex(&proof.external_nullifier())
        );
    }

    // An epoch-less proof (the decomposed spec shape may omit "epoch") is
    // resolved by the timestamp alone: the same proof verifies under the
    // timestamp naming its epoch and reads `invalid` under a neighboring
    // (still fresh) one — the expected external nullifier is recomputed from
    // the timestamp's epoch, never scanned for across the window.
    #[test]
    fn validate_proof_impl_resolves_epochless_proof_from_timestamp() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 2}"#).unwrap();
        let registry = format!("logos:local:{}", "dc".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let signal = b"epochless";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let now_epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        let rlp = proof::generate_for_test(&[7u8; 32], signal, now_epoch - 1, &rln_id);
        roots::set_window_for_test(&registry, vec![rlp.root()], now_unix());
        let mut json = rlp.to_json();
        json.as_object_mut().unwrap().remove("epoch");
        let proof_json = json.to_string();

        let neighbor = (now_epoch * 600).to_string();
        let out = validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &neighbor, &proof_json)
            .unwrap();
        assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));

        let honest = ((now_epoch - 1) * 600).to_string();
        let ok =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &honest, &proof_json).unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // A double-signal caught in-module: two proofs from ONE identity/slot over
    // different signals share a nullifier but split on share_x. The first
    // verifies `valid`; the second is a `rate_limit_violation` whose
    // `recovered_secret` is the offender's own seed-7 secret, reconstructed
    // from the two colliding shares. Serialized + reset like its neighbors, as
    // it and the sibling verify tests share the seed-7 / epoch-now nullifier.
    #[test]
    fn validate_proof_rate_limit_violation_recovers_secret() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "e1".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        let pa = proof::generate_for_test(&[7u8; 32], b"sig-A", epoch, &rln_id);
        let pb = proof::generate_for_test(&[7u8; 32], b"sig-B", epoch, &rln_id);
        // One identity + path ⇒ one root; pb shares it, so a single warm root
        // serves both.
        roots::set_window_for_test(&registry, vec![pa.root()], now_unix());

        let ts = (epoch * 600).to_string();
        let sig_a = registry_id::bytes_to_hex(b"sig-A");
        let first = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &sig_a,
            &ts,
            &pa.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(first, serde_json::json!({ "verdict": "valid" }));

        let sig_b = registry_id::bytes_to_hex(b"sig-B");
        let second = validate_proof_impl(
            &registry,
            &rln_id_hex,
            &sig_b,
            &ts,
            &pb.to_json().to_string(),
        )
        .unwrap();
        assert_eq!(second["verdict"], serde_json::json!("rate_limit_violation"));
        assert_eq!(
            second["recovered_secret"],
            serde_json::json!("3c87aa7480ec2cad022ef39c256ddb6e4fb083c7d4a0dfdc4eee891feda7a62b")
        );

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // Retransmission: the SAME proof + signal verified twice reads `valid` then
    // `duplicate` (equal share_x ⇒ no violation), and the duplicate reply
    // carries NO recovered_secret.
    #[test]
    fn validate_proof_duplicate_on_retransmission() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "e2".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        let p = proof::generate_for_test(&[7u8; 32], b"dup-sig", epoch, &rln_id);
        roots::set_window_for_test(&registry, vec![p.root()], now_unix());
        let ts = (epoch * 600).to_string();
        let sig = registry_id::bytes_to_hex(b"dup-sig");
        let proof_json = p.to_json().to_string();

        let first = validate_proof_impl(&registry, &rln_id_hex, &sig, &ts, &proof_json).unwrap();
        assert_eq!(first, serde_json::json!({ "verdict": "valid" }));

        let second = validate_proof_impl(&registry, &rln_id_hex, &sig, &ts, &proof_json).unwrap();
        assert_eq!(second["verdict"], serde_json::json!("duplicate"));
        assert!(second.get("recovered_secret").is_none());

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // Invalid proofs never touch the log: two wrong-signal verifies both read
    // `invalid` (not `duplicate`), and the correct signal afterward is `valid`
    // — proof that the failed attempts left the nullifier unrecorded.
    #[test]
    fn validate_proof_invalid_never_logs() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "e3".repeat(32));
        let rln_id = [9u8; 32];
        let rln_id_hex = registry_id::bytes_to_hex(&rln_id);
        let epoch = rate_limit::current_epoch(now_unix(), epoch_size().unwrap());

        let p = proof::generate_for_test(&[7u8; 32], b"correct-sig", epoch, &rln_id);
        roots::set_window_for_test(&registry, vec![p.root()], now_unix());
        let ts = (epoch * 600).to_string();
        let proof_json = p.to_json().to_string();

        let wrong = registry_id::bytes_to_hex(b"wrong-sig");
        for _ in 0..2 {
            let out =
                validate_proof_impl(&registry, &rln_id_hex, &wrong, &ts, &proof_json).unwrap();
            assert_eq!(out, serde_json::json!({ "verdict": "invalid" }));
        }

        let correct = registry_id::bytes_to_hex(b"correct-sig");
        let ok = validate_proof_impl(&registry, &rln_id_hex, &correct, &ts, &proof_json).unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // get_epoch_quota: a consistent {epoch_index, rate_limit, remaining}
    // snapshot from local state.
    #[test]
    fn epoch_quota_snapshot_tracks_spent_slots() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let dir = std::env::temp_dir().join(format!("rln-ms-quota-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(dir.clone()).expect("test store open");

        let registry = format!("logos:local:{}", "aa".repeat(32));
        let rln_id = "ef".repeat(32);

        let now = now_unix();
        let ts = now.to_string();

        // No membership yet → a zero-budget SNAPSHOT, not an error (spec
        // SHALL): rate_limit 0 is the no-usable-membership signal, so it can
        // never be confused with an exhausted budget.
        let q = get_epoch_quota_impl(Ok(store.clone()), &registry, &rln_id, &ts).unwrap();
        assert_eq!(q["rate_limit"], 0, "got: {q}");
        assert_eq!(q["remaining"], 0, "got: {q}");
        assert!(q["epoch_index"].as_u64().is_some(), "got: {q}");

        // Seed an ACTIVE membership registered under this scope.
        let commitment = [0x77u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        store.unlock("pw").unwrap();
        seed_membership(
            &store,
            &hash,
            &registry,
            &registry_id::bytes_to_hex(&commitment),
            &rln_id,
            &"88".repeat(32),
            MembershipState::Active,
            4,
            100,
        );

        let fresh = get_epoch_quota_impl(Ok(store.clone()), &registry, &rln_id, &ts).unwrap();
        assert_eq!(fresh["rate_limit"], serde_json::json!(100));
        assert_eq!(fresh["remaining"], serde_json::json!(100));
        let epoch_index = fresh["epoch_index"].as_u64().expect("numeric epoch index");
        assert_eq!(epoch_index, now / 600);

        // Spend two slots in the CURRENT epoch; the snapshot pairs the same
        // index with the decremented budget.
        store
            .reserve_message_id(&hash, &rln_id, epoch_index, epoch_index, 100, 600)
            .unwrap();
        store
            .reserve_message_id(&hash, &rln_id, epoch_index, epoch_index, 100, 600)
            .unwrap();
        let spent = get_epoch_quota_impl(Ok(store.clone()), &registry, &rln_id, &ts).unwrap();
        assert_eq!(spent["epoch_index"], serde_json::json!(epoch_index));
        assert_eq!(spent["remaining"], serde_json::json!(98));

        // The queried epoch is fixed by the timestamp (spec): the NEXT epoch,
        // still inside the default gap, keeps its own untouched budget.
        let next_ts = ((epoch_index + 1) * 600).to_string();
        let next = get_epoch_quota_impl(Ok(store.clone()), &registry, &rln_id, &next_ts).unwrap();
        assert_eq!(next["epoch_index"], serde_json::json!(epoch_index + 1));
        assert_eq!(next["rate_limit"], serde_json::json!(100));
        assert_eq!(next["remaining"], serde_json::json!(100));

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // The quota read enforces generate_proof's freshness window on the
    // supplied timestamp (spec: fail permanent, letting a consumer test a
    // timestamp before committing to it), and a malformed timestamp is a
    // plain invalid_argument. Both reject before any membership lookup.
    #[test]
    fn epoch_quota_rejects_bad_or_out_of_window_timestamp() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "ae".repeat(32));
        let rln_id = "ef".repeat(32);

        let err = get_epoch_quota_impl(no_store(), &registry, &rln_id, "not-a-number").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);

        // Epoch 0 is far below now − max_epoch_gap: refused with the same
        // permanent-class error generate_proof raises for the timestamp.
        let err = get_epoch_quota_impl(no_store(), &registry, &rln_id, "0").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
        assert_eq!(err.kind.class(), "permanent");
        assert!(err.message.contains("epoch window"), "got: {}", err.message);
    }

    // The readiness gate runs before input validation, so start() first,
    // then probe the malformed inputs.
    #[test]
    fn validate_proof_impl_rejects_malformed_input() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "cd".repeat(32));
        let rln_id_hex = "ef".repeat(32);
        let ts = now_unix().to_string();
        let e1 = validate_proof_impl(&registry, &rln_id_hex, "zz", &ts, "{}").unwrap_err();
        assert_eq!(e1.kind, ErrorKind::InvalidArgument);
        let e2 = validate_proof_impl(&registry, &rln_id_hex, "00", &ts, "not json").unwrap_err();
        assert_eq!(e2.kind, ErrorKind::InvalidArgument);
        // A non-integer timestamp is malformed input too, on both methods.
        let e3 = validate_proof_impl(&registry, &rln_id_hex, "00", "later", "{}").unwrap_err();
        assert_eq!(e3.kind, ErrorKind::InvalidArgument);
        assert!(e3.message.contains("timestamp"), "got: {}", e3.message);
        let e4 = get_epoch_quota_impl(no_store(), &registry, &rln_id_hex, "later").unwrap_err();
        assert_eq!(e4.kind, ErrorKind::InvalidArgument);
        assert!(e4.message.contains("timestamp"), "got: {}", e4.message);
    }

    #[test]
    fn generate_proof_impl_rejects_bad_signal_before_touching_state() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let registry = format!("logos:local:{}", "cd".repeat(32));
        let rln_id_hex = "ef".repeat(32);
        let err = generate_proof_impl(
            no_store(),
            &registry,
            &rln_id_hex,
            "nothex",
            &now_unix().to_string(),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
    }

    // The path-cache miss/hit contract: cargo tests never link the real
    // lez module, so `get_merkle_proof` is a DEAD TRANSPORT (no lp
    // client) — provider_failure proves a registry read was attempted. A
    // pre-filled cache (synthetic zero-sibling depth-20 path) must let
    // generate_proof succeed with ZERO registry I/O.
    // The cache sits outside the authenticated surface, so an `active` row
    // with no leaf_index is reachable by tampering. Leaf 0 is a valid leaf:
    // proving against it would spend a message-id slot on a proof no
    // verifier accepts, so the refusal must come BEFORE the reservation.
    #[test]
    fn generate_proof_impl_refuses_a_usable_row_without_a_leaf_index() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-no-leaf-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp
            .unlock_keystore("pw".into())
            .contains(r#""unlocked":true"#));

        let reg = format!("logos:local:{}", "ab".repeat(32));
        let rln_id_hex = "ef".repeat(32);
        let (commitment_hex, secret_hex) = proof::generate_identity().expect("test identity");
        let commitment =
            registry_id::hex_to_bytes32(&commitment_hex).expect("generated commitment is 32 bytes");
        let hash = registry_id::membership_hash(&reg, &commitment);

        seed_membership(
            &store,
            &hash,
            &reg,
            &commitment_hex,
            &rln_id_hex,
            &secret_hex,
            MembershipState::Active,
            5,
            300,
        );
        // A warm path for leaf 0 would be served if the code defaulted.
        path_cache::set_path_for_test(
            &hash,
            vec!["00".repeat(32); proof::RLN_TREE_DEPTH],
            vec![0u8; proof::RLN_TREE_DEPTH],
            0,
        );
        store
            .update_cache(&hash, |m| m.leaf_index = None)
            .expect("clear the leaf");

        let err = generate_proof_impl(Ok(store), &reg, &rln_id_hex, "aa", &now_unix().to_string())
            .expect_err("a usable row without a leaf must not prove against leaf 0");
        assert_eq!(
            err.kind,
            ErrorKind::UnknownMembership,
            "got: {}",
            err.message
        );
        assert!(err.message.contains("leaf_index"), "got: {}", err.message);

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_proof_impl_serves_cached_path_with_zero_registry_io() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-path-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp
            .unlock_keystore("pw".into())
            .contains(r#""unlocked":true"#));

        let reg = format!("logos:local:{}", "ab".repeat(32));
        let rln_id_hex = "ef".repeat(32);
        let (commitment_hex, secret_hex) = proof::generate_identity().expect("test identity");
        let commitment =
            registry_id::hex_to_bytes32(&commitment_hex).expect("generated commitment is 32 bytes");
        let hash = registry_id::membership_hash(&reg, &commitment);
        let leaf_index = 5u64;

        seed_membership(
            &store,
            &hash,
            &reg,
            &commitment_hex,
            &rln_id_hex,
            &secret_hex,
            MembershipState::Active,
            leaf_index,
            300,
        );

        let signal_hex = "aa";

        // MISS: cold cache falls back to the registry — dead transport, so
        // provider_failure proves a real read was attempted.
        let miss = generate_proof_impl(
            Ok(store.clone()),
            &reg,
            &rln_id_hex,
            signal_hex,
            &now_unix().to_string(),
        )
        .unwrap_err();
        assert_eq!(
            miss.kind,
            ErrorKind::ProviderFailure,
            "a cold cache must fall back to the registry: {}",
            miss.message
        );

        // HIT: pre-fill the cache — generate_proof must now succeed without
        // ever calling the dead transport.
        path_cache::set_path_for_test(
            &hash,
            vec!["00".repeat(32); proof::RLN_TREE_DEPTH],
            vec![0u8; proof::RLN_TREE_DEPTH],
            leaf_index,
        );
        let out = generate_proof_impl(
            Ok(store),
            &reg,
            &rln_id_hex,
            signal_hex,
            &now_unix().to_string(),
        )
        .expect("a warm cache entry needs no registry call");
        assert!(
            out.get("proof").and_then(|v| v.as_str()).is_some(),
            "got: {out}"
        );
        assert!(
            out.get("root").and_then(|v| v.as_str()).is_some(),
            "got: {out}"
        );
        assert_eq!(
            out.get("message_id").and_then(|v| v.as_u64()),
            Some(0),
            "first allocation on a fresh (rln_identifier, epoch): {out}"
        );
        assert_eq!(
            out.get("membership_hash").and_then(|v| v.as_str()),
            Some(hash.as_str())
        );

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // generate_proof_prehashed is generate_proof over the consumer-hashed x:
    // the proof it mints validates through BOTH validate dialects — with the
    // hash and with the original bytes — and a malformed hash is refused
    // before any slot is reserved.
    #[test]
    fn generate_proof_prehashed_mints_a_proof_both_dialects_validate() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        nullifier_log::reset_for_test();
        let dir =
            std::env::temp_dir().join(format!("rln-ms-prehashed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp
            .unlock_keystore("pw".into())
            .contains(r#""unlocked":true"#));

        let reg = format!("logos:local:{}", "ac".repeat(32));
        let rln_id_hex = "ee".repeat(32);
        let (commitment_hex, secret_hex) = proof::generate_identity().expect("test identity");
        let commitment =
            registry_id::hex_to_bytes32(&commitment_hex).expect("generated commitment is 32 bytes");
        let hash = registry_id::membership_hash(&reg, &commitment);
        let leaf_index = 5u64;
        seed_membership(
            &store,
            &hash,
            &reg,
            &commitment_hex,
            &rln_id_hex,
            &secret_hex,
            MembershipState::Active,
            leaf_index,
            300,
        );
        path_cache::set_path_for_test(
            &hash,
            vec!["00".repeat(32); proof::RLN_TREE_DEPTH],
            vec![0u8; proof::RLN_TREE_DEPTH],
            leaf_index,
        );

        let signal = b"payload bytes, then a content topic, then eight timestamp bytes";
        let signal_hex = registry_id::bytes_to_hex(signal);
        let hash_hex = registry_id::bytes_to_hex(&rln_signal::signal_hash(signal));
        let ts = now_unix().to_string();

        let bad = generate_proof_with(
            Ok(store.clone()),
            &reg,
            &rln_id_hex,
            SignalArg::Prehashed(&"ff".repeat(32)),
            &ts,
        )
        .unwrap_err();
        assert_eq!(bad.kind, ErrorKind::InvalidArgument, "got: {}", bad.message);

        let out = generate_proof_with(
            Ok(store),
            &reg,
            &rln_id_hex,
            SignalArg::Prehashed(&hash_hex),
            &ts,
        )
        .expect("prehashed generate over a warm cache");
        assert_eq!(out["share_x"].as_str().unwrap(), hash_hex, "got: {out}");
        assert_eq!(
            out["message_id"].as_u64(),
            Some(0),
            "the refused hash must not have spent a slot: {out}"
        );
        let root = registry_id::hex_to_bytes32(out["root"].as_str().unwrap()).expect("root");
        roots::set_window_for_test(&reg, vec![root], now_unix());
        let proof_json = out.to_string();

        let raw = validate_proof_impl(&reg, &rln_id_hex, &signal_hex, &ts, &proof_json).unwrap();
        assert_eq!(raw, serde_json::json!({ "verdict": "valid" }));
        let pre = validate_proof_with(
            &reg,
            &rln_id_hex,
            SignalArg::Prehashed(&hash_hex),
            &ts,
            &proof_json,
        )
        .unwrap();
        assert_eq!(pre, serde_json::json!({ "verdict": "duplicate" }));

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The proof's epoch follows the CALLER's timestamp, not the module
    // clock: an in-window past timestamp yields a proof bound to that past
    // epoch.
    #[test]
    fn generate_proof_impl_derives_epoch_from_supplied_timestamp() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-epoch-src-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // start() BEFORE the membership exists → tracked is empty, so the
        // warm-up is a harmless one-shot and never races the cache below.
        start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 1}"#).unwrap();

        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp
            .unlock_keystore("pw".into())
            .contains(r#""unlocked":true"#));

        let reg = format!("logos:local:{}", "1a".repeat(32));
        let rln_id_hex = "2b".repeat(32);
        let (commitment_hex, secret_hex) = proof::generate_identity().expect("test identity");
        let commitment = registry_id::hex_to_bytes32(&commitment_hex).unwrap();
        let hash = registry_id::membership_hash(&reg, &commitment);
        let leaf_index = 3u64;
        seed_membership(
            &store,
            &hash,
            &reg,
            &commitment_hex,
            &rln_id_hex,
            &secret_hex,
            MembershipState::Active,
            leaf_index,
            300,
        );
        path_cache::set_path_for_test(
            &hash,
            vec!["00".repeat(32); proof::RLN_TREE_DEPTH],
            vec![0u8; proof::RLN_TREE_DEPTH],
            leaf_index,
        );

        let size = epoch_size().unwrap();
        let now_epoch = rate_limit::current_epoch(now_unix(), size);
        // One epoch in the past — inside now ± max_epoch_gap (=1).
        let ts = (now_unix() - size).to_string();
        let out = generate_proof_impl(Ok(store), &reg, &rln_id_hex, "aa", &ts)
            .expect("a past-but-in-window timestamp still proves");
        assert_eq!(
            out.get("epoch_index").and_then(|v| v.as_u64()),
            Some(now_epoch - 1),
            "epoch must derive from the supplied timestamp, not the module clock: {out}"
        );
        // The full canonical blob; its leading segment is the bare proof[128].
        let canonical = out
            .get("proof_canonical")
            .and_then(|v| v.as_str())
            .expect("reply carries proof_canonical");
        assert_eq!(canonical.len(), 289 * 2);
        assert!(canonical.starts_with(out["proof"].as_str().unwrap()));

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A timestamp whose epoch is outside now ± max_epoch_gap is rejected at
    // generation (invalid_argument) before any membership is selected.
    #[test]
    fn generate_proof_impl_rejects_timestamp_outside_epoch_window() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        reset_config_for_test();
        start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 1}"#).unwrap();
        let registry = format!("logos:local:{}", "3c".repeat(32));
        let rln_id_hex = "4d".repeat(32);
        // 100 epochs in the past — far outside now ± 1.
        let stale = (now_unix() - 100 * 600).to_string();
        let err =
            generate_proof_impl(no_store(), &registry, &rln_id_hex, "aa", &stale).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
        assert!(err.message.contains("window"), "got: {}", err.message);
        // Leave CONFIG set (per the suite convention): a trailing reset would
        // strand another serialized test that reads epoch_size() from ambient
        // config with NOT_READY.
    }
}
