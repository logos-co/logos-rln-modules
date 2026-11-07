//! Registration: RegistryOptions parsing, the per-scope in-flight claim, the
//! funded and delegated submits, and the fire-and-record callbacks that land
//! their replies on the record.

use std::sync::{Arc, Mutex, Weak};

use crate::config::{epoch_params_for, DEFAULT_RATE_LIMIT};
use crate::delegated::{delegated_request_args, DelegatedOptions};
use crate::error::{ApiError, ErrorKind};
use crate::lifecycle::{self, note_granted_by, MembershipState, StoredCredential};
use crate::poller;
use crate::proof;
use crate::proof_api::proof_error;
use crate::provider;
use crate::registry_id;
use crate::scope::{backend_of, parse_scope, records_for_registry, scope_matches};
use crate::sealed_store::{self, store::Store};
use crate::util::{lock, now_unix};
use crate::views;

/// The wire's options_json: the spec RegistryOptions ARRAY of {"key","value"}
/// string pairs (char* pairs, so a non-string value is a type error, never a
/// coercion; duplicate keys are rejected). Returns the rate_limit (defaulted
/// when absent) and the remaining pairs as a flat object.
pub(crate) fn parse_registry_options(options_json: &str) -> Result<(u64, serde_json::Value), ApiError> {
    let trimmed = options_json.trim();
    let entries = if trimmed.is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(serde_json::Value::Array(a)) => a,
            Ok(_) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "options_json must be a RegistryOptions array of {\"key\",\"value\"} string pairs",
                ))
            }
            Err(e) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    &format!("options_json: {e}"),
                ))
            }
        }
    };
    let mut map = serde_json::Map::new();
    for entry in &entries {
        let key = match entry.get("key").and_then(|k| k.as_str()) {
            Some(k) if !k.is_empty() => k,
            _ => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "every RegistryOptions entry needs a string \"key\"",
                ))
            }
        };
        let value = match entry.get("value").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    &format!("RegistryOptions value for '{key}' must be a string (char* pair)"),
                ))
            }
        };
        let prior = map.insert(key.to_string(), serde_json::Value::String(value.to_string()));
        if prior.is_some() {
            return Err(ApiError::new(
                ErrorKind::InvalidArgument,
                &format!("duplicate RegistryOptions key '{key}'"),
            ));
        }
    }
    // A present-but-blank value falls back to the default, like absent.
    let raw = map.remove("rate_limit");
    let given = raw.as_ref().and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let rate_limit = match given {
        None => DEFAULT_RATE_LIMIT,
        Some(s) => s.parse::<u64>().ok().filter(|r| *r > 0).ok_or_else(|| {
            ApiError::new(
                ErrorKind::InvalidArgument,
                "rate_limit option must be a positive decimal string",
            )
        })?,
    };
    Ok((rate_limit, serde_json::Value::Object(map)))
}

/// The spec's failed-submission retryable flag: transient, not-ready, and
/// provider-side failures MAY succeed on a fresh register; anything else
/// needs the caller to change something first.
pub(crate) fn is_retryable_submit_error(e: &ApiError) -> bool {
    matches!(e.kind, ErrorKind::Transient | ErrorKind::NotReady | ErrorKind::ProviderFailure)
}

/// The registry module's refusal to submit, from a register_member reply
/// `{"error":"<kind>: <reason>"}`; None for an accepted submission.
pub(crate) fn register_refusal(reply: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(reply)
        .ok()?
        .get("error")?
        .as_str()
        .map(str::to_owned)
}

/// Fire-and-record tail of a funded submit: record the register_member reply,
/// or mark the record failed. Runs on the module's event loop after register
/// returns; `store` is a Weak capture of the store the record was inserted
/// into — gone (re-context replaced it) means there is nothing to record on.
pub(crate) fn funded_submit_callback(store: Weak<Store>, hash: String) -> provider::RegisterCallback {
    Box::new(move |result| {
        let update = match store.upgrade() {
            Some(store) => store.update_cache(&hash, |m| match &result {
                // The lez module refused to submit (an argument or balance the
                // program would reject). Nothing was sent: fail now with its
                // reason instead of waiting out the confirmation window.
                Ok(reply) if register_refusal(reply).is_some() => {
                    let why = register_refusal(reply).unwrap_or_default();
                    m.record_async_submit_error(&why, false)
                }
                // A reply that lands after the poller confirmed the record
                // from the registry has nothing authoritative to add: the
                // estimate must not replace the chain's leaf.
                Ok(_) if m.state != MembershipState::Pending => {}
                Ok(reply) => {
                    m.tx_result = Some(reply.clone());
                    // The reply's leaf_index is a pre-submit ESTIMATE; recorded
                    // for observability, authoritative only after the poller's
                    // read-back.
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(reply) {
                        if let Some(leaf) = v.get("leaf_index").and_then(|x| x.as_u64()) {
                            m.leaf_index = Some(leaf);
                        }
                    }
                }
                Err(e) => m.record_async_submit_error(&e.message, is_retryable_submit_error(e)),
            }),
            None => Err(ApiError::internal("store closed before the submit callback landed")),
        };
        if let Err(e) = update {
            eprintln!("membership register callback: {}", e.message);
        }
    })
}

/// The failure reason of a registration the poller gave up on before the
/// registry showed it.
pub(crate) const WINDOW_ELAPSED: &str = "confirmation_window_elapsed";

/// How long a delegated registration may stay unconfirmed: the gifter
/// client's whole budget, then the funded window for the registry to show
/// what the allocator submitted at the very end of it.
pub(crate) fn delegated_confirm_deadline(submitted_at: u64) -> u64 {
    submitted_at + provider::GIFTER_REQUEST_TIMEOUT.as_secs() + lifecycle::CONFIRMATION_WINDOW_SECS
}

/// Fire-and-record tail of a delegated submit: a gifter {"error":…} marks
/// the record failed (and says so on `membership_state_changed`), as does a
/// grant on a registry other than the scope's (the poller would never see
/// it); a grant records the leaf estimate and a funded-style tx_result
/// envelope on a pending record, and re-opens one the window already failed
/// — the gift is on the chain, so the poller confirms it. A record the
/// registry already confirmed keeps its authoritative leaf. Confirmation
/// stays the poller's registry read-back.
pub(crate) fn delegated_submit_callback(
    store: Weak<Store>,
    hash: String,
    registry_account: String,
) -> provider::RegisterCallback {
    Box::new(move |result| {
        let Some(store) = store.upgrade() else {
            eprintln!("membership delegated callback: store closed before the submit callback landed");
            return;
        };
        let before = store.membership(&hash);
        let mut reopened = false;
        let update = store.update_cache(&hash, |m| match &result {
            Ok(reply) => match serde_json::from_str::<serde_json::Value>(reply) {
                Ok(v) => {
                    let granted_elsewhere = v
                        .get("config_account")
                        .and_then(|x| x.as_str())
                        .filter(|got| !got.eq_ignore_ascii_case(&registry_account))
                        .map(|got| format!("registered on {got}, not {registry_account}"));
                    let error = v
                        .get("error")
                        .map(|e| e.as_str().map(String::from).unwrap_or_else(|| e.to_string()))
                        .or(granted_elsewhere);
                    if let Some(msg) = error {
                        // A late gifter rejection must not overwrite a state
                        // the poller already confirmed from the registry
                        // (authoritative). Only a still-pending record fails.
                        if m.state == MembershipState::Pending {
                            m.state = MembershipState::Failed;
                            m.failed_reason = Some(format!("gifter_failed: {msg}"));
                        }
                        return;
                    }
                    // Who granted is bookkeeping, whatever the record's state:
                    // the poller may have confirmed the gift from the registry
                    // before this reply arrived.
                    note_granted_by(&hash, &v);
                    match m.state {
                        MembershipState::Pending => {}
                        MembershipState::Failed
                            if m.failed_reason.as_deref() == Some(WINDOW_ELAPSED) =>
                        {
                            m.state = MembershipState::Pending;
                            m.failed_reason = None;
                            m.retryable = None;
                            reopened = true;
                        }
                        _ => return,
                    }
                    if let Some(leaf) = v.get("leaf_index").and_then(|x| x.as_u64()) {
                        m.leaf_index = Some(leaf);
                    }
                    let tx = v.get("tx_hash").and_then(|x| x.as_str()).unwrap_or("");
                    let inner = serde_json::json!(
                        {"error": "", "secrets": [], "success": true, "tx_hash": tx})
                    .to_string();
                    m.tx_result = Some(
                        serde_json::json!(
                            {"leaf_index": m.leaf_index.unwrap_or(0), "pending": true, "tx_result": inner})
                        .to_string(),
                    );
                }
                Err(parse) => {
                    // The record stays PENDING for the poller's registry
                    // read-back, but the operator should see the garbage.
                    eprintln!(
                        "membership delegated callback: unparseable gifter reply ({parse}): {reply}"
                    );
                    m.tx_result = Some(reply.clone());
                }
            },
            Err(e) => m.record_async_submit_error(&e.message, is_retryable_submit_error(e)),
        });
        let prior = match update {
            Ok(prior) => prior,
            Err(e) => {
                eprintln!("membership delegated callback: {}", e.message);
                return;
            }
        };
        if reopened {
            poller::ensure_running();
        }
        if let (Some(before), Some(after)) = (before, store.membership(&hash)) {
            lifecycle::emit_transition(&hash, &before, prior, after.cache.state);
        }
    })
}

/// In-flight register claims by (canonical registry, rln id): the idempotency
/// scan and the insert are separated by a provider round-trip (up to ~70s), so
/// without a claim two concurrent register(scope) calls double-mint. The loser
/// errors transient and retries into the short-circuit.
pub(crate) static REGISTER_IN_FLIGHT: Mutex<Option<std::collections::HashSet<(String, String)>>> =
    Mutex::new(None);

pub(crate) struct RegisterClaim(String, String);

impl RegisterClaim {
    /// Taken BEFORE argument validation, so any test that reaches
    /// `register_impl` contends on this process-global set: tests that do not
    /// serialize on `TEST_GLOBAL_LOCK` must use a scope of their own, or a
    /// concurrent registration's claim surfaces as their result.
    pub(crate) fn take(registry: &str, rln_id_hex: &str) -> Result<RegisterClaim, ApiError> {
        let mut set = lock(&REGISTER_IN_FLIGHT);
        let set = set.get_or_insert_with(std::collections::HashSet::new);
        if !set.insert((registry.to_string(), rln_id_hex.to_string())) {
            return Err(ApiError::new(
                ErrorKind::ProviderFailure,
                "a registration for this scope is already in flight — retry to observe its result",
            ));
        }
        Ok(RegisterClaim(registry.to_string(), rln_id_hex.to_string()))
    }
}

impl Drop for RegisterClaim {
    fn drop(&mut self) {
        if let Some(set) = lock(&REGISTER_IN_FLIGHT).as_mut() {
            set.remove(&(self.0.clone(), self.1.clone()));
        }
    }
}

/// Spec register(): generate the identity credential INSIDE the module,
/// persist it encrypted, and submit its rate commitment — returning the
/// public Pending membership immediately. Idempotent PER SCOPE: the scope's
/// live membership short-circuits. Submission is fire-and-record (the async
/// callback lands on the module's event loop after this returns); the store
/// lock is NEVER held across a provider call.
pub(crate) fn register_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    options_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    // "delegated":"true" selects delegated registration via the RLN
    // Membership Allocation Protocol (the .lidl documents the option
    // vocabulary). Validated up front so a malformed request never mints a
    // credential.
    let (rate_limit, opts) = parse_registry_options(options_json)?;
    let delegated = DelegatedOptions::from_registry_options(&opts)?;
    register_scoped(store, &registry, &rln_id_hex, rate_limit, delegated)
}

/// The registration itself, on an ALREADY-PARSED scope and options:
/// `delegated` = `None` for a funded registration.
///
/// Split from `register_impl` so an in-module caller can register under an
/// EMPTY rln_identifier, which the wire deliberately refuses (the spec says
/// the module holds no default scope, so a caller must name one). An empty
/// identifier is not a missing value here, it is a registry-wide membership:
/// `scope_matches` already treats such a record as backing every application
/// on its registry, and `proof::generate` takes the identifier from the
/// REQUEST rather than from the credential. One is therefore enough for a
/// node that does not yet know which applications will use it — which is what
/// provisioning at start() needs, since `start`'s config names registries and
/// no scopes.
pub(crate) fn register_scoped(
    store: Result<Arc<Store>, ApiError>,
    registry: &registry_id::CanonicalRegistryId,
    rln_id_hex: &str,
    rate_limit: u64,
    delegated: Option<DelegatedOptions>,
) -> Result<serde_json::Value, ApiError> {
    let registry = registry.clone();
    let rln_id_hex = rln_id_hex.to_string();
    let backend = backend_of(&registry)?;
    // Claimed for the whole dispatch (RAII): the live-record scan below is
    // only sound while no other register for the same scope is in flight.
    let _claim = RegisterClaim::take(&registry.canonical, &rln_id_hex)?;

    // Idempotent PER SCOPE: a LIVE (pending/active/grace_period) record for
    // this scope short-circuits; terminal states (failed, expired, erased)
    // never block a fresh registration. A DIFFERENT application on the same
    // registry gets its own membership (dedicated budget, isolated slashing
    // blast radius); one membership can still back many applications at
    // proof time (see scope_candidates).
    let store = store?;
    let records = records_for_registry(&store, &registry);
    if let Some(rec) = records
        .iter()
        .find(|r| !r.quarantined && r.cache.state.is_live() && scope_matches(r, &rln_id_hex))
    {
        let mismatch = rec.cache.rate_limit != Some(rate_limit);
        // A live membership bound to a DIFFERENT epoch size can never reserve
        // under the current config (Permanent), yet register short-circuits
        // to it forever — surface the bind. Skipped before start() configures.
        let bound = rec.alloc.epoch_size_sec;
        let epoch_mismatch = epoch_params_for(&registry.canonical)
            .is_ok_and(|(size, _)| bound != 0 && bound != size);
        return Ok(views::public_membership(&rec.hash, rec, false, mismatch, epoch_mismatch));
    }

    // Fast-fail a rate_limit outside the registry's bounds BEFORE minting a
    // credential (spec: above max_rate_limit SHALL fail). An unreadable
    // registry skips the pre-check — it enforces its own bounds at
    // submission.
    match backend.registry.get_registry_bounds(&registry) {
        Ok(bounds) => {
            let max = bounds.get("max_rate_limit").and_then(|x| x.as_u64());
            let min = bounds.get("min_rate_limit").and_then(|x| x.as_u64());
            if max.is_some_and(|m| rate_limit > m) || min.is_some_and(|m| rate_limit < m) {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    &format!(
                        "rate_limit {rate_limit} outside registry bounds [{}, {}]",
                        min.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                        max.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                    ),
                ));
            }
        }
        Err(e) => eprintln!("register: bounds pre-check skipped: {}", e.message),
    }

    // Generate the identity credential in-module; the secret is encrypted into
    // the keystore and never returned across this interface.
    let (commitment_hex, secret_hash_hex) = proof::generate_identity().map_err(proof_error)?;
    let commitment = registry_id::hex_to_bytes32(&commitment_hex)
        .ok_or_else(|| ApiError::internal("generated commitment is not 32 bytes"))?;
    let hash = registry_id::membership_hash(&registry.canonical, &commitment);
    let credential = StoredCredential {
        identity_commitment: commitment_hex.clone(),
        identity_secret_hash: secret_hash_hex,
        registry_id: registry.canonical.clone(),
    };

    // Pending record FIRST (an interrupted submit still leaves an auditable
    // record the poller will resolve), then the async submit, whose callback
    // lands on the module's event loop after this handler has returned. `insert`
    // owns the Pending cache row and the empty allocation ledger
    // (allocations, the epoch-size binding, and the floor start unset; the
    // binding and floor are adopted at the first successful reservation —
    // registration doesn't know the app's final epoch size).
    let identity = sealed_store::format::IdentityBlock {
        registry_id: registry.canonical.clone(),
        rln_identifier: rln_id_hex.clone(),
        identity_commitment: commitment_hex.clone(),
        submitted_at: now_unix(),
    };
    store.insert(&hash, identity, &credential, rate_limit)?;
    if delegated.is_some() {
        let deadline = delegated_confirm_deadline(now_unix());
        store.update_cache(&hash, |m| m.confirm_deadline = Some(deadline))?;
    }

    let submit = match &delegated {
        Some(d) => provider::gifter_request_async(
            &delegated_request_args(d, &commitment_hex, rate_limit, &registry.account),
            delegated_submit_callback(Arc::downgrade(&store), hash.clone(), registry.account.clone()),
        ),
        None => backend.registry.register_async(
            &registry,
            &commitment_hex,
            rate_limit,
            funded_submit_callback(Arc::downgrade(&store), hash.clone()),
        ),
    };
    if let Err(e) = submit {
        // Synchronous submission failure (bad options, no client): the
        // record goes Failed immediately and the error surfaces.
        let retryable = is_retryable_submit_error(&e);
        store.update_cache(&hash, |m| m.mark_submit_failed(&e.message, retryable))?;
        return Err(e);
    }
    poller::ensure_running();

    let record = store
        .membership(&hash)
        .ok_or_else(|| ApiError::internal("record vanished after insert"))?;
    Ok(views::public_membership(&hash, &record, false, false, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::LiblogosRlnModule;
    use crate::test_support::{imp_with_store, opts_arr, seed_membership, TEST_GLOBAL_LOCK};
    use crate::LogosRlnModuleImpl;

    // The submit replies land after the poller may already have confirmed
    // the record from the registry: neither the funded estimate nor the
    // gifter's leaf replaces the chain's, and a gift that arrives after the
    // window failed its record re-opens it for the poller.
    #[test]
    fn late_submit_replies_respect_the_registry_and_reopen_a_window_failed_gift() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-late-reply-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "6f".repeat(32));
        let account = "6f".repeat(32);
        // Confirmed by the poller: Active at the chain's leaf 7.
        seed_membership(&store, "ha", &registry, &"46".repeat(32), "", &"f8".repeat(32), MembershipState::Active, 7, 100);
        funded_submit_callback(Arc::downgrade(&store), "ha".into())(Ok(
            r#"{"leaf_index":3,"pending":true,"tx_result":"{}"}"#.to_string(),
        ));
        let rec = store.membership("ha").unwrap();
        assert_eq!((rec.cache.state, rec.cache.leaf_index), (MembershipState::Active, Some(7)), "funded estimate kept out");
        delegated_submit_callback(Arc::downgrade(&store), "ha".into(), account.clone())(Ok(
            format!(r#"{{"leaf_index":3,"gifterPeerId":"p","config_account":"{account}"}}"#),
        ));
        let rec = store.membership("ha").unwrap();
        assert_eq!((rec.cache.state, rec.cache.leaf_index), (MembershipState::Active, Some(7)), "gifter leaf kept out");

        // The window gave up on a gift; the grant arrives later.
        seed_membership(&store, "hg", &registry, &"47".repeat(32), "", &"f9".repeat(32), MembershipState::Failed, 0, 100);
        store.update_cache("hg", |m| { m.failed_reason = Some(WINDOW_ELAPSED.into()); m.retryable = Some(true); }).unwrap();
        delegated_submit_callback(Arc::downgrade(&store), "hg".into(), account.clone())(Ok(
            format!(r#"{{"leaf_index":9,"gifterPeerId":"p","discovered":true,"config_account":"{account}"}}"#),
        ));
        let rec = store.membership("hg").unwrap();
        assert_eq!(rec.cache.state, MembershipState::Pending, "re-opened for the poller: {:?}", rec.cache.failed_reason);
        assert_eq!(rec.cache.leaf_index, Some(9));
        assert!(rec.cache.failed_reason.is_none() && rec.cache.retryable.is_none());
        assert_eq!(lifecycle::granted_by("hg").as_deref(), Some("p (discovered)"));

        // A record failed for another reason stays failed.
        seed_membership(&store, "hf", &registry, &"48".repeat(32), "", &"fa".repeat(32), MembershipState::Failed, 0, 100);
        store.update_cache("hf", |m| m.failed_reason = Some("gifter_failed: refused".into())).unwrap();
        delegated_submit_callback(Arc::downgrade(&store), "hf".into(), account)(Ok(
            r#"{"leaf_index":9,"gifterPeerId":"p"}"#.to_string(),
        ));
        assert_eq!(store.membership("hf").unwrap().cache.state, MembershipState::Failed);

        // The poller's writes yield to a fresher writer.
        seed_membership(&store, "hp", &registry, &"49".repeat(32), "", &"fb".repeat(32), MembershipState::Pending, 0, 100);
        let written = poller::write_if_still("hp", MembershipState::Pending, |m| m.state = MembershipState::Active).unwrap();
        assert_eq!(written, Some(MembershipState::Pending));
        let yielded = poller::write_if_still("hp", MembershipState::Pending, |m| m.state = MembershipState::Failed).unwrap();
        assert_eq!(yielded, None, "the snapshot was Pending, the record is Active: no write");
        assert_eq!(store.membership("hp").unwrap().cache.state, MembershipState::Active);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_validates_arguments_before_touching_anything() {
        let imp = LogosRlnModuleImpl::default();
        // Its own scope: register_impl takes the process-global RegisterClaim
        // before it validates arguments, so sharing the suite's (ab.., ef..)
        // fixture would make a concurrent register test's in-flight claim
        // surface here instead of the expected argument error.
        let rln_id = "7a".repeat(32);

        let out = imp.register_membership("not-caip10".into(), rln_id.clone(), String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        let out = imp.register_membership(
            "eip155:1:0xB9cd878C90E49F797B4431fBF4fb333108CB90e6".into(),
            rln_id.clone(),
            String::new(),
        );
        assert!(out.contains(r#""kind":"unknown_registry""#), "got: {out}");

        let logos = format!("logos:local:{}", "8b".repeat(32));
        let out = imp.register_membership(logos.clone(), rln_id, opts_arr(&[("rate_limit", "0")]));
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        // A malformed rln_identifier is rejected before any state work.
        let out = imp.register_membership(logos, "xyz".into(), String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
    }

    // The common rate_limit key is optional: absent, the module applies
    // DEFAULT_RATE_LIMIT.
    #[test]
    fn register_defaults_rate_limit_when_option_absent() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-default-rate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, _store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "ab".repeat(32));

        let out = imp.register_membership(
            registry.clone(),
            "ef".repeat(32),
            opts_arr(&[]),
        );
        assert!(out.contains(r#""kind":"provider_failure""#), "dead transport: {out}");
        let listed = imp.get_memberships(registry);
        assert!(
            listed.contains(&format!(r#""rate_limit":{DEFAULT_RATE_LIMIT}"#)),
            "absent rate_limit option must apply the module default: {listed}"
        );

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A fresh register mints + persists a credential, records Pending, then
    // the dead stub transport fails the submit → provider_failure (record
    // retained, marked retryable). A live local membership short-circuits
    // before any provider call and surfaces a rate-limit mismatch.
    #[test]
    fn register_local_idempotency_and_dead_transport() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-lib-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let rln_id = "ef".repeat(32);

        // Part 1 — internal generation + dead transport: a credential is minted
        // and persisted in-module, then the funded submit fails against the
        // stub → provider_failure; the record remains (marked failed).
        let reg_a = format!("logos:local:{}", "ab".repeat(32));
        let funding = opts_arr(&[("rate_limit", "300")]);
        let out = imp.register_membership(reg_a.clone(), rln_id.clone(), funding);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");
        let listed = imp.get_memberships(reg_a);
        assert!(listed.contains("membership_hash"), "a credential was generated and persisted");
        assert!(
            listed.contains(r#""retryable":true"#),
            "a provider_failure dispatch is retryable (spec: a failed submission SHALL report whether it is retryable): {listed}"
        );

        // Part 2 — local idempotency: a live (active) membership short-circuits
        // before any provider call, returns the existing rate with a mismatch,
        // and mints no second credential.
        let reg_b = format!("logos:local:{}", "12".repeat(32));
        let commitment = [0x34u8; 32];
        let hash = registry_id::membership_hash(&reg_b, &commitment);
        seed_membership(
            &store,
            &hash,
            &reg_b,
            &registry_id::bytes_to_hex(&commitment),
            &"ef".repeat(32),
            &"22".repeat(32),
            MembershipState::Active,
            7,
            300,
        );

        let out = imp.register_membership(reg_b.clone(), rln_id, opts_arr(&[("rate_limit", "250")]));
        assert!(!out.contains(r#""error""#), "idempotent short-circuit, no provider call: {out}");
        assert!(out.contains(r#""state":"active""#), "got: {out}");
        assert!(out.contains(r#""rate_limit":300"#), "existing registration's rate wins: {out}");
        assert!(out.contains(r#""rate_limit_mismatch":true"#), "got: {out}");
        assert!(out.contains(&format!(r#""membership_hash":"{hash}""#)), "got: {out}");

        // Part 3 — a DIFFERENT application (rln_identifier) on the same
        // registry is NOT the same scope: no short-circuit — register mints a
        // fresh credential for it (and then fails at the dead-transport
        // submit), leaving TWO records on the registry.
        let funding = opts_arr(&[("rate_limit", "300")]);
        let out = imp.register_membership(reg_b.clone(), "aa".repeat(32), funding);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");
        let listed = imp.get_memberships(reg_b);
        assert_eq!(
            listed.matches("membership_hash").count(),
            2,
            "distinct scope must mint its own membership: {listed}"
        );

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Idempotency is LIVE-only: a TERMINAL record (expired, erased) never
    // blocks a fresh registration — register mints a brand-new credential,
    // which then fails against the dead stub transport, leaving BOTH records.
    #[test]
    fn register_ignores_terminal_records_mints_fresh_credential() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-terminal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let rln_id = "ef".repeat(32);
        let funding = opts_arr(&[("rate_limit", "300")]);

        // An EXPIRED record for the scope: register must not short-circuit
        // to it.
        let reg_expired = format!("logos:local:{}", "56".repeat(32));
        let expired_commitment = [0x9au8; 32];
        let expired_hash = registry_id::membership_hash(&reg_expired, &expired_commitment);
        seed_membership(
            &store,
            &expired_hash,
            &reg_expired,
            &registry_id::bytes_to_hex(&expired_commitment),
            &rln_id,
            &"99".repeat(32),
            MembershipState::Expired,
            3,
            300,
        );

        let out = imp.register_membership(reg_expired.clone(), rln_id.clone(), funding.clone());
        assert!(
            out.contains(r#""kind":"provider_failure""#),
            "no short-circuit — the fresh submit hits the dead transport: {out}"
        );
        let records = store.records_for(&reg_expired);
        let hashes: Vec<&str> = records.iter().map(|r| r.hash.as_str()).collect();
        assert_eq!(
            records.len(),
            2,
            "the expired record is retained AND a fresh one was minted: {hashes:?}"
        );
        assert!(
            records.iter().any(|r| r.hash != expired_hash && r.cache.state == MembershipState::Failed),
            "a NEW credential (different membership_hash) was minted, then failed at the \
             dead transport: {hashes:?}"
        );

        // An ERASED record on a second registry: same rule.
        let reg_erased = format!("logos:local:{}", "78".repeat(32));
        let erased_commitment = [0x9bu8; 32];
        let erased_hash = registry_id::membership_hash(&reg_erased, &erased_commitment);
        seed_membership(
            &store,
            &erased_hash,
            &reg_erased,
            &registry_id::bytes_to_hex(&erased_commitment),
            &rln_id,
            &"aa".repeat(32),
            MembershipState::Erased,
            5,
            300,
        );

        let out = imp.register_membership(reg_erased.clone(), rln_id, funding);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");
        let records = store.records_for(&reg_erased);
        assert_eq!(records.len(), 2, "the erased record is retained AND a fresh one was minted");
        assert!(records.iter().any(|r| r.hash != erased_hash && r.cache.state == MembershipState::Failed));

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Delegated register: malformed options fail before a credential is
    // minted; well-formed options against the dead stub transport mint +
    // persist the credential, then fail cleanly at the gifter dispatch.
    #[test]
    fn delegated_register_validates_then_fails_cleanly_on_dead_transport() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-delegated-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, _store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let rln_id = "ef".repeat(32);

        let out = imp.register_membership(
            registry.clone(),
            rln_id.clone(),
            opts_arr(&[("delegated", "true"), ("discover", "false")]),
        );
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert_eq!(
            imp.get_memberships(registry.clone()),
            r#"{"memberships":[]}"#,
            "invalid delegated options must not mint a credential"
        );

        let opts = opts_arr(&[
            ("delegated", "true"),
            ("gifter_peer_id", "12D3KooWTest"),
            ("gifter_multiaddr", "/ip4/127.0.0.1/tcp/1"),
            ("auth_type", "keycard-attestation"),
            ("auth_provider", "keycard_capture_module"),
        ]);
        let out = imp.register_membership(registry.clone(), rln_id.clone(), opts);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");
        assert!(
            imp.get_memberships(registry.clone()).contains("membership_hash"),
            "the credential was minted and the failed record retained"
        );

        // A plugin auth vector this module has never heard of passes the same
        // validation (open vocabulary) and reaches the gifter dispatch — the
        // prior failed record is terminal, so a fresh credential is minted.
        let opts = opts_arr(&[
            ("delegated", "true"),
            ("gifter_peer_id", "12D3KooWTest"),
            ("gifter_multiaddr", "/ip4/127.0.0.1/tcp/1"),
            ("auth_type", "voucher-v1"),
            ("auth_payload", "deadbeef"),
        ]);
        let out = imp.register_membership(registry.clone(), rln_id, opts);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The retired 0.5.0 object encoding is rejected outright too. Fails
    // before any store access — no unlock/init needed.
    #[test]
    fn register_rejects_non_string_values_and_non_array_options() {
        let imp = LogosRlnModuleImpl::default();
        // Its own scope, for the RegisterClaim reason above.
        let registry = format!("logos:local:{}", "9d".repeat(32));
        let rln_id = "6e".repeat(32);

        let out = imp.register_membership(
            registry.clone(),
            rln_id.clone(),
            r#"[{"key":"delegated","value":true}]"#.into(),
        );
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert!(out.contains("'delegated' must be a string"), "got: {out}");

        let out =
            imp.register_membership(registry.clone(), rln_id.clone(), r#"{"delegated":"true"}"#.into());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert!(out.contains("must be a RegistryOptions array"), "got: {out}");

        let out = imp.register_membership(
            registry,
            rln_id,
            r#"[{"key":"rate_limit","value":"5"},{"key":"rate_limit","value":"9"}]"#.into(),
        );
        assert!(out.contains("duplicate RegistryOptions key 'rate_limit'"), "got: {out}");
    }

    // Shape-only auth validation (the vocabulary is OPEN): every rejection
    // lands BEFORE a credential is minted.
    #[test]
    fn delegated_register_validates_auth_options_before_minting() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-auth-validate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, _store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let rln_id = "ef".repeat(32);
        let opts = |extra: &str| {
            format!(
                r#"[{{"key":"delegated","value":"true"}},
                    {{"key":"gifter_peer_id","value":"12D3KooWTest"}},
                    {{"key":"gifter_multiaddr","value":"/ip4/127.0.0.1/tcp/1"}},{extra}]"#
            )
        };
        let reg = |imp: &LogosRlnModuleImpl, extra: &str| {
            imp.register_membership(registry.clone(), rln_id.clone(), opts(extra))
        };

        for (extra, expect) in [
            (r#"{"key":"auth_type","value":42}"#, "'auth_type' must be a string"),
            (r#"{"key":"auth_payload","value":"deadbeef"}"#, "need auth_type"),
            (
                r#"{"key":"auth_type","value":"voucher-v1"}"#,
                "needs auth_payload or auth_provider",
            ),
            (
                r#"{"key":"auth_type","value":"voucher-v1"},{"key":"auth_payload","value":"deadbeef"},{"key":"auth_provider","value":"voucher_module"}"#,
                "mutually exclusive",
            ),
            (
                r#"{"key":"auth_type","value":"voucher-v1"},{"key":"auth_payload","value":"not-hex!"}"#,
                "must be hex",
            ),
        ] {
            let out = reg(&imp, extra);
            assert!(out.contains(r#""kind":"invalid_argument""#), "{extra} got: {out}");
            assert!(out.contains(expect), "{extra} got: {out}");
        }

        let out = imp.register_membership(
            registry.clone(),
            rln_id.clone(),
            opts_arr(&[("auth_type", "voucher-v1"), ("auth_payload", "deadbeef")]),
        );
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert!(out.contains("delegated registration only"), "got: {out}");

        assert_eq!(
            imp.get_memberships(registry),
            r#"{"memberships":[]}"#,
            "no rejection above may mint a credential"
        );

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // An allocator block without a pair is discovery alone: the request
    // names no gifter and the options say so; a pair with discovery off
    // dials that gifter only.
    #[test]
    fn an_allocator_block_without_a_pair_discovers() {
        let d = DelegatedOptions::from_allocator_block(Some(&serde_json::json!({})), "x").unwrap().unwrap();
        assert!(d.discover && d.gifter_peer_id.is_empty() && d.gifter_multiaddr.is_empty());
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300, "cf")).unwrap();
        assert_eq!(v["discover"], true, "got: {v}");
        assert!(v.get("gifterPeerId").is_none() && v.get("gifterMultiaddr").is_none(), "got: {v}");
        let flat = |pairs: serde_json::Value| {
            let (_, flat) = parse_registry_options(&pairs.to_string()).unwrap();
            DelegatedOptions::from_registry_options(&flat).unwrap()
        };
        assert_eq!(flat(serde_json::json!([{ "key": "delegated", "value": "true" }])), Some(d));

        let d = DelegatedOptions::from_allocator_block(
            Some(&serde_json::json!({ "discover": false, "peer_id": "p", "multiaddr": "/m" })),
            "x",
        )
        .unwrap()
        .unwrap();
        assert!(!d.discover);
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300, "cf")).unwrap();
        assert_eq!(v["discover"], false, "got: {v}");
        assert_eq!(v["gifterPeerId"], "p", "got: {v}");
        assert_eq!(
            flat(serde_json::json!([
                { "key": "delegated", "value": "true" },
                { "key": "discover", "value": "false" },
                { "key": "gifter_peer_id", "value": "p" },
                { "key": "gifter_multiaddr", "value": "/m" },
            ])),
            Some(d)
        );
        assert_eq!(flat(serde_json::json!([{ "key": "rate_limit", "value": "7" }])), None);
    }
}
