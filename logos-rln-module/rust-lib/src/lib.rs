//! liblogos_rln_module — the RLN Module.
//!
//! Implements the RLN Module API (RLN-API) and the RLN-MEMBERSHIP-MANAGEMENT
//! spec (logos-lips docs/anoncomms/raw/): registry-agnostic membership
//! management — with the identity credential generated IN-MODULE at register
//! and never released — plus RLN rate limiting: proof generation over the
//! encrypted credential and hot-path verification from a locally maintained
//! valid-root window. Every call is scoped by (registry_id, rln_identifier).
//!
//! Architecture (spec concept → crate):
//! - registry_id (CAIP-10) parse/canonicalize/route → `registry_id.rs`
//! - storage backend → `sealed_store/` (the sealed keystore: crypto,
//!   on-disk format, durable files, runtime Store with persist-before-issue
//!   message_id reservation) and `lifecycle.rs` (the state machine, merged
//!   view)
//! - registry provider → `provider.rs` (trait + the lez-rln provider, a raw
//!   lp_* wire client of the sibling liblogos_lez_rln_module; also the lazy
//!   gifter client for delegated registration)
//! - Pending confirmation window + involuntary-removal detection →
//!   `poller.rs` (a `worker.rs`-supervised worker)
//! - selection (per-scope RoundRobin etc.; public view only) → `select.rs`
//! - proof engine (zerokit, witness assembly, canonical RateLimitProof,
//!   in-module identity generation) → `proof.rs`
//! - epoch + message_id allocation → `rate_limit.rs`
//! - valid-root window (no registry access on the verify path) → `roots.rs`
//! - per-membership Merkle proof-path cache (background-maintained, no
//!   registry access on `generate_proof`'s hot path) → `path_cache.rs`
//!
//! Wire conventions: every method returns a compact JSON object (serde_json
//! ⇒ alphabetical keys); failures are
//! `{"error":{"kind":…,"message":…}}` — see `ErrorKind`. The sibling RLN
//! module's ""-on-error convention is not used here.
//!
//! Concurrency is SINGLE: registration is fire-and-record
//! (lp_invoke_async), so no handler blocks on a sequencer submit; the
//! poller thread does the slow reads off the dispatch thread.

use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

mod keychain;
mod lifecycle;
mod nullifier_log;
mod panic_hook;
mod path_cache;
mod poller;
mod proof;
mod provider;
mod rate_limit;
mod registry_id;
mod roots;
mod sealed_store;
mod select;
mod views;
mod wallet_home;
mod worker;

mod generated {
    #![allow(warnings)]
    #![allow(clippy::all)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
pub(crate) use generated::*;

use lifecycle::{MembershipRecord, MembershipState, StoredCredential};
use sealed_store::store::Store;
use zeroize::Zeroize;

/// Tests touching process-global subsystems (the worker supervisor, CONFIG,
/// the nullifier log, root windows, the path cache, the keychain backend,
/// the published store slot, event emission) serialize on this.
#[cfg(test)]
pub(crate) static TEST_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

/// Open a store in `dir` and publish it in the worker-loop slot — the tests'
/// stand-in for `on_context_ready`'s store wiring.
#[cfg(test)]
pub(crate) fn publish_test_store(dir: std::path::PathBuf) -> Arc<Store> {
    sealed_store::store::publish(None);
    let store = Store::open(dir).expect("test store open");
    sealed_store::store::publish(Some(&store));
    store
}

// -------------------------------------------------------------------- errors

/// Reply-envelope error kinds. The spec's RLN Module API mandates
/// distinguishing at least NOT_READY / TRANSIENT / BUDGET_EXHAUSTED /
/// PERMANENT (the rate-limiting portion), plus this crate's management kinds
/// unknown_registry / unknown_membership / provider_failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ErrorKind {
    UnknownRegistry,
    UnknownMembership,
    ProviderFailure,
    Locked,
    BadPassword,
    NoUsableMembership,
    AmbiguousSelection,
    InvalidArgument,
    KeychainUnavailable,
    Internal,
    /// Module cannot serve the call yet (registry view not warm) — retry.
    NotReady,
    /// A recoverable failure (registry/RPC/engine hiccup) — the caller MAY retry.
    Transient,
    /// The epoch's rate-limit budget is spent — retry next epoch.
    BudgetExhausted,
    /// Retrying as-is cannot succeed. Constructed by the rate-limit
    /// allocator's floor/epoch-size guards (`store::reserve_message_id`):
    /// an epoch below the persisted allocation floor, or a configured
    /// `epoch_size_sec` this membership's allocations are not bound to.
    Permanent,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::UnknownRegistry => "unknown_registry",
            ErrorKind::UnknownMembership => "unknown_membership",
            ErrorKind::ProviderFailure => "provider_failure",
            ErrorKind::Locked => "locked",
            ErrorKind::BadPassword => "bad_password",
            ErrorKind::NoUsableMembership => "no_usable_membership",
            ErrorKind::AmbiguousSelection => "ambiguous_selection",
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::KeychainUnavailable => "keychain_unavailable",
            ErrorKind::Internal => "internal",
            ErrorKind::NotReady => "not_ready",
            ErrorKind::Transient => "transient",
            ErrorKind::BudgetExhausted => "budget_exhausted",
            ErrorKind::Permanent => "permanent",
        }
    }

    /// The coarse RLN-API error class (the spec's RlnErrorKind quartet),
    /// carried in every error envelope. `locked` maps to not_ready: the
    /// keystore password is invisible to the spec surface, so the caller
    /// retries after the app's unlock flow.
    fn class(self) -> &'static str {
        match self {
            ErrorKind::NotReady | ErrorKind::Locked => "not_ready",
            ErrorKind::Transient | ErrorKind::ProviderFailure => "transient",
            ErrorKind::BudgetExhausted => "budget_exhausted",
            ErrorKind::UnknownRegistry
            | ErrorKind::UnknownMembership
            | ErrorKind::BadPassword
            | ErrorKind::NoUsableMembership
            | ErrorKind::AmbiguousSelection
            | ErrorKind::InvalidArgument
            | ErrorKind::KeychainUnavailable
            | ErrorKind::Internal
            | ErrorKind::Permanent => "permanent",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(kind: ErrorKind, message: &str) -> Self {
        ApiError {
            kind,
            message: message.to_string(),
        }
    }

    pub(crate) fn internal(message: &str) -> Self {
        ApiError::new(ErrorKind::Internal, message)
    }

    /// The typed error object: {"class":…,"kind":…,"message":…}, in
    /// alphabetical wire order (see `views.rs`).
    fn body(&self) -> serde_json::Value {
        serde_json::to_value(views::ErrorBody::new(
            self.kind.class(),
            self.kind.as_str(),
            self.message.clone(),
        ))
        .unwrap_or(serde_json::Value::Null)
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::json!({ "error": self.body() }).to_string()
    }
}

/// Flatten a handler result into the wire string (the tstr-method dialect):
/// the Ok value, or the in-band {"error":{…}} envelope.
pub(crate) fn reply(result: Result<serde_json::Value, ApiError>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(e) => e.to_json(),
    }
}

/// Flatten a handler result into a `-> result` (LogosResult) return: the
/// generated dispatch wraps Ok into {"success":true,"value":…} and Err into
/// {"success":false,"error":<this string>}, so the error string is the
/// JSON-encoded typed object {"class":…,"kind":…,"message":…}.
pub(crate) fn reply_result(
    result: Result<serde_json::Value, ApiError>,
) -> Result<serde_json::Value, String> {
    result.map_err(|e| e.body().to_string())
}

/// Serialize a typed reply view (`views.rs`) into its wire `Value`.
fn ok_json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::internal(&format!("serialize reply: {e}")))
}

/// Poison-recovering lock: a poisoned mutex is a bug elsewhere, not a
/// reason to wedge every future call.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wall-clock UNIX seconds; a clock before the epoch reads as 0 rather
/// than panicking.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ------------------------------------------------------------------- helpers

/// Parse a 32-byte LE hex field, returning the bytes and their normalized
/// lowercase re-encoding. Invalid → InvalidArgument.
fn parse_hex32(field: &str, hex: &str) -> Result<([u8; 32], String), ApiError> {
    let bytes = registry_id::hex_to_bytes32(hex).ok_or_else(|| {
        ApiError::new(ErrorKind::InvalidArgument, &format!("{field} must be 32-byte hex"))
    })?;
    let hex = registry_id::bytes_to_hex(&bytes);
    Ok((bytes, hex))
}


/// The public Membership view (spec Membership minus secrets): the
/// `credential` object exposes only the commitment; the identity secret
/// never crosses this interface.
fn public_membership_json(
    hash: &str,
    record: &MembershipRecord,
    quarantined: bool,
    rate_limit_mismatch: bool,
) -> serde_json::Value {
    serde_json::to_value(views::MembershipView::new(hash, record, quarantined, rate_limit_mismatch))
        .unwrap_or(serde_json::Value::Null)
}

fn parse_registry(raw: &str) -> Result<registry_id::CanonicalRegistryId, ApiError> {
    registry_id::parse(raw).map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &e))
}

/// The registry's local membership records.
fn records_for_registry(
    store: &Store,
    registry: &registry_id::CanonicalRegistryId,
) -> Vec<MembershipRecord> {
    store.records_for(&registry.canonical)
}

/// Canonicalize the registry_id and parse/normalize the 32-byte
/// rln_identifier. Every call passes its scope explicitly (spec: the
/// Module holds no default); empty args fail invalid_argument.
fn parse_scope(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<(registry_id::CanonicalRegistryId, [u8; 32], String), ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let (bytes, hex) = parse_hex32("rln_identifier", rln_identifier_hex)?;
    Ok((registry, bytes, hex))
}

/// Whether a record backs a scope: registered under the same rln_identifier,
/// or carrying none — pre-scope legacy records back every application on
/// their registry.
fn scope_matches(record: &MembershipRecord, rln_id_hex: &str) -> bool {
    record.identity.rln_identifier == rln_id_hex || record.identity.rln_identifier.is_empty()
}

/// The registry records backing a scope (spec: a membership "MAY back any
/// application whose scope names its registry"). If the scope has a USABLE
/// match, only its matching records are candidates — a dedicated membership
/// shadows the registry's others; otherwise every record backs it.
fn scope_candidates(
    records: &[MembershipRecord],
    rln_id_hex: &str,
) -> Vec<MembershipRecord> {
    let has_usable_match = records
        .iter()
        .any(|r| !r.quarantined && scope_matches(r, rln_id_hex) && r.cache.state.is_usable());
    if has_usable_match {
        records
            .iter()
            .filter(|r| scope_matches(r, rln_id_hex))
            .cloned()
            .collect()
    } else {
        records.to_vec()
    }
}

fn provider_of(
    registry: &registry_id::CanonicalRegistryId,
) -> Result<&'static dyn provider::RegistryProvider, ApiError> {
    provider::provider_for(&registry.namespace).ok_or_else(|| {
        ApiError::new(
            ErrorKind::UnknownRegistry,
            &format!("no registry provider for namespace {}", registry.namespace),
        )
    })
}

// -------------------------------------------------------------- method impls

/// Delegated-registration options (the RegistryOptions FLAT
/// "gifter_peer_id"/"gifter_multiaddr"/"auth_*" keys, selected by
/// "delegated":"true"). The auth surface is vector-agnostic: "auth_type"
/// and its payload material pass to the gifter verbatim.
struct DelegatedOptions {
    gifter_peer_id: String,
    gifter_multiaddr: String,
    auth_type: Option<String>,
    auth_payload: Option<String>,
    auth_provider: Option<String>,
    auth_args: Option<String>,
}

/// Read a RegistryOptions flat boolean field: the spec's char* key/value
/// pairs make every value a JSON string, so "true" is the only truthy
/// spelling and a JSON bool is a type error, not a coercion.
fn flat_bool_option(options: &serde_json::Value, key: &str) -> Result<bool, ApiError> {
    match options.get(key) {
        Some(serde_json::Value::Bool(_)) => Err(ApiError::new(
            ErrorKind::InvalidArgument,
            &format!(
                "options_json.{key} must be the string \"true\"/\"false\", not a JSON boolean"
            ),
        )),
        Some(v) => Ok(v.as_str() == Some("true")),
        None => Ok(false),
    }
}

/// Read a RegistryOptions flat string field: absent and "" both mean unset;
/// any non-string JSON value is a type error.
fn flat_str_option(options: &serde_json::Value, key: &str) -> Result<Option<String>, ApiError> {
    match options.get(key) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) if s.is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ApiError::new(
            ErrorKind::InvalidArgument,
            &format!("options_json.{key} must be a string (flat char* option)"),
        )),
    }
}

/// The logos-namespace default when the common "rate_limit" option key is
/// absent (spec register(): "absent, the registry … applies its default").
/// The lez registry declares no default today, so the module supplies one.
/// TODO: investigate a registry-declared default in logos-lez-rln (surfaced
/// via get_registry_parameters, e.g. default_rate_limit) and prefer it over
/// this constant when present.
const DEFAULT_RATE_LIMIT: u64 = 100;

/// Parse the wire's options_json — the JSON binding of the spec's
/// RegistryOptions: an ARRAY of {"key","value"} pairs, both strings (char*
/// pairs in the C type, so a non-string value is a type error, never a
/// coercion). Empty input means "no options". Duplicate keys are a caller
/// bug and rejected. Returns the requested rate_limit (the common key,
/// defaulted when absent/empty) and the remaining options as a flat object
/// — the shape the option validators and the provider consume.
fn parse_registry_options(options_json: &str) -> Result<(u64, serde_json::Value), ApiError> {
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
    let rate_limit = match map.remove("rate_limit") {
        None => DEFAULT_RATE_LIMIT,
        Some(v) => {
            let s = v.as_str().unwrap_or_default().trim().to_string();
            if s.is_empty() {
                DEFAULT_RATE_LIMIT
            } else {
                s.parse::<u64>().ok().filter(|r| *r > 0).ok_or_else(|| {
                    ApiError::new(
                        ErrorKind::InvalidArgument,
                        "rate_limit option must be a positive decimal string",
                    )
                })?
            }
        }
    };
    Ok((rate_limit, serde_json::Value::Object(map)))
}

/// Gifter `request` args for a delegated registration: the module-generated
/// commitment (never the secret) plus the caller's gifter and auth-vector
/// selection, passed through verbatim. With an auth_provider the gifter
/// client produces the payload bound to exactly this commitment.
fn delegated_request_args(d: &DelegatedOptions, commitment_hex: &str, rate_limit: u64) -> String {
    let mut args = serde_json::json!({
        "gifterPeerId": d.gifter_peer_id,
        "gifterMultiaddr": d.gifter_multiaddr,
        "identityCommitment": commitment_hex,
        "rate": rate_limit,
    });
    if let Some(t) = &d.auth_type {
        args["authType"] = t.as_str().into();
    }
    if let Some(p) = &d.auth_payload {
        args["authPayload"] = p.as_str().into();
    }
    if let Some(module) = &d.auth_provider {
        args["authProvider"] = module.as_str().into();
    }
    if let Some(extra) = &d.auth_args {
        args["authArgs"] = extra.as_str().into();
    }
    args.to_string()
}

/// The spec's failed-submission retryable flag: transient, not-ready, and
/// provider-side failures MAY succeed on a fresh register; anything else
/// needs the caller to change something first.
fn is_retryable_submit_error(e: &ApiError) -> bool {
    matches!(e.kind, ErrorKind::Transient | ErrorKind::NotReady | ErrorKind::ProviderFailure)
}

/// Fire-and-record tail of a funded submit: record the register_member reply,
/// or mark the record failed. Runs on the owner thread after register
/// returns; `store` is a Weak capture of the store the record was inserted
/// into — gone (re-context replaced it) means there is nothing to record on.
fn funded_submit_callback(store: Weak<Store>, hash: String) -> provider::RegisterCallback {
    Box::new(move |result| {
        let update = match store.upgrade() {
            Some(store) => store.update_cache(&hash, |m| match &result {
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

/// Fire-and-record tail of a delegated submit: a gifter {"error":…} marks
/// the record failed; a grant records the leaf estimate and a funded-style
/// tx_result envelope. Confirmation stays the poller's registry read-back.
fn delegated_submit_callback(store: Weak<Store>, hash: String) -> provider::RegisterCallback {
    Box::new(move |result| {
        let update = match store.upgrade() {
            Some(store) => store.update_cache(&hash, |m| match &result {
                Ok(reply) => match serde_json::from_str::<serde_json::Value>(reply) {
                    Ok(v) => {
                        if let Some(e) = v.get("error") {
                            // A late gifter rejection must not overwrite a state
                            // the poller already confirmed from the registry
                            // (authoritative). Only a still-pending record fails.
                            if m.state == MembershipState::Pending {
                                let msg = e
                                    .as_str()
                                    .map(String::from)
                                    .unwrap_or_else(|| e.to_string());
                                m.state = MembershipState::Failed;
                                m.failed_reason = Some(format!("gifter_failed: {msg}"));
                            }
                            return;
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
            }),
            None => Err(ApiError::internal("store closed before the submit callback landed")),
        };
        if let Err(e) = update {
            eprintln!("membership delegated callback: {}", e.message);
        }
    })
}

/// Spec register(): generate the identity credential INSIDE the module,
/// persist it encrypted, and submit its rate commitment — returning the
/// public Pending membership immediately. Idempotent PER SCOPE: the scope's
/// live membership short-circuits. Submission is fire-and-record (the async
/// callback lands on the owner thread after this returns); the store lock
/// is NEVER held across a provider call.
fn register_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    options_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let prov = provider_of(&registry)?;

    // Spec register(scope, RegistryOptions): options_json is the
    // RegistryOptions ARRAY binding; the common "rate_limit" key is lifted
    // out here (defaulted when absent) and the remaining pairs become the
    // flat option map. Delegated registration (selecting the RLN Membership
    // Allocation Protocol) is the "delegated":"true" pair plus
    // "gifter_peer_id"/"gifter_multiaddr" and the optional "auth_type"/
    // "auth_payload"/"auth_provider"/"auth_args" vector selection (OPEN
    // vocabulary; payload from auth_payload hex or an auth_provider module,
    // auth_args forwarded verbatim). No auth_type is an unauthenticated
    // request. Validated up front so a malformed request never mints a
    // credential.
    let (rate_limit, opts) = parse_registry_options(options_json)?;
    let delegated = if flat_bool_option(&opts, "delegated")? {
        Some(DelegatedOptions {
            gifter_peer_id: opts
                .get("gifter_peer_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            gifter_multiaddr: opts
                .get("gifter_multiaddr")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            auth_type: flat_str_option(&opts, "auth_type")?,
            auth_payload: flat_str_option(&opts, "auth_payload")?,
            auth_provider: flat_str_option(&opts, "auth_provider")?,
            auth_args: flat_str_option(&opts, "auth_args")?,
        })
    } else {
        None
    };
    if let Some(d) = &delegated {
        if d.gifter_peer_id.is_empty() || d.gifter_multiaddr.is_empty() {
            return Err(ApiError::new(
                ErrorKind::InvalidArgument,
                "delegated registration needs gifter_peer_id and gifter_multiaddr",
            ));
        }
        // Shape-only checks (the auth_type vocabulary is OPEN): payload
        // material needs a named vector, and a named vector needs exactly
        // one payload source (auth_payload xor auth_provider) — validated
        // BEFORE a credential is minted.
        if d.auth_type.is_none()
            && (d.auth_payload.is_some() || d.auth_provider.is_some() || d.auth_args.is_some())
        {
            return Err(ApiError::new(
                ErrorKind::InvalidArgument,
                "auth_payload/auth_provider/auth_args need auth_type",
            ));
        }
        if let Some(t) = d.auth_type.as_deref() {
            match (&d.auth_payload, &d.auth_provider) {
                (Some(_), Some(_)) => {
                    return Err(ApiError::new(
                        ErrorKind::InvalidArgument,
                        "auth_payload and auth_provider are mutually exclusive",
                    ))
                }
                (None, None) => {
                    return Err(ApiError::new(
                        ErrorKind::InvalidArgument,
                        &format!("auth_type '{t}' needs auth_payload or auth_provider"),
                    ))
                }
                _ => {}
            }
        }
        if let Some(p) = &d.auth_payload {
            let h = p.trim_start_matches("0x");
            if h.is_empty() || h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "auth_payload must be hex-encoded bytes",
                ));
            }
        }
    } else if ["auth_type", "auth_payload", "auth_provider", "auth_args"]
        .iter()
        .any(|k| opts.get(*k).is_some())
    {
        // Auth material on the funded path is a caller mistake, not a no-op.
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "auth_* options apply to delegated registration only — set \"delegated\":\"true\"",
        ));
    }

    // Idempotent PER SCOPE: a LIVE (pending/active/grace_period) record for
    // this scope short-circuits; terminal states (failed, expired, erased)
    // never block a fresh registration. A DIFFERENT application on the same
    // registry gets its own membership (dedicated budget, isolated slashing
    // blast radius); one membership can still back many applications at
    // proof time (see scope_candidates).
    let store = store?;
    let records = records_for_registry(store, &registry);
    if let Some(rec) = records
        .iter()
        .find(|r| !r.quarantined && r.cache.state.is_live() && scope_matches(r, &rln_id_hex))
    {
        let mismatch = rec.cache.rate_limit != Some(rate_limit);
        return Ok(public_membership_json(&rec.hash, rec, false, mismatch));
    }

    // Fast-fail a rate_limit outside the registry's bounds BEFORE minting a
    // credential (spec: above max_rate_limit SHALL fail). An unreadable
    // registry skips the pre-check — it enforces its own bounds at
    // submission.
    match prov.get_registry_bounds(&registry) {
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
        identity_nullifier: None,
        identity_secret_hash: secret_hash_hex,
        identity_trapdoor: None,
        registry_id: registry.canonical.clone(),
    };

    // Pending record FIRST (an interrupted submit still leaves an auditable
    // record the poller will resolve), then the async submit, whose callback
    // lands on the owner thread after this handler has returned. `insert`
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
    store.insert(&hash, identity, &credential)?;
    store.update_cache(&hash, |m| m.rate_limit = Some(rate_limit))?;

    let submit = match &delegated {
        Some(d) => provider::gifter_request_async(
            &delegated_request_args(d, &commitment_hex, rate_limit),
            delegated_submit_callback(Arc::downgrade(store), hash.clone()),
        ),
        None => prov.register_async(
            &registry,
            // The provider consumes the flat option OBJECT (its wire is
            // unchanged); the RegistryOptions array was flattened above.
            &opts.to_string(),
            &commitment_hex,
            rate_limit,
            funded_submit_callback(Arc::downgrade(store), hash.clone()),
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
    Ok(public_membership_json(&hash, &record, false, false))
}

/// Spec get_membership_state(scope): a live registry read overlaid on the
/// local record of the membership backing the scope (scope_candidates). No
/// candidate → UNKNOWN; more than one → AmbiguousSelection. Transitions the
/// merged view implies are persisted.
fn get_membership_state_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let prov = provider_of(&registry)?;

    // A missing store (no persistence path) degrades to no local records.
    let records = store
        .as_ref()
        .map(|s| records_for_registry(s, &registry))
        .unwrap_or_default();
    let candidates: Vec<_> = scope_candidates(&records, &rln_id_hex)
        .into_iter()
        .filter(|r| !r.quarantined)
        .collect();
    if candidates.is_empty() {
        return ok_json(views::MembershipStateView::unknown(&registry.canonical));
    }
    if candidates.len() > 1 {
        return Err(ApiError::new(
            ErrorKind::AmbiguousSelection,
            "multiple memberships back this scope; use get_memberships / select_membership",
        ));
    }
    // Records exist, so the store does too.
    let store = store?;
    let record = &candidates[0];
    let hash = &record.hash;

    let pm = prov.get_membership(&registry, &record.identity.identity_commitment)?;
    let registry_state = if pm.registered { Some(pm.state) } else { None };
    let merged = lifecycle::merge_state(Some(record), registry_state, now_unix());

    if merged != record.cache.state {
        // Self-healing cache write: the merged view is recomputed from
        // (local, registry, now) on every read, so a failed persist only
        // costs the next reader a recompute — log it and move on.
        let persist = store.update_cache(hash, |m| {
            m.state = merged;
            if pm.registered {
                // The pending→active re-read (spec MUST).
                m.leaf_index = Some(pm.leaf_index);
                m.rate_limit = Some(pm.rate_limit);
                m.failed_reason = None;
                m.retryable = None;
            } else if merged == MembershipState::Failed {
                m.failed_reason = Some("confirmation_window_elapsed".to_string());
                // Re-registration can be attempted (spec: a failed
                // submission SHALL report whether it is retryable).
                m.retryable = Some(true);
            } else if merged == MembershipState::Erased {
                m.failed_reason = Some("removed_from_registry".to_string());
            }
        });
        if let Err(e) = persist {
            eprintln!("membership state persist: {}", e.message);
        } else if let Some((registry_id, rln_identifier, membership_hash, state, previous)) =
            lifecycle::transition_event(hash, record, merged)
        {
            // Emitted after the store write returned: no store lock is held
            // across the event emit.
            emit_membership_state_changed(
                &registry_id,
                &rln_identifier,
                &membership_hash,
                &state,
                &previous,
            );
        }
    }

    let (leaf_index, rate_limit) = if pm.registered {
        (pm.leaf_index, pm.rate_limit)
    } else {
        (record.cache.leaf_index.unwrap_or(0), record.cache.rate_limit.unwrap_or(0))
    };
    let view = views::MembershipStateView::resolved(
        hash,
        &registry.canonical,
        merged,
        leaf_index,
        rate_limit,
    );
    ok_json(view)
}

/// Spec select(): resolve WHICH membership an application should prove with,
/// for scopes that hold more than one. Returns the PUBLIC membership view
/// only — the identity credential is never released. No unlocked keystore
/// is required.
fn select_membership_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    selector_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_identifier_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let selector = select::parse_selector(selector_json)?;

    let store = store?;
    let records = records_for_registry(store, &registry);
    let hash = select::select_hash(
        &records,
        (&registry.canonical, &rln_identifier_hex),
        &selector,
    )?;
    let record = records
        .iter()
        .find(|r| r.hash == hash)
        .cloned()
        .ok_or_else(|| ApiError::internal("selected record vanished"))?;
    Ok(public_membership_json(&hash, &record, false, false))
}

fn get_memberships_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    // No provider needed: listing LOCAL records is meaningful even for a
    // namespace this build can't reach.
    let records = records_for_registry(store?, &registry);
    let memberships: Vec<serde_json::Value> = records
        .iter()
        .map(|r| public_membership_json(&r.hash, r, r.quarantined, false))
        .collect();
    Ok(serde_json::json!({ "memberships": memberships }))
}

// ---------------------------------------------------------------- rate limiting

/// Default `max_epoch_gap` (see [`epoch_gap`]) when `start()` sets none.
const DEFAULT_MAX_EPOCH_GAP: u64 = 1;

/// A registry's deviation from the instance defaults (spec: the epoch size
/// and the maximum epoch gap are per-REGISTRY configuration).
#[derive(Clone, Copy, Default)]
struct RegistryOverride {
    epoch_size_sec: Option<u64>,
    max_epoch_gap: Option<u64>,
}

/// Runtime configuration applied by `start()`: instance defaults plus
/// per-registry overrides, keyed by canonical registry_id.
struct ModuleConfig {
    epoch_size_sec: u64,
    max_epoch_gap: u64,
    overrides: std::collections::BTreeMap<String, RegistryOverride>,
}

static CONFIG: Mutex<Option<ModuleConfig>> = Mutex::new(None);

/// The configured epoch length — an APPLICATION parameter every proof
/// generator and verifier must share, so there is deliberately NO default:
/// before `start()` configures it, the epoch-dependent functions fail
/// `not_ready` (spec: RLN_ERR_NOT_READY). Production code resolves
/// per-registry via `epoch_size_for`; tests use this default-path view.
#[cfg(test)]
fn epoch_size() -> Result<u64, ApiError> {
    lock(&CONFIG).as_ref().map(|c| c.epoch_size_sec).ok_or_else(|| {
        ApiError::new(
            ErrorKind::NotReady,
            "start() has not configured epoch_size_sec; rate limiting is not ready",
        )
    })
}

/// The epoch length in force for one registry: its start() override when
/// given, else the instance default (spec: per-registry configuration).
fn epoch_size_for(registry_canonical: &str) -> Result<u64, ApiError> {
    lock(&CONFIG)
        .as_ref()
        .map(|c| {
            c.overrides
                .get(registry_canonical)
                .and_then(|o| o.epoch_size_sec)
                .unwrap_or(c.epoch_size_sec)
        })
        .ok_or_else(|| {
            ApiError::new(
                ErrorKind::NotReady,
                "start() has not configured epoch_size_sec; rate limiting is not ready",
            )
        })
}

/// [`epoch_gap`], per registry: the start() override when given, else the
/// instance default.
fn epoch_gap_for(registry_canonical: &str) -> u64 {
    lock(&CONFIG)
        .as_ref()
        .map(|c| {
            c.overrides
                .get(registry_canonical)
                .and_then(|o| o.max_epoch_gap)
                .unwrap_or(c.max_epoch_gap)
        })
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_EPOCH_GAP)
}

#[cfg(test)]
pub(crate) fn reset_config_for_test() {
    *lock(&CONFIG) = None;
}

/// Spec start(): apply configuration, warm the configured registries' root
/// windows, begin maintenance, and clear any prior stop(). Idempotent —
/// safe to call again to reconfigure. config_json:
/// {"epoch_size_sec":N (required — the instance default), "max_epoch_gap"?:N,
/// "registries"?:[<entry>,…]} where an entry is a CAIP-10 string, or an
/// object {"registry_id":caip10, "epoch_size_sec"?:N, "max_epoch_gap"?:N}
/// overriding the defaults for that registry (spec: epoch size and max gap
/// are per-registry configuration).
fn start_impl(config_json: &str) -> Result<serde_json::Value, ApiError> {
    panic_hook::install_once();
    let cfg: serde_json::Value = if config_json.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(config_json)
            .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &format!("config_json: {e}")))?
    };

    let epoch_size_sec = cfg
        .get("epoch_size_sec")
        .and_then(|x| x.as_u64())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorKind::InvalidArgument,
                "config_json.epoch_size_sec is required (a positive integer all \
                 validators of the application share)",
            )
        })?;
    let max_epoch_gap = cfg
        .get("max_epoch_gap")
        .and_then(|x| x.as_u64())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_EPOCH_GAP);

    // Warm the root window for every configured registry; an object entry
    // additionally carries that registry's overrides. Unparseable entries
    // are skipped, as ever.
    let mut tracked: Vec<String> = Vec::new();
    let mut overrides: std::collections::BTreeMap<String, RegistryOverride> =
        std::collections::BTreeMap::new();
    let mut track = |raw: &str, over: Option<RegistryOverride>| {
        if let Ok(registry) = registry_id::parse(raw) {
            roots::track(&registry);
            if let Some(o) = over {
                if o.epoch_size_sec.is_some() || o.max_epoch_gap.is_some() {
                    overrides.insert(registry.canonical.clone(), o);
                }
            }
            if !tracked.contains(&registry.canonical) {
                tracked.push(registry.canonical);
            }
        }
    };
    if let Some(arr) = cfg.get("registries").and_then(|x| x.as_array()) {
        for entry in arr {
            match entry {
                serde_json::Value::String(raw) => track(raw, None),
                serde_json::Value::Object(o) => {
                    let raw = o.get("registry_id").and_then(|x| x.as_str()).unwrap_or_default();
                    let over = RegistryOverride {
                        epoch_size_sec: o
                            .get("epoch_size_sec")
                            .and_then(|x| x.as_u64())
                            .filter(|n| *n > 0),
                        max_epoch_gap: o
                            .get("max_epoch_gap")
                            .and_then(|x| x.as_u64())
                            .filter(|n| *n > 0),
                    };
                    track(raw, Some(over));
                }
                _ => {}
            }
        }
    }

    let overrides_view = views::start_overrides_view(
        overrides.iter().map(|(k, o)| (k.as_str(), o.epoch_size_sec, o.max_epoch_gap)),
    );
    *lock(&CONFIG) = Some(ModuleConfig { epoch_size_sec, max_epoch_gap, overrides });
    // A membership whose persisted allocations are bound to a DIFFERENT
    // epoch_size_sec can no longer generate proofs (the store fails those
    // reservations `permanent`); surface that at configure time. Warn-only:
    // rejecting start() would DoS validate_proof for every scope over one
    // stale local membership. Ignore an uninitialized store (pre-context) —
    // read the published slot, exactly like the worker loops.
    // Effective-size check is approximate under overrides: a binding that
    // matches ANY configured size passes (the record's own registry is not
    // threaded through epoch_size_bindings).
    if let Some(store) = sealed_store::store::current() {
        let effective: Vec<u64> = std::iter::once(epoch_size_sec)
            .chain(
                lock(&CONFIG)
                    .as_ref()
                    .map(|c| c.overrides.values().filter_map(|o| o.epoch_size_sec).collect::<Vec<u64>>())
                    .unwrap_or_default(),
            )
            .collect();
        for (hash, bound) in store.epoch_size_bindings() {
            if bound != 0 && !effective.contains(&bound) {
                eprintln!(
                    "membership start: entry {hash} allocations are bound to \
                     epoch_size_sec={bound}, config says {epoch_size_sec}; \
                     generate_proof for it will fail permanent"
                );
            }
        }
    }
    // Permit + (re)spawn the maintenance workers, and warm the tracked
    // registries' root windows and every usable membership's Merkle path in
    // the background — must not block start() itself.
    let warm_roots = !tracked.is_empty();
    worker::start(move || {
        if warm_roots {
            if let Err(payload) = std::panic::catch_unwind(roots::refresh_all) {
                eprintln!("membership start: root warm-up panicked: {payload:?}");
            }
        }
        if let Err(payload) = std::panic::catch_unwind(poller::refresh_paths) {
            eprintln!("membership start: path warm-up panicked: {payload:?}");
        }
    });

    ok_json(views::StartReply::new(epoch_size_sec, max_epoch_gap, overrides_view, tracked))
}

/// Spec stop(): halt the maintenance tasks. Sleeping workers are joined
/// within a short grace; a worker blocked in an in-flight registry read
/// (≤80s) is DETACHED — it performs at most that one read, observes it is
/// superseded, and exits. Nothing spawns again until the next start(); the
/// supervisor's generation counter keeps a detached straggler from ever
/// duplicating a worker.
fn stop_impl() -> Result<serde_json::Value, ApiError> {
    worker::stop();
    ok_json(views::StopReply::new())
}

fn proof_error(e: proof::ProofError) -> ApiError {
    match e {
        proof::ProofError::BadInput(m) => ApiError::new(ErrorKind::InvalidArgument, &m),
        proof::ProofError::Engine(m) => ApiError::new(ErrorKind::Transient, &m),
    }
}

/// Decode one field of a provider `get_merkle_proof` reply. Shared with
/// `path_cache.rs` so cache hits and misses build identically-shaped
/// witnesses.
pub(crate) fn json_str_array(v: &serde_json::Value, key: &str) -> Result<Vec<String>, ApiError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
        .ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("merkle proof missing {key}"))
        })
}

pub(crate) fn json_u8_array(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, ApiError> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_u64().map(|n| n as u8)).collect())
        .ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("merkle proof missing {key}"))
        })
}

/// Spec generate_proof(scope, signal, timestamp): pick the scope's usable
/// membership, serve its Merkle path (cache when warm, on-demand fetch on a
/// miss), reserve + DURABLY PERSIST the next message_id, and prove — the
/// identity secret never leaves the module. The proof's epoch derives from
/// the caller-supplied `timestamp` (Unix seconds), NOT this module's clock,
/// and must land within now ± `max_epoch_gap`. Returns the `RateLimitProof`
/// (spec shape: `proof` = compressed Groth16 proof[128], `epoch` = epoch[32]
/// LE hex) plus the spent `message_id`, the u64 `epoch_index`, and the
/// `membership_hash`.
fn generate_proof_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal_hex: &str,
    timestamp: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, rln_identifier, rln_id_hex) =
        parse_scope(registry_id_raw, rln_identifier_hex)?;
    let prov = provider_of(&registry)?;
    // Readiness gate FIRST (spec: not_ready before anything else). Size and
    // gap are the REGISTRY's (start() override or instance default).
    let size = epoch_size_for(&registry.canonical)?;
    let gap = epoch_gap_for(&registry.canonical);
    // The epoch derives from the CONSUMER's timestamp — the value stamped on
    // the message — so the receiver's timestamp->epoch check lines up by
    // construction.
    let epoch = epoch_of_timestamp(timestamp, size)?;
    // A stale or future timestamp fails fast instead of minting a proof the
    // verifier would reject as not fresh.
    let now_epoch = rate_limit::current_epoch(now_unix(), size);
    if !epoch_in_window(epoch, now_epoch, gap) {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "timestamp is outside the acceptable epoch window (now ± max_epoch_gap)",
        ));
    }
    let signal = registry_id::hex_to_vec(signal_hex)
        .ok_or_else(|| ApiError::new(ErrorKind::InvalidArgument, "signal must be hex"))?;

    // Keep this registry's root window warm (this node may verify too).
    roots::track(&registry);

    // Pick THE usable membership backing this scope; base generate_proof
    // requires a single candidate (AmbiguousSelection otherwise).
    let store = store?;
    let records = records_for_registry(store, &registry);
    let hash = select::select_hash(
        &scope_candidates(&records, &rln_id_hex),
        (&registry.canonical, &rln_id_hex),
        &select::Selector::None,
    )?;
    let record = store
        .membership(&hash)
        .ok_or_else(|| ApiError::new(ErrorKind::UnknownMembership, "selected membership vanished"))?;
    let leaf_index = record.cache.leaf_index.unwrap_or(0);
    let rate_limit = record.cache.rate_limit.unwrap_or(0);

    // Decrypt the credential in-module (requires an unlocked keystore).
    let credential = store.unseal_credential(&hash)?;

    // Fetch the Merkle path first — it can fail without spending a slot. A
    // cache hit is ZERO registry I/O; a miss falls back to the on-demand
    // fetch, which also fills the cache. A cached entry is only trusted
    // when its leaf_index still matches — see path_cache.rs.
    let (path_elements_hex, path_indices) = match path_cache::hit(&hash, leaf_index) {
        Some(path) => path,
        None => {
            path_cache::fill_path_cache(&registry, &hash, leaf_index, prov)?;
            path_cache::hit(&hash, leaf_index)
                .ok_or_else(|| ApiError::internal("path cache: fetched path vanished before use"))?
        }
    };

    // Reserve + durably persist the slot BEFORE proving, so a crash can
    // waste a slot but never reissue one. `retain_floor` is only the
    // window's CANDIDATE; the store's persisted monotone floor decides what
    // may be pruned or served.
    let retain_floor = now_epoch.saturating_sub(gap);
    let message_id =
        store.reserve_message_id(&hash, &rln_id_hex, epoch, retain_floor, rate_limit, size)?;

    let material = proof::WitnessMaterial {
        identity_secret_hash_hex: credential.identity_secret_hash.clone(),
        rate_limit,
        message_id,
        path_elements_hex,
        path_indices,
    };
    let rlp =
        proof::generate(&material, &signal, epoch, &rln_identifier).map_err(proof_error)?;

    let mut out = rlp.to_json();
    if let Some(obj) = out.as_object_mut() {
        // Extras beyond the spec struct: the spent slot, the u64 epoch index
        // (`epoch` itself stays the spec's epoch[32] LE hex), and the local
        // handle. Opaque to consumers, tolerated by from_json.
        obj.insert("message_id".to_string(), message_id.into());
        obj.insert("epoch_index".to_string(), epoch.into());
        obj.insert("membership_hash".to_string(), hash.into());
    }
    Ok(out)
}

/// Accepted distance, in epochs, between a proof's epoch and the verifier's
/// current one — absorbs clock skew and propagation latency. A start()
/// parameter (default 1); generator and verifiers must share it AND
/// epoch_size for the binding check to line up. Also the retention floor
/// for verification-side state keyed by epoch. Production code resolves
/// per-registry via `epoch_gap_for`; tests use this default-path view.
#[cfg(test)]
fn epoch_gap() -> u64 {
    lock(&CONFIG)
        .as_ref()
        .map(|c| c.max_epoch_gap)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_EPOCH_GAP)
}

/// Parse a wire `timestamp` argument (Unix seconds as a decimal string — a
/// tstr on purpose, so a numeric JSON arg cannot silently coerce to 0) into
/// its epoch index.
fn epoch_of_timestamp(timestamp: &str, epoch_size_sec: u64) -> Result<u64, ApiError> {
    Ok(rate_limit::current_epoch(
        timestamp.trim().parse::<u64>().map_err(|_| {
            ApiError::new(ErrorKind::InvalidArgument, "timestamp must be a Unix-seconds integer")
        })?,
        epoch_size_sec,
    ))
}

/// The freshness window every rate-limiting method enforces: an epoch is
/// acceptable when within now ± max_epoch_gap of the module clock.
fn epoch_in_window(epoch: u64, now_epoch: u64, gap: u64) -> bool {
    (now_epoch.saturating_sub(gap)..=now_epoch.saturating_add(gap)).contains(&epoch)
}

/// Whether a proof is bound to `expected_epoch` — the epoch derived from
/// the message's timestamp (spec: proof.epoch MUST equal it). Holds when
/// the expected epoch is fresh (within now ± epoch_gap()), the proof's
/// carried epoch (spec epoch[32]), when present, equals it, and the proof's
/// external nullifier equals the one recomputed from that epoch + the
/// scope's rln_identifier. Any failure is a verdict-`invalid` condition,
/// never an error.
fn epoch_binding_holds(
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
fn validate_proof_impl(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    signal_hex: &str,
    timestamp: &str,
    proof_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, rln_identifier, _) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    // Namespace support check only — no registry I/O on the verify path.
    provider_of(&registry)?;
    // Readiness gate FIRST (spec: not_ready before anything else). Size and
    // gap are the REGISTRY's (start() override or instance default).
    let size = epoch_size_for(&registry.canonical)?;
    let gap = epoch_gap_for(&registry.canonical);
    let now_epoch = rate_limit::current_epoch(now_unix(), size);
    let expected_epoch = epoch_of_timestamp(timestamp, size)?;
    let signal = registry_id::hex_to_vec(signal_hex)
        .ok_or_else(|| ApiError::new(ErrorKind::InvalidArgument, "signal must be hex"))?;
    let proof_value: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &format!("proof_json: {e}")))?;
    let rlp = proof::RateLimitProof::from_json(&proof_value).map_err(proof_error)?;

    // Application + epoch binding first — pure local computation, so a stale
    // or wrong-application proof rejects definitively even before the root
    // window is consulted.
    let bound = rlp.external_nullifier();
    if !epoch_binding_holds(rlp.epoch(), &bound, &rln_identifier, expected_epoch, now_epoch, gap)
    {
        return ok_json(views::VerdictReply::verdict("invalid"));
    }

    // Root window BEFORE any log touch: a cold/stale window is NOT_READY, never
    // a verdict, and must not leave a nullifier logged for an unservable proof.
    roots::track(&registry);
    let window = roots::window(&registry.canonical).ok_or_else(|| {
        ApiError::new(ErrorKind::NotReady, "valid-root window not warm yet; retry")
    })?;
    // A WARM window that simply doesn't carry the proof's root is the
    // freshly-published-root race (a just-activated membership's first
    // proofs) as often as it is a bad proof. The verdict stays "invalid"
    // (spec: zero registry access on this path), but nudge the refresher
    // for one out-of-band tick so the caller's retry lands against a fresh
    // window instead of waiting out the refresh interval.
    if !window.contains(&rlp.root()) {
        roots::nudge();
        return ok_json(views::VerdictReply::verdict("invalid"));
    }
    if !proof::verify(&rlp, &signal, &window).map_err(proof_error)? {
        // Invalid proofs are NOT logged — only a validated nullifier counts.
        return ok_json(views::VerdictReply::verdict("invalid"));
    }

    // The retention floor stays wall-clock-derived: a caller-chosen
    // timestamp must never move the nullifier log's prune floor.
    let retain_floor = now_epoch.saturating_sub(gap);
    let view = match nullifier_log::record_verified(
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
fn get_epoch_quota_impl(
    store: Result<&Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    timestamp: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    // Namespace support check only — the quota is served from local state.
    provider_of(&registry)?;
    // Readiness gate FIRST. The single epoch observation is fixed by the
    // caller's timestamp: taken once, it keys the remaining lookup. Size and
    // gap are the REGISTRY's (start() override or instance default).
    let size = epoch_size_for(&registry.canonical)?;
    let epoch_index = epoch_of_timestamp(timestamp, size)?;
    let now_epoch = rate_limit::current_epoch(now_unix(), size);
    if !epoch_in_window(epoch_index, now_epoch, epoch_gap_for(&registry.canonical)) {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "timestamp is outside the acceptable epoch window (now ± max_epoch_gap)",
        ));
    }

    let store = store?;
    let records = records_for_registry(store, &registry);
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
    ok_json(views::EpochQuotaView::new(epoch_index, rate_limit, remaining))
}

/// Registry parameters read (spec's optional extension): the
/// registry-declared bounds plus the module's configured epoch length. The
/// spec's SHOULD-check ("reject a configured epoch size that contradicts a
/// declared one") is vacuous here: `get_registry_bounds` declares no epoch
/// length (`active_duration`/`grace_period_duration` are the on-chain
/// membership-lifecycle clock, not the rate-limiting epoch).
fn get_registry_parameters_impl(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, _) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let prov = provider_of(&registry)?;

    let bounds = prov.get_registry_bounds(&registry)?;
    let view =
        views::RegistryParametersView::from_bounds(epoch_size_for(&registry.canonical)?, &bounds);
    ok_json(view)
}

// -------------------------------------------------------------------- module

/// The store handle: `Unready` carries the cause `on_context_ready` failed
/// with (or the never-initialized default) so every keystore op can surface
/// it; `Ready` is the open store.
enum StoreCell {
    Unready(String),
    Ready(Arc<Store>),
}

impl Default for StoreCell {
    fn default() -> StoreCell {
        StoreCell::Unready(sealed_store::store::UNINIT_MSG.to_string())
    }
}

#[derive(Default)]
struct LogosRlnModuleImpl {
    store: StoreCell,
}

impl LogosRlnModuleImpl {
    /// The open store, or `internal` naming why there is none.
    fn store(&self) -> Result<&Arc<Store>, ApiError> {
        match &self.store {
            StoreCell::Ready(store) => Ok(store),
            StoreCell::Unready(cause) => Err(ApiError::internal(cause)),
        }
    }

    /// (Re-)open the store in `dir`, adopt it, and publish it for the worker
    /// loops; on failure the cell records the cause every later op will
    /// surface. A previously adopted store is closed FIRST so its directory
    /// lock releases deterministically and the re-open can reacquire it —
    /// OS file locks conflict between file descriptions even within one
    /// process.
    fn open_store(&mut self, dir: std::path::PathBuf) {
        sealed_store::store::publish(None);
        if let StoreCell::Ready(prev) = &self.store {
            prev.close();
        }
        match Store::open(dir) {
            Ok(store) => {
                sealed_store::store::publish(Some(&store));
                self.store = StoreCell::Ready(store);
            }
            Err(e) => {
                // Fail closed: leave the store unready so every keystore op
                // errors rather than clobbering shared or existing state.
                eprintln!("store: {e}");
                self.store = StoreCell::Unready(e.to_string());
            }
        }
    }
}

impl LiblogosRlnModule for LogosRlnModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        panic_hook::install_once();
        // The lp client to the sibling RLN module must be created on this
        // (the host's main Qt) thread — see provider.rs.
        provider::init_client();
        if ctx.instance_persistence_path.is_empty() {
            // No cwd fallback: a keystore in an unknown directory is worse
            // than a hard error at the first keystore op (see README).
            eprintln!(
                "membership module: host provided no instance_persistence_path — keystore ops will fail"
            );
            sealed_store::store::publish(None);
            if let StoreCell::Ready(prev) = &self.store {
                prev.close();
            }
            self.store = StoreCell::Unready(
                sealed_store::store::OpenError::NoPersistencePath(
                    "no instance persistence path from the host — keystore ops are \
                     disabled (no silent cwd fallback; see README)"
                        .to_string(),
                )
                .to_string(),
            );
        } else {
            self.open_store(std::path::PathBuf::from(&ctx.instance_persistence_path));
            // Resume confirmation polling for records that were pending at
            // the last shutdown.
            if let StoreCell::Ready(store) = &self.store {
                if !store.pending_records().is_empty() {
                    poller::ensure_running();
                }
                // Full-lazy module-owned custody (keychain.rs): resume the
                // auto-owned session or self-provision on a fresh store, so
                // the keystore works with zero unlock calls. Opt out with
                // LOGOS_RLN_DISABLE_AUTO_UNLOCK=1 (user-password
                // deployments and the e2e manual-unlock probes) — the same
                // switch also refuses the wire op.
                if !keychain::auto_unlock_disabled() {
                    keychain::lazy_auto_unlock();
                }
            }
        }
    }

    fn unlock_keystore(&mut self, mut password: String) -> String {
        let result = self
            .store()
            .and_then(|s| s.unlock(&password))
            .and_then(|count| ok_json(views::UnlockKeystoreReply::new(count as u64)));
        password.zeroize();
        reply(result)
    }

    fn lock_keystore(&mut self) -> String {
        reply(self.store().map(|s| {
            s.lock();
            serde_json::json!({ "locked": true })
        }))
    }

    fn provision_wallet_home(&mut self, options_json: String) -> String {
        reply(wallet_home::provision_impl(&options_json))
    }

    fn unlock_keystore_auto(&mut self) -> String {
        reply(keychain::auto_unlock_impl())
    }

    fn remember_keystore_password(&mut self) -> String {
        reply(keychain::remember_impl())
    }

    fn register(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        options_json: String,
    ) -> String {
        reply(register_impl(self.store(), &registry_id, &rln_identifier_hex, &options_json))
    }

    fn get_membership_state(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
    ) -> String {
        reply(get_membership_state_impl(self.store(), &registry_id, &rln_identifier_hex))
    }

    fn get_memberships(&mut self, registry_id: String) -> String {
        reply(get_memberships_impl(self.store(), &registry_id))
    }

    fn select_membership(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        selector_json: String,
    ) -> String {
        reply(select_membership_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &selector_json,
        ))
    }

    fn get_merkle_proof(&mut self, registry_id: String, leaf_index: i64) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let prov = provider_of(&registry)?;
            if leaf_index < 0 {
                return Err(ApiError::new(ErrorKind::InvalidArgument, "leaf_index must be non-negative"));
            }
            prov.get_merkle_proof(&registry, leaf_index as u64)
        })())
    }

    fn get_valid_roots(&mut self, registry_id: String) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let prov = provider_of(&registry)?;
            let roots = prov.get_valid_roots(&registry)?;
            Ok(serde_json::json!({ "valid_roots": roots }))
        })())
    }

    fn generate_proof(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hex: String,
        timestamp: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(generate_proof_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &signal_hex,
            &timestamp,
        ))
    }

    fn validate_proof(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hex: String,
        timestamp: String,
        proof_json: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(validate_proof_impl(
            &registry_id,
            &rln_identifier_hex,
            &signal_hex,
            &timestamp,
            &proof_json,
        ))
    }

    fn get_epoch_quota(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        timestamp: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(get_epoch_quota_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &timestamp,
        ))
    }

    fn get_registry_parameters(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(get_registry_parameters_impl(&registry_id, &rln_identifier_hex))
    }

    fn start(&mut self, config_json: String) -> Result<serde_json::Value, String> {
        reply_result(start_impl(&config_json))
    }

    fn stop(&mut self) -> Result<serde_json::Value, String> {
        reply_result(stop_impl())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosRlnModuleImpl>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "no store" argument for `_impl` fns whose store access must never
    /// be reached (or must surface the uninitialized internal error).
    fn no_store<'a>() -> Result<&'a Arc<Store>, ApiError> {
        Err(ApiError::internal(sealed_store::store::UNINIT_MSG))
    }

    /// The wire's RegistryOptions array from (key, value) pairs — the LIP
    /// binding every register call site speaks.
    fn opts_arr(pairs: &[(&str, &str)]) -> String {
        serde_json::Value::Array(
            pairs
                .iter()
                .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
                .collect(),
        )
        .to_string()
    }

    /// Seed one membership the way the old tests seeded a MembershipMeta
    /// literal: insert (Pending), then push the cache row to the wanted
    /// state/leaf/rate. Needs the store unlocked.
    #[allow(clippy::too_many_arguments)]
    fn seed_membership(
        store: &Store,
        hash: &str,
        registry: &str,
        commitment_hex: &str,
        rln_identifier: &str,
        secret_hex: &str,
        state: MembershipState,
        leaf_index: u64,
        rate_limit: u64,
    ) {
        let identity = sealed_store::format::IdentityBlock {
            registry_id: registry.to_string(),
            rln_identifier: rln_identifier.to_string(),
            identity_commitment: commitment_hex.to_string(),
            submitted_at: now_unix(),
        };
        let credential = StoredCredential {
            identity_commitment: commitment_hex.to_string(),
            identity_nullifier: None,
            identity_secret_hash: secret_hex.to_string(),
            identity_trapdoor: None,
            registry_id: registry.to_string(),
        };
        store.insert(hash, identity, &credential).expect("seed insert");
        store
            .update_cache(hash, |m| {
                m.state = state;
                m.leaf_index = Some(leaf_index);
                m.rate_limit = Some(rate_limit);
            })
            .expect("seed cache");
    }

    /// A module instance wired to a fresh store in `dir` (the tests'
    /// on_context_ready stand-in), plus the store for direct seeding.
    fn imp_with_store(dir: std::path::PathBuf) -> (LogosRlnModuleImpl, Arc<Store>) {
        let mut imp = LogosRlnModuleImpl::default();
        imp.open_store(dir);
        let store = imp.store().expect("test store open").clone();
        (imp, store)
    }

    // Pins the error envelope's byte shape (alphabetical keys), including
    // the coarse RLN-API class.
    #[test]
    fn error_envelope_shape() {
        let e = ApiError::new(ErrorKind::UnknownRegistry, "no provider for namespace");
        assert_eq!(
            e.to_json(),
            r#"{"error":{"class":"permanent","kind":"unknown_registry","message":"no provider for namespace"}}"#
        );
        // The quartet mapping the shim relies on.
        assert_eq!(ErrorKind::Locked.class(), "not_ready");
        assert_eq!(ErrorKind::NotReady.class(), "not_ready");
        assert_eq!(ErrorKind::ProviderFailure.class(), "transient");
        assert_eq!(ErrorKind::BudgetExhausted.class(), "budget_exhausted");
        assert_eq!(ErrorKind::InvalidArgument.class(), "permanent");
    }

    // The `-> result` dialect: the generated dispatch wraps Ok/Err into the
    // LogosResult envelope, and the Err string is the JSON-encoded typed
    // error object.
    #[test]
    fn result_dialect_error_carries_typed_body() {
        // stop() tears down the global worker supervisor; serialize with the
        // other global-state tests and reset it after.
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let mut imp = LogosRlnModuleImpl::default();
        let err = imp
            .validate_proof("not-caip10".into(), "ef".repeat(32), "00".into(), "0".into(), "{}".into())
            .unwrap_err();
        assert_eq!(
            err,
            r#"{"class":"permanent","kind":"invalid_argument","message":"registry_id must be namespace:reference:account_address (CAIP-10), got 1 segment(s)"}"#
        );
        let ok = imp.stop().unwrap();
        assert_eq!(ok, serde_json::json!({ "stopped": true }));
        worker::reset_for_test();
    }

    #[test]
    fn start_configures_epoch_and_stop_tears_down() {
        // CONFIG is process-global; serialize with the other tests that read
        // or write it (the store lock is the crate's global-state lock).
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let out = start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 3}"#).unwrap();
        assert_eq!(out["started"], serde_json::json!(true));
        assert_eq!(out["epoch_size_sec"], serde_json::json!(600));
        assert_eq!(out["max_epoch_gap"], serde_json::json!(3));
        assert_eq!(epoch_size().unwrap(), 600);
        assert_eq!(epoch_gap(), 3);
        assert!(!worker::is_stopped());

        let out = stop_impl().unwrap();
        assert_eq!(out["stopped"], serde_json::json!(true));
        assert!(worker::is_stopped());

        // The gap defaults when omitted; the epoch size is required.
        let out = start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        assert!(!worker::is_stopped());
        assert_eq!(out["epoch_size_sec"], serde_json::json!(600));
        assert_eq!(out["max_epoch_gap"], serde_json::json!(DEFAULT_MAX_EPOCH_GAP));
        let err = start_impl(r#"{"max_epoch_gap": 2}"#).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
        assert!(err.message.contains("epoch_size_sec"), "got: {}", err.message);
    }

    // Spec: epoch size and max gap are per-REGISTRY configuration. A
    // registries entry may be an object carrying overrides; a plain string
    // entry inherits the instance defaults. The reply surfaces only the
    // overrides actually set.
    #[test]
    fn start_per_registry_overrides_select_epoch_config() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let reg_a = format!("logos:local:{}", "ab".repeat(32));
        let reg_b = format!("logos:local:{}", "cd".repeat(32));
        let cfg = serde_json::json!({
            "epoch_size_sec": 600,
            "max_epoch_gap": 2,
            "registries": [
                reg_a,
                {"registry_id": reg_b, "epoch_size_sec": 60, "max_epoch_gap": 5},
            ],
        })
        .to_string();
        let out = start_impl(&cfg).unwrap();
        assert_eq!(out["overrides"][reg_b.as_str()]["epoch_size_sec"], serde_json::json!(60));
        assert_eq!(out["overrides"][reg_b.as_str()]["max_epoch_gap"], serde_json::json!(5));
        assert!(
            out["overrides"].get(reg_a.as_str()).is_none(),
            "a plain string entry carries no override: {out}"
        );
        assert_eq!(epoch_size_for(&reg_a).unwrap(), 600);
        assert_eq!(epoch_gap_for(&reg_a), 2);
        assert_eq!(epoch_size_for(&reg_b).unwrap(), 60);
        assert_eq!(epoch_gap_for(&reg_b), 5);

        // Reconfiguring without overrides clears them (idempotent start).
        let out = start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        assert!(out.get("overrides").is_none(), "no overrides key when none are set: {out}");
        assert_eq!(epoch_size_for(&reg_b).unwrap(), 600);
    }

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
        let err = generate_proof_impl(no_store(), &registry, &rln_id_hex, signal_hex, &ts).unwrap_err();
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
        let ok = validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &ts, &proof_json).unwrap();
        assert_eq!(ok, serde_json::json!({ "verdict": "valid" }));

        // A different signal is invalid, not an error.
        let other = registry_id::bytes_to_hex(b"another-signal");
        let bad = validate_proof_impl(&registry, &rln_id_hex, &other, &ts, &proof_json).unwrap();
        assert_eq!(bad, serde_json::json!({ "verdict": "invalid" }));

        start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
    }

    // A WARM window that misses the proof's root answers `invalid` AND asks
    // the refresher for one out-of-band tick — the freshly-published-root
    // race resolves on the caller's retry instead of a full refresh
    // interval. The verification path itself still never reads the registry.
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
        assert_eq!(crate::worker::nudges_for_test(), before + 1, "a root miss must nudge");

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
        assert_eq!(crate::worker::nudges_for_test(), before, "a crypto-invalid proof must not nudge");
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
        let out =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &earlier, &proof_json).unwrap();
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
        let out =
            validate_proof_impl(&registry, &rln_id_hex, &signal_hex, &neighbor, &proof_json).unwrap();
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
        let first =
            validate_proof_impl(&registry, &rln_id_hex, &sig_a, &ts, &pa.to_json().to_string())
                .unwrap();
        assert_eq!(first, serde_json::json!({ "verdict": "valid" }));

        let sig_b = registry_id::bytes_to_hex(b"sig-B");
        let second =
            validate_proof_impl(&registry, &rln_id_hex, &sig_b, &ts, &pb.to_json().to_string())
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
            let out = validate_proof_impl(&registry, &rln_id_hex, &wrong, &ts, &proof_json).unwrap();
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
        let q = get_epoch_quota_impl(Ok(&store), &registry, &rln_id, &ts).unwrap();
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

        let fresh = get_epoch_quota_impl(Ok(&store), &registry, &rln_id, &ts).unwrap();
        assert_eq!(fresh["rate_limit"], serde_json::json!(100));
        assert_eq!(fresh["remaining"], serde_json::json!(100));
        let epoch_index = fresh["epoch_index"].as_u64().expect("numeric epoch index");
        assert_eq!(epoch_index, now / 600);

        // Spend two slots in the CURRENT epoch; the snapshot pairs the same
        // index with the decremented budget.
        store.reserve_message_id(&hash, &rln_id, epoch_index, epoch_index, 100, 600).unwrap();
        store.reserve_message_id(&hash, &rln_id, epoch_index, epoch_index, 100, 600).unwrap();
        let spent = get_epoch_quota_impl(Ok(&store), &registry, &rln_id, &ts).unwrap();
        assert_eq!(spent["epoch_index"], serde_json::json!(epoch_index));
        assert_eq!(spent["remaining"], serde_json::json!(98));

        // The queried epoch is fixed by the timestamp (spec): the NEXT epoch,
        // still inside the default gap, keeps its own untouched budget.
        let next_ts = ((epoch_index + 1) * 600).to_string();
        let next = get_epoch_quota_impl(Ok(&store), &registry, &rln_id, &next_ts).unwrap();
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

    // Every call passes its scope explicitly (spec: the Module holds no
    // default) — an empty registry_id or rln_identifier_hex is a plain parse
    // error on every scope-taking method, not a fallback.
    #[test]
    fn empty_scope_args_are_invalid_argument() {
        let registry = format!("logos:local:{}", "dd".repeat(32));
        let rln_id = "ef".repeat(32);

        let err = get_membership_state_impl(no_store(), "", "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = get_membership_state_impl(no_store(), &registry, "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = get_membership_state_impl(no_store(), "", &rln_id).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);

        let err = validate_proof_impl("", "", "00", "0", "{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = validate_proof_impl(&registry, "", "00", "0", "{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
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
        let err = generate_proof_impl(no_store(), &registry, &rln_id_hex, "nothex", &now_unix().to_string())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
    }

    // The path-cache miss/hit contract: cargo tests never link the real
    // sibling module, so `get_merkle_proof` is a DEAD TRANSPORT (no lp
    // client) — provider_failure proves a registry read was attempted. A
    // pre-filled cache (synthetic zero-sibling depth-20 path) must let
    // generate_proof succeed with ZERO registry I/O.
    #[test]
    fn generate_proof_impl_serves_cached_path_with_zero_registry_io() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-path-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

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
        let miss =
            generate_proof_impl(Ok(&store), &reg, &rln_id_hex, signal_hex, &now_unix().to_string())
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
        let out =
            generate_proof_impl(Ok(&store), &reg, &rln_id_hex, signal_hex, &now_unix().to_string())
                .expect("a warm cache entry needs no registry call");
        assert!(out.get("proof").and_then(|v| v.as_str()).is_some(), "got: {out}");
        assert!(out.get("root").and_then(|v| v.as_str()).is_some(), "got: {out}");
        assert_eq!(
            out.get("message_id").and_then(|v| v.as_u64()),
            Some(0),
            "first allocation on a fresh (rln_identifier, epoch): {out}"
        );
        assert_eq!(out.get("membership_hash").and_then(|v| v.as_str()), Some(hash.as_str()));

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

        let (mut imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

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
        let out = generate_proof_impl(Ok(&store), &reg, &rln_id_hex, "aa", &ts)
            .expect("a past-but-in-window timestamp still proves");
        assert_eq!(
            out.get("epoch_index").and_then(|v| v.as_u64()),
            Some(now_epoch - 1),
            "epoch must derive from the supplied timestamp, not the module clock: {out}"
        );

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
        let err = generate_proof_impl(no_store(), &registry, &rln_id_hex, "aa", &stale).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
        assert!(err.message.contains("window"), "got: {}", err.message);
        // Leave CONFIG set (per the suite convention): a trailing reset would
        // strand another serialized test that reads epoch_size() from ambient
        // config with NOT_READY.
    }

    // Frozen cross-crate wire contract: every MembershipState variant MUST
    // serialize to the exact string logos-lez-rln-module's
    // rln_core::membership_status returns. No shared type — this pin is the
    // single anchor forcing a coordinated rename on both sides.
    #[test]
    fn membership_state_wire_strings() {
        assert_eq!(serde_json::to_value(MembershipState::Unknown).unwrap(), serde_json::json!("unknown"));
        assert_eq!(serde_json::to_value(MembershipState::Pending).unwrap(), serde_json::json!("pending"));
        assert_eq!(serde_json::to_value(MembershipState::Failed).unwrap(), serde_json::json!("failed"));
        assert_eq!(serde_json::to_value(MembershipState::Active).unwrap(), serde_json::json!("active"));
        assert_eq!(serde_json::to_value(MembershipState::GracePeriod).unwrap(), serde_json::json!("grace_period"));
        assert_eq!(serde_json::to_value(MembershipState::Expired).unwrap(), serde_json::json!("expired"));
        assert_eq!(
            serde_json::to_value(MembershipState::ErasedAwaitsWithdrawal).unwrap(),
            serde_json::json!("erased_awaits_withdrawal")
        );
        assert_eq!(serde_json::to_value(MembershipState::Erased).unwrap(), serde_json::json!("erased"));
        assert_eq!(serde_json::to_value(MembershipState::Slashed).unwrap(), serde_json::json!("slashed"));
    }

    #[test]
    fn keystore_ops_without_store_report_internal() {
        // With no store initialized (host provided no persistence path),
        // every keystore op fails with the internal error, never panics.
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let mut imp = LogosRlnModuleImpl::default();
        let out = imp.lock_keystore();
        assert!(out.contains(r#""kind":"internal""#), "got: {out}");
    }

    #[test]
    fn register_validates_arguments_before_touching_anything() {
        let mut imp = LogosRlnModuleImpl::default();
        let rln_id = "ef".repeat(32);

        let out = imp.register("not-caip10".into(), rln_id.clone(), String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        let out = imp.register(
            "eip155:1:0xB9cd878C90E49F797B4431fBF4fb333108CB90e6".into(),
            rln_id.clone(),
            String::new(),
        );
        assert!(out.contains(r#""kind":"unknown_registry""#), "got: {out}");

        let logos = format!("logos:local:{}", "ab".repeat(32));
        let out = imp.register(logos.clone(), rln_id, opts_arr(&[("rate_limit", "0")]));
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        // A malformed rln_identifier is rejected before any state work.
        let out = imp.register(logos, "xyz".into(), String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
    }

    // The common rate_limit key is optional: absent, the module applies
    // DEFAULT_RATE_LIMIT (the registry declares no default today — see the
    // constant's TODO). The defaulted value lands on the Pending record.
    #[test]
    fn register_defaults_rate_limit_when_option_absent() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-ms-default-rate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut imp, _store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "ab".repeat(32));

        let out = imp.register(
            registry.clone(),
            "ef".repeat(32),
            opts_arr(&[("funding_holding_account_id", &"cd".repeat(32))]),
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
        let (mut imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let rln_id = "ef".repeat(32);

        // Part 1 — internal generation + dead transport: a credential is minted
        // and persisted in-module, then the funded submit fails against the
        // stub → provider_failure; the record remains (marked failed).
        let reg_a = format!("logos:local:{}", "ab".repeat(32));
        let funding =
            opts_arr(&[("rate_limit", "300"), ("funding_holding_account_id", &"cd".repeat(32))]);
        let out = imp.register(reg_a.clone(), rln_id.clone(), funding);
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

        let out = imp.register(reg_b.clone(), rln_id, opts_arr(&[("rate_limit", "250")]));
        assert!(!out.contains(r#""error""#), "idempotent short-circuit, no provider call: {out}");
        assert!(out.contains(r#""state":"active""#), "got: {out}");
        assert!(out.contains(r#""rate_limit":300"#), "existing registration's rate wins: {out}");
        assert!(out.contains(r#""rate_limit_mismatch":true"#), "got: {out}");
        assert!(out.contains(&format!(r#""membership_hash":"{hash}""#)), "got: {out}");

        // Part 3 — a DIFFERENT application (rln_identifier) on the same
        // registry is NOT the same scope: no short-circuit — register mints a
        // fresh credential for it (and then fails at the dead-transport
        // submit), leaving TWO records on the registry.
        let funding =
            opts_arr(&[("rate_limit", "300"), ("funding_holding_account_id", &"cd".repeat(32))]);
        let out = imp.register(reg_b.clone(), "aa".repeat(32), funding);
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
        let (mut imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let rln_id = "ef".repeat(32);
        let funding =
            opts_arr(&[("rate_limit", "300"), ("funding_holding_account_id", &"cd".repeat(32))]);

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

        let out = imp.register(reg_expired.clone(), rln_id.clone(), funding.clone());
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

        let out = imp.register(reg_erased.clone(), rln_id, funding);
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
        let (mut imp, _store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let rln_id = "ef".repeat(32);

        let out =
            imp.register(registry.clone(), rln_id.clone(), opts_arr(&[("delegated", "true")]));
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
        let out = imp.register(registry.clone(), rln_id.clone(), opts);
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
        let out = imp.register(registry.clone(), rln_id, opts);
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // RegistryOptions is the spec's char* key/value pair list: every value
    // is a STRING; a JSON bool (or any non-string) is a type error at the
    // array binding, never a coercion. A non-array options_json — including
    // the retired 0.5.0 object encoding — is rejected outright, and
    // duplicate keys are a caller bug. Fails before any store access, so no
    // unlock/init needed.
    #[test]
    fn register_rejects_non_string_values_and_non_array_options() {
        let mut imp = LogosRlnModuleImpl::default();
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let rln_id = "ef".repeat(32);

        let out = imp.register(
            registry.clone(),
            rln_id.clone(),
            r#"[{"key":"delegated","value":true}]"#.into(),
        );
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert!(out.contains("'delegated' must be a string"), "got: {out}");

        let out =
            imp.register(registry.clone(), rln_id.clone(), r#"{"delegated":"true"}"#.into());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");
        assert!(out.contains("must be a RegistryOptions array"), "got: {out}");

        let out = imp.register(
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
        let (mut imp, _store) = imp_with_store(dir.clone());
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
        let reg = |imp: &mut LogosRlnModuleImpl, extra: &str| {
            imp.register(registry.clone(), rln_id.clone(), opts(extra))
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
            let out = reg(&mut imp, extra);
            assert!(out.contains(r#""kind":"invalid_argument""#), "{extra} got: {out}");
            assert!(out.contains(expect), "{extra} got: {out}");
        }

        let out = imp.register(
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

    // The gifter request args carry the auth selection verbatim, and an
    // unspecified vector stays ABSENT rather than defaulting here.
    #[test]
    fn delegated_request_args_pass_auth_selection_through_verbatim() {
        let mut d = DelegatedOptions {
            gifter_peer_id: "p".into(),
            gifter_multiaddr: "/ip4/127.0.0.1/tcp/1".into(),
            auth_type: None,
            auth_payload: None,
            auth_provider: None,
            auth_args: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300)).unwrap();
        for key in ["authType", "authPayload", "authProvider", "authArgs"] {
            assert!(v.get(key).is_none(), "unset {key} must stay absent, got: {v}");
        }

        d.auth_type = Some("voucher-v1".into());
        d.auth_provider = Some("voucher_module".into());
        d.auth_args = Some(r#"{"campaign":"launch"}"#.into());
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300)).unwrap();
        assert_eq!(v["authType"], "voucher-v1", "got: {v}");
        assert_eq!(v["authProvider"], "voucher_module", "got: {v}");
        assert_eq!(v["authArgs"], r#"{"campaign":"launch"}"#, "got: {v}");
        assert!(v.get("authPayload").is_none(), "got: {v}");

        d.auth_provider = None;
        d.auth_args = None;
        d.auth_payload = Some("deadbeef".into());
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300)).unwrap();
        assert_eq!(v["authPayload"], "deadbeef", "got: {v}");
    }

    // select_membership returns the PUBLIC membership only — never the
    // secret, and without requiring an unlocked keystore.
    #[test]
    fn select_membership_returns_public_view_without_releasing_secret() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-select-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut imp, store) = imp_with_store(dir.clone());
        // Seeding a credential still needs unlock (writes are encrypted).
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

        let registry = format!("logos:local:{}", "cd".repeat(32));
        let commitment = [0x66u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        seed_membership(
            &store,
            &hash,
            &registry,
            &registry_id::bytes_to_hex(&commitment),
            "",
            &"77".repeat(32),
            MembershipState::Active,
            3,
            300,
        );

        let rln_id = "ef".repeat(32);
        // Even locked, select returns the public view — no secret, no error.
        assert!(imp.lock_keystore().contains(r#""locked":true"#));
        let out = imp.select_membership(registry.clone(), rln_id, String::new());
        assert!(out.contains(&format!(r#""membership_hash":"{hash}""#)), "got: {out}");
        assert!(
            !out.contains("identity_secret_hash"),
            "the identity secret must NEVER be released: {out}"
        );
        assert!(!out.contains(r#""kind":"locked""#), "no unlock required to select: {out}");
        assert!(imp.get_memberships(registry).contains(&hash));

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
            },
            alloc: rate_limit::AllocationState::default(),
            quarantined: false,
        };
        let out = public_membership_json("fixture-hash", &record, false, true);
        assert_eq!(
            out.to_string(),
            format!(
                r#"{{"credential":{{"identity_commitment":"{commitment}"}},"failed_reason":"submit_failed: boom","leaf_index":7,"membership_hash":"fixture-hash","rate_limit":300,"rate_limit_mismatch":true,"registry_id":"{registry}","retryable":true,"rln_identifier":"{rln_identifier}","state":"failed","submitted_at":1234567890,"tx_result":"tx-result-blob"}}"#
            )
        );

        // Quarantined forces state:"failed"/failed_reason:"metadata_tamper"
        // and SUPPRESSES retryable — never "just retry" a tamper verdict.
        // rate_limit_mismatch is only ever true or absent, never false.
        let quarantined = public_membership_json("fixture-hash", &record, true, false);
        assert_eq!(
            quarantined.to_string(),
            format!(
                r#"{{"credential":{{"identity_commitment":"{commitment}"}},"failed_reason":"metadata_tamper","leaf_index":7,"membership_hash":"fixture-hash","rate_limit":300,"registry_id":"{registry}","rln_identifier":"{rln_identifier}","state":"failed","submitted_at":1234567890,"tx_result":"tx-result-blob"}}"#
            )
        );
    }
}
