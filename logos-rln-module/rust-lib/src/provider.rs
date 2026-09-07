//! Registry provider layer: the spec's provider interface as a Rust trait,
//! namespace → provider routing, and the lez-rln provider — a client of the
//! sibling `liblogos_lez_rln_module` through the SDK's generated typed
//! client (`modules().liblogos_lez_rln_module`), plus a `PluginProxy` to the
//! gifter module.
//!
//! Every outbound call carries its own timeout (`READ_TIMEOUT`,
//! `REGISTER_TIMEOUT`, `GIFTER_REQUEST_TIMEOUT`) through the SDK's
//! `*_with_timeout` entry points; the raw `lp_*` C ABI this file used to bind
//! for that purpose is gone with logos-rust-sdk 80d028ab.
//!
//! Threading contract. Handlers run on `concurrency:"multi"` worker threads
//! and reach the sibling through the ASYNC twins plus a channel wait
//! (`await_reply`): the SDK delivers the callback from the module's Qt event
//! loop once the reply lands, so the worker only ever blocks on its channel
//! and the loop stays free for every other call. Never use the synchronous
//! twins from a worker — they marshal onto the main thread and serialize
//! every in-flight call behind one nested wait. `register_async` and the
//! gifter request are fire-and-record: their callback runs on the loop after
//! the dispatching handler has returned, so it may freely take the store
//! lock.
//!
//! Client lifetime. One shared client per target lives in a static for the
//! process lifetime (the SDK's cache holds only weak references, so a
//! transient `modules()` would create and destroy a client per call).
//! `init_client` warms both on the host's main thread at load; at protocol
//! 0.9 that is a courtesy, not a requirement — `lp_client_create` constructs
//! a Qt-affine client on the Qt main thread whoever calls it, so a worker
//! that finds no client may create one lazily.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use logos_rust_sdk::{LogosError, LogosModuleSDK, PluginProxy};

use crate::liblogos_lez_rln_module::LiblogosLezRlnModuleClient;
use crate::lifecycle::MembershipState;
use crate::registry_id::CanonicalRegistryId;
use crate::{lock, ApiError, ErrorKind};

const TARGET_MODULE: &str = "liblogos_lez_rln_module";
/// The sibling's reads run up to 60s against the wallet; add hop margin.
const READ_TIMEOUT: Duration = Duration::from_secs(70);
/// The sibling's register_member submits with a 180s tx timeout.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(190);
/// The protocol owns timeout enforcement; this margin only guards the channel
/// wait against a callback that never fires.
const REPLY_MARGIN: Duration = Duration::from_secs(10);

// ------------------------------------------------------------ shared clients

static LEZ_CLIENT: Mutex<Option<Arc<LiblogosLezRlnModuleClient>>> = Mutex::new(None);
static GIFTER_CLIENT: Mutex<Option<Arc<PluginProxy>>> = Mutex::new(None);

/// Warm the process-lifetime clients. Called from `on_context_ready` on the
/// host's main Qt thread so the one-time construction happens at load rather
/// than inside the first dispatch; safe to re-call.
pub(crate) fn init_client() {
    let _ = lez_client();
    let _ = gifter_client();
}

/// The shared typed client to the sibling, created on first use. The lock is
/// released before the caller makes any SDK call.
fn lez_client() -> Arc<LiblogosLezRlnModuleClient> {
    let mut slot = lock(&LEZ_CLIENT);
    Arc::clone(slot.get_or_insert_with(|| Arc::new(LiblogosLezRlnModuleClient::new())))
}

/// A client whose construction failed (the SDK answers every call with
/// "Failed to create protocol client") is dropped so the next call retries.
fn forget_lez_client() {
    *lock(&LEZ_CLIENT) = None;
}

/// Run one bounded async call from a worker and wait for its reply. `start`
/// receives the completion callback to hand to the SDK's `*_async_with_timeout`
/// twin. A transport failure, a dispatch refusal, or a silent callback all
/// collapse to the sibling's provider_failure (logged), so callers just `?`.
fn await_reply<T: Send + 'static>(
    method: &str,
    timeout: Duration,
    start: impl FnOnce(Box<dyn FnOnce(Result<T, LogosError>) + Send + 'static>),
) -> Result<T, ApiError> {
    let (tx, rx) = mpsc::channel::<Result<T, LogosError>>();
    start(Box::new(move |result| {
        let _ = tx.send(result);
    }));
    match rx.recv_timeout(timeout + REPLY_MARGIN) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => {
            if is_no_client(&e) {
                forget_lez_client();
            }
            eprintln!("membership provider: {method}: {e}");
            Err(provider_failure(method))
        }
        Err(_) => {
            eprintln!("membership provider: {method}: reply channel timed out");
            Err(provider_failure(method))
        }
    }
}

fn is_no_client(e: &LogosError) -> bool {
    matches!(e, LogosError::Other(msg) if msg.starts_with("Failed to create protocol client"))
}

/// One read of the sibling: its QString reply, where an empty reply is the
/// sibling's own ""-means-error convention and so a provider_failure.
fn read_reply(method: &str, reply: Result<String, ApiError>) -> Result<String, ApiError> {
    let value = reply?;
    if value.is_empty() {
        return Err(provider_failure(method));
    }
    Ok(value)
}

/// The SDK's completion as the `RegisterCallback`'s `Result`, with the
/// target's "" folded to provider_failure like every other reply.
fn fold_reply(method: &str, result: Result<String, LogosError>) -> Result<String, ApiError> {
    match result {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(provider_failure(method)),
        Err(e) => {
            eprintln!("membership provider: {method}: {e}");
            Err(provider_failure(method))
        }
    }
}

/// Fire-and-record dispatch, keeping the contract the raw ABI had: a
/// submission the SDK cannot even dispatch (no client, unencodable
/// arguments) is a SYNCHRONOUS `Err` here — the SDK reports that case from
/// the callback before `*_async_with_timeout` returns — so the record's owner
/// marks it failed once and surfaces the error; a reply that lands later
/// reaches `on_done` from the module's event loop after the dispatching
/// handler has returned. One mutex orders the two, so a completion racing the
/// return is delivered exactly once either way.
fn dispatch_recorded(
    method: &'static str,
    on_done: RegisterCallback,
    start: impl FnOnce(Box<dyn FnOnce(Result<String, LogosError>) + Send + 'static>),
) -> Result<(), ApiError> {
    struct Pending {
        dispatched: bool,
        on_done: Option<RegisterCallback>,
        sync_result: Option<Result<String, ApiError>>,
    }
    let state = Arc::new(Mutex::new(Pending {
        dispatched: false,
        on_done: Some(on_done),
        sync_result: None,
    }));
    let cb_state = Arc::clone(&state);
    start(Box::new(move |result| {
        let outcome = fold_reply(method, result);
        let mut st = lock(&cb_state);
        if !st.dispatched {
            st.sync_result = Some(outcome);
            return;
        }
        let cb = st.on_done.take();
        drop(st);
        if let Some(cb) = cb {
            cb(outcome);
        }
    }));
    let mut st = lock(&state);
    st.dispatched = true;
    match st.sync_result.take() {
        Some(Err(e)) => {
            st.on_done = None;
            Err(e)
        }
        Some(Ok(value)) => {
            let cb = st.on_done.take();
            drop(st);
            if let Some(cb) = cb {
                cb(Ok(value));
            }
            Ok(())
        }
        None => Ok(()),
    }
}

// ------------------------------------------------------------ gifter delegate

/// The delegated-registration executor (RLN Membership Allocation Protocol):
/// the co-located gifter client module. NOT declared in metadata.json
/// dependencies — deployments without a gifter module must still load, so it
/// is reached through an untyped `PluginProxy` rather than a generated client.
const GIFTER_MODULE: &str = "rln_gifter_module";
/// The gifter request budget: client-side payload production by the vector's
/// provider module (≤120s — keycard capture with a slow tap sets the bar)
/// plus the dial and the server-side on-chain register (≤205s), with
/// dispatch margin.
const GIFTER_REQUEST_TIMEOUT: Duration = Duration::from_secs(340);

fn gifter_client() -> Arc<PluginProxy> {
    let mut slot = lock(&GIFTER_CLIENT);
    Arc::clone(slot.get_or_insert_with(|| Arc::new(LogosModuleSDK::new().plugin(GIFTER_MODULE))))
}

/// Fire the gifter module's `request` with the module-generated commitment and
/// record the reply (fire-and-record). The gifter client produces the auth
/// payload via the selected vector's provider module
/// — bound to that commitment — then dials the gifter server, which verifies
/// through its configured vector and funds the on-chain register.
pub(crate) fn gifter_request_async(
    args_json: &str,
    on_done: RegisterCallback,
) -> Result<(), ApiError> {
    let client = gifter_client();
    let args = serde_json::json!([args_json]);
    dispatch_recorded("request", on_done, |done| {
        client.call_json_async_with_timeout("request", &args, GIFTER_REQUEST_TIMEOUT, move |result| {
            // The gifter answers a QString like the sibling does; anything
            // else is its failure value.
            done(result.map(|v| match v {
                serde_json::Value::String(s) => s,
                _ => String::new(),
            }))
        })
    })
}

// ----------------------------------------------------------- provider trait

/// The registry's view of one commitment (the spec provider's
/// `get_membership` return: state + authoritative leaf_index/rate_limit).
pub(crate) struct ProviderMembership {
    pub(crate) registered: bool,
    /// active | grace_period | expired (meaningful only when registered;
    /// `Unknown` placeholder otherwise, never read while `!registered`).
    pub(crate) state: MembershipState,
    pub(crate) leaf_index: u64,
    pub(crate) rate_limit: u64,
}

pub(crate) type RegisterCallback = Box<dyn FnOnce(Result<String, ApiError>) + Send>;

/// The spec's Registry Provider Interface. One instance serves every
/// registry of its namespace (the registry's anchor account travels in
/// `CanonicalRegistryId`).
pub(crate) trait RegistryProvider: Send + Sync {
    fn get_membership(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
    ) -> Result<ProviderMembership, ApiError>;

    /// Submit a registration without blocking: `on_done` receives the
    /// submission reply (acceptance, NOT application — confirmation is the
    /// poller's read-back) or the submission error. Runs on the module's
    /// event loop after the current dispatch returns.
    fn register_async(
        &self,
        registry: &CanonicalRegistryId,
        options_json: &str,
        id_commitment_hex: &str,
        rate_limit: u64,
        on_done: RegisterCallback,
    ) -> Result<(), ApiError>;

    fn get_merkle_proof(
        &self,
        registry: &CanonicalRegistryId,
        leaf_index: u64,
    ) -> Result<serde_json::Value, ApiError>;

    fn get_valid_roots(&self, registry: &CanonicalRegistryId)
        -> Result<Vec<String>, ApiError>;

    /// The registry's parameters (spec RegistryParameters — max_rate_limit and
    /// friends) as the sibling's raw bounds object. Backs the quota read.
    fn get_registry_bounds(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<serde_json::Value, ApiError>;
}

static LEZ_RLN: LezRlnProvider = LezRlnProvider;

/// Namespace routing (spec MUST). Unknown namespaces are the caller's
/// `unknown_registry` error.
pub(crate) fn provider_for(namespace: &str) -> Option<&'static dyn RegistryProvider> {
    match namespace {
        "logos" => Some(&LEZ_RLN),
        _ => None,
    }
}

// ---------------------------------------------------------- lez-rln provider

/// The `logos` namespace: lez-rln registries, anchored on the registration
/// program's config PDA, reached through the sibling liblogos_lez_rln_module.
struct LezRlnProvider;

fn provider_failure(method: &str) -> ApiError {
    ApiError::new(
        ErrorKind::ProviderFailure,
        &format!("{TARGET_MODULE}.{method} failed (empty reply)"),
    )
}

impl RegistryProvider for LezRlnProvider {
    fn get_membership(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
    ) -> Result<ProviderMembership, ApiError> {
        let client = lez_client();
        let raw = read_reply(
            "get_membership",
            await_reply("get_membership", READ_TIMEOUT, |done| {
                client.get_membership_async_with_timeout(
                    &registry.account,
                    id_commitment_hex,
                    READ_TIMEOUT,
                    done,
                )
            }),
        )?;
        let v: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| ApiError::new(ErrorKind::ProviderFailure, &format!("get_membership reply parse: {e}")))?;
        let registered = v.get("registered").and_then(|x| x.as_bool()).unwrap_or(false);
        if !registered {
            return Ok(ProviderMembership {
                registered: false,
                state: MembershipState::Unknown,
                leaf_index: 0,
                rate_limit: 0,
            });
        }
        // For a registered member these fields are the registry's contract —
        // a missing one is a provider fault, never a defaultable value (leaf 0
        // is a VALID leaf; defaulting would prove against the wrong
        // membership).
        let required = |key: &str| {
            v.get(key).and_then(|x| x.as_u64()).ok_or_else(|| {
                ApiError::new(
                    ErrorKind::ProviderFailure,
                    &format!("get_membership: registered member missing {key}"),
                )
            })
        };
        Ok(ProviderMembership {
            registered: true,
            state: serde_json::from_value::<MembershipState>(
                v.get("state").cloned().unwrap_or(serde_json::Value::Null),
            )
            .map_err(|_| {
                ApiError::new(
                    ErrorKind::ProviderFailure,
                    "get_membership: unrecognized state",
                )
            })?,
            leaf_index: required("leaf_index")?,
            rate_limit: required("rate_limit")?,
        })
    }

    fn register_async(
        &self,
        registry: &CanonicalRegistryId,
        options_json: &str,
        id_commitment_hex: &str,
        rate_limit: u64,
        on_done: RegisterCallback,
    ) -> Result<(), ApiError> {
        // lez-rln RegisterOptions: the funding holding account that pays
        // rate_limit × price_per_unit.
        let options: serde_json::Value = if options_json.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(options_json).map_err(|e| {
                ApiError::new(ErrorKind::InvalidArgument, &format!("options_json: {e}"))
            })?
        };
        let Some(funding) = options
            .get("funding_holding_account_id")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        else {
            return Err(ApiError::new(
                ErrorKind::InvalidArgument,
                "logos registries require options_json.funding_holding_account_id",
            ));
        };
        // The wire carries `int`; a rate the sibling could not even receive
        // is the caller's error, not a submission to be recorded.
        let rate_limit = i64::try_from(rate_limit).map_err(|_| {
            ApiError::new(ErrorKind::InvalidArgument, "rate_limit exceeds the wire's i64")
        })?;

        let client = lez_client();
        dispatch_recorded("register_member", on_done, |done| {
            client.register_member_async_with_timeout(
                &registry.account,
                funding,
                id_commitment_hex,
                rate_limit,
                REGISTER_TIMEOUT,
                done,
            )
        })
    }

    fn get_merkle_proof(
        &self,
        registry: &CanonicalRegistryId,
        leaf_index: u64,
    ) -> Result<serde_json::Value, ApiError> {
        let client = lez_client();
        let indices = format!("[{leaf_index}]");
        let raw = read_reply(
            "get_merkle_proofs",
            await_reply("get_merkle_proofs", READ_TIMEOUT, |done| {
                client.get_merkle_proofs_async_with_timeout(
                    &registry.account,
                    &indices,
                    READ_TIMEOUT,
                    done,
                )
            }),
        )?;
        let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("proofs reply parse: {e}"))
        })?;
        v.as_array()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or_else(|| {
                ApiError::new(
                    ErrorKind::ProviderFailure,
                    "empty proof array (leaf out of range?)",
                )
            })
    }

    fn get_valid_roots(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<Vec<String>, ApiError> {
        let client = lez_client();
        let raw = read_reply(
            "get_valid_roots",
            await_reply("get_valid_roots", READ_TIMEOUT, |done| {
                client.get_valid_roots_async_with_timeout(&registry.account, READ_TIMEOUT, done)
            }),
        )?;
        serde_json::from_str::<Vec<String>>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("roots reply parse: {e}"))
        })
    }

    fn get_registry_bounds(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<serde_json::Value, ApiError> {
        let client = lez_client();
        let raw = read_reply(
            "get_registry_bounds",
            await_reply("get_registry_bounds", READ_TIMEOUT, |done| {
                client.get_registry_bounds_async_with_timeout(&registry.account, READ_TIMEOUT, done)
            }),
        )?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("bounds reply parse: {e}"))
        })
    }
}

// ------------------------------------------------------- test-time transport

/// The unit-test binary links no logos-protocol archive, yet the SDK's client
/// path references the `lp_*` symbols by name. Define the ones that path can
/// reach as a "no client" transport — `lp_client_create` answers NULL, so
/// every call fails cleanly with the SDK's own error and nothing below the
/// ABI is ever exercised. The real symbols come from the protocol archive at
/// the final plugin link.
#[cfg(test)]
mod lp_test_transport {
    // `#[no_mangle]` definitions are what the crate-wide `deny(unsafe_code)`
    // exists to flag; these five exist only to give the test binary a link
    // target, and never run past returning "no client".
    #![allow(unsafe_code)]
    use std::ffi::{c_char, c_int, c_void};

    #[no_mangle]
    pub extern "C" fn lp_client_create(
        _target_module: *const c_char,
        _origin_module: *const c_char,
        _target_transport_json: *const c_char,
        _capability_transport_json: *const c_char,
    ) -> *mut c_void {
        std::ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn lp_client_destroy(_client: *mut c_void) {}

    #[no_mangle]
    pub extern "C" fn lp_invoke(
        _client: *mut c_void,
        _method: *const c_char,
        _args_json: *const c_char,
        _timeout_ms: c_int,
        _out_result_json: *mut *mut c_char,
        _out_error_json: *mut *mut c_char,
    ) -> c_int {
        -3
    }

    #[no_mangle]
    pub extern "C" fn lp_invoke_async(
        _client: *mut c_void,
        _method: *const c_char,
        _args_json: *const c_char,
        _timeout_ms: c_int,
        _cb: Option<extern "C" fn(c_int, *const c_char, *mut c_void)>,
        _user_data: *mut c_void,
    ) -> c_int {
        -3
    }

    #[no_mangle]
    pub extern "C" fn lp_string_free(_s: *mut c_char) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_id;

    // With the test transport (no client), every provider path must degrade
    // to provider_failure — never panic, never wedge.
    #[test]
    fn stubbed_transport_degrades_to_provider_failure() {
        let registry = registry_id::parse(&format!("logos:local:{}", "ab".repeat(32))).unwrap();
        let provider = provider_for("logos").unwrap();
        assert!(provider.get_membership(&registry, &"11".repeat(32)).is_err());
        assert!(provider.get_merkle_proof(&registry, 0).is_err());
        assert!(provider.get_valid_roots(&registry).is_err());
        // Fire-and-record: a submission the SDK cannot dispatch (no client)
        // is a synchronous provider_failure, and the callback is NOT also
        // invoked — the record's owner handles the failure exactly once.
        let fired = Arc::new(Mutex::new(false));
        let seen = Arc::clone(&fired);
        let err = provider
            .register_async(
                &registry,
                &format!(r#"{{"funding_holding_account_id":"{}"}}"#, "cd".repeat(32)),
                &"11".repeat(32),
                300,
                Box::new(move |_| {
                    *lock(&seen) = true;
                }),
            )
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::ProviderFailure);
        assert!(!*lock(&fired), "a synchronous failure must not also reach on_done");
    }

    #[test]
    fn register_requires_funding_option() {
        let registry = registry_id::parse(&format!("logos:local:{}", "ab".repeat(32))).unwrap();
        let provider = provider_for("logos").unwrap();
        let err = provider
            .register_async(&registry, "{}", &"11".repeat(32), 300, Box::new(|_| {}))
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
    }

    #[test]
    fn unknown_namespace_has_no_provider() {
        assert!(provider_for("eip155").is_none());
    }
}
