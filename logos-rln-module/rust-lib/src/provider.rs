//! Registry provider layer: the spec's provider interface as a Rust trait,
//! namespace → provider routing, and the lez-rln provider — a raw `lp_*`
//! wire client of the sibling `liblogos_lez_rln_module`.
//!
//! Binds the raw consumer C ABI rather than the SDK's generated typed
//! client: the generated `PluginProxy` hardcodes `timeout_ms = 0` (the ~20s
//! protocol default) at every call site with no per-call override, and calls
//! here need per-call timeouts ([`READ_TIMEOUT_MS`],
//! [`GIFTER_REQUEST_TIMEOUT_MS`]).
//!
//! Threading contract: the lp client is created once
//! on the host's main Qt thread (`init_client` from `on_context_ready`) and
//! is owner-thread-bound. On the owner thread `provider_call` uses the
//! synchronous `lp_invoke` (its QtRO wait loop pumps the owner loop); off
//! it (the poller thread) `lp_invoke_async` + a channel wait, replies
//! delivered from the owner thread whenever it pumps. `register_async` is
//! fire-and-record: the boxed callback runs on the owner thread when the
//! loop pumps — i.e. after the dispatching handler has returned — so it may
//! freely take the store lock.

use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

use crate::registry_id::CanonicalRegistryId;
use crate::store::MembershipState;
use crate::{lock, ApiError, ErrorKind};

const TARGET_MODULE: &str = "liblogos_lez_rln_module";
/// The sibling's reads run up to 60s against the wallet; add hop margin.
const READ_TIMEOUT_MS: c_int = 70_000;
/// The sibling's register_member submits with a 180s tx timeout.
const REGISTER_TIMEOUT_MS: c_int = 190_000;

// ---------------------------------------------------------------- lp raw ABI
//
// Same consumer C ABI the sibling binds (symbols resolve against the
// logos-protocol archive linked into this plugin).
#[cfg(not(test))]
mod lp {
    use std::ffi::{c_char, c_int};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    /// Result callback for `lp_invoke_async`: `ok != 0` → `json` is the
    /// result value; `ok == 0` → canonical error object. `json` is only
    /// valid for the duration of the callback.
    pub type LpResultCb =
        extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut std::ffi::c_void);

    extern "C" {
        pub fn lp_client_create(
            target_module: *const c_char,
            origin_module: *const c_char,
            target_transport_json: *const c_char,
            capability_transport_json: *const c_char,
        ) -> *mut LpClient;
        pub fn lp_invoke(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            out_result_json: *mut *mut c_char,
            out_error_json: *mut *mut c_char,
        ) -> c_int;
        pub fn lp_invoke_async(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            cb: LpResultCb,
            user_data: *mut std::ffi::c_void,
        ) -> c_int;
        pub fn lp_string_free(s: *mut c_char);
    }

    pub const LP_OK: c_int = 0;
}

// The unit-test binary has no protocol archive to resolve lp_* against;
// stub them as "no client". `unsafe` mirrors the extern ABI's signatures so
// call sites compile identically.
#[cfg(test)]
#[allow(clippy::missing_safety_doc)]
mod lp {
    use std::ffi::{c_char, c_int};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    pub type LpResultCb =
        extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut std::ffi::c_void);

    pub unsafe fn lp_client_create(
        _target_module: *const c_char,
        _origin_module: *const c_char,
        _target_transport_json: *const c_char,
        _capability_transport_json: *const c_char,
    ) -> *mut LpClient {
        std::ptr::null_mut()
    }

    pub unsafe fn lp_invoke(
        _client: *mut LpClient,
        _method: *const c_char,
        _args_json: *const c_char,
        _timeout_ms: c_int,
        _out_result_json: *mut *mut c_char,
        _out_error_json: *mut *mut c_char,
    ) -> c_int {
        -3
    }

    pub unsafe fn lp_invoke_async(
        _client: *mut LpClient,
        _method: *const c_char,
        _args_json: *const c_char,
        _timeout_ms: c_int,
        _cb: LpResultCb,
        _user_data: *mut std::ffi::c_void,
    ) -> c_int {
        -3
    }

    pub unsafe fn lp_string_free(_s: *mut c_char) {}

    pub const LP_OK: c_int = 0;
}

struct ClientHandle(*mut lp::LpClient);
// The lp client is only ever USED per its owner-thread contract; the handle
// itself may be read from any thread.
unsafe impl Send for ClientHandle {}

static PROVIDER_CLIENT: Mutex<Option<ClientHandle>> = Mutex::new(None);
static PROVIDER_OWNER: Mutex<Option<ThreadId>> = Mutex::new(None);

/// Create the process-lifetime lp client to the sibling RLN module. MUST
/// run on the host's main Qt thread (async replies are delivered FROM the
/// owner thread's pumping loop). Called from `on_context_ready`; safe to
/// re-call — the host may load this module before the target registers, so
/// dispatch paths retry via `ensure_client_on_owner_thread`.
pub(crate) fn init_client() {
    let mut slot = lock(&PROVIDER_CLIENT);
    if slot.is_some() {
        return;
    }
    let (Ok(target), Ok(origin)) = (CString::new(TARGET_MODULE), CString::new("core")) else {
        return;
    };
    let raw = unsafe {
        lp::lp_client_create(
            target.as_ptr(),
            origin.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if raw.is_null() {
        eprintln!("membership provider: lp_client_create failed for {TARGET_MODULE}");
        return;
    }
    *slot = Some(ClientHandle(raw));
    *lock(&PROVIDER_OWNER) = Some(std::thread::current().id());
}

/// Lazy owner-thread retry for hosts that ran `on_context_ready` before the
/// target module registered. Only the owner thread (or, before any client
/// exists, the single-concurrency dispatch thread — the same thread) may
/// create the client.
fn ensure_client_on_owner_thread() {
    let has_client = lock(&PROVIDER_CLIENT).is_some();
    if has_client {
        return;
    }
    let owner = *lock(&PROVIDER_OWNER);
    if owner.is_none() || owner == Some(std::thread::current().id()) {
        init_client();
    }
}

/// Acquire the owner-thread-bound lp client, lazily retrying creation for
/// hosts that ran `on_context_ready` before the target registered. A missing
/// client is the sibling's provider_failure (logged once per call).
fn owner_client(method: &str) -> Result<*mut lp::LpClient, ApiError> {
    ensure_client_on_owner_thread();
    let slot = lock(&PROVIDER_CLIENT);
    match slot.as_ref() {
        Some(h) => Ok(h.0),
        None => {
            eprintln!("membership provider: {method}: no lp client for {TARGET_MODULE}");
            Err(provider_failure(method))
        }
    }
}

struct AsyncReply {
    tx: std::sync::mpsc::Sender<(bool, String)>,
}

extern "C" fn reply_trampoline(ok: c_int, json: *const c_char, user_data: *mut std::ffi::c_void) {
    if user_data.is_null() {
        return;
    }
    let reply = unsafe { Box::from_raw(user_data as *mut AsyncReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned()
    };
    let _ = reply.tx.send((ok != 0, raw));
}

/// Interpret a raw lp result as the target's QString reply, "" otherwise —
/// the sibling module's own error value.
fn lp_result_to_string(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// One call to the sibling module: JSON-array args in, its QString reply out.
/// An empty reply, a missing client, or any transport error all collapse to
/// the sibling's provider_failure (its own ""-means-error convention), so
/// callers just `?` and never re-check for emptiness.
fn provider_call(
    method: &str,
    args: &serde_json::Value,
    timeout_ms: c_int,
) -> Result<String, ApiError> {
    let client = owner_client(method)?;
    let (Ok(method_c), Ok(args_c)) = (CString::new(method), CString::new(args.to_string()))
    else {
        eprintln!("membership provider: {method}: args not CString-safe");
        return Err(provider_failure(method));
    };

    let on_owner_thread = lock(&PROVIDER_OWNER)
        .map(|id| id == std::thread::current().id())
        .unwrap_or(false);
    let raw = if on_owner_thread {
        let mut result_json: *mut c_char = std::ptr::null_mut();
        let mut error_json: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            lp::lp_invoke(
                client,
                method_c.as_ptr(),
                args_c.as_ptr(),
                timeout_ms,
                &mut result_json,
                &mut error_json,
            )
        };
        if rc != lp::LP_OK {
            if !error_json.is_null() {
                let message = unsafe { CStr::from_ptr(error_json) }.to_string_lossy();
                eprintln!("membership provider: {method}: lp error {rc}: {message}");
                unsafe { lp::lp_string_free(error_json) };
            } else {
                eprintln!("membership provider: {method}: lp error {rc}");
            }
            return Err(provider_failure(method));
        }
        if result_json.is_null() {
            String::new()
        } else {
            let s = unsafe { CStr::from_ptr(result_json) }
                .to_string_lossy()
                .into_owned();
            unsafe { lp::lp_string_free(result_json) };
            s
        }
    } else {
        let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
        let user_data = Box::into_raw(Box::new(AsyncReply { tx })) as *mut std::ffi::c_void;
        let rc = unsafe {
            lp::lp_invoke_async(
                client,
                method_c.as_ptr(),
                args_c.as_ptr(),
                timeout_ms,
                reply_trampoline,
                user_data,
            )
        };
        if rc != lp::LP_OK {
            // The callback will never fire; reclaim the box.
            drop(unsafe { Box::from_raw(user_data as *mut AsyncReply) });
            eprintln!("membership provider: {method}: lp_invoke_async dispatch failed rc={rc}");
            return Err(provider_failure(method));
        }

        // The protocol owns timeout enforcement; the margin only guards against
        // a callback that never fires.
        let wait = Duration::from_millis(timeout_ms as u64 + 10_000);
        let (ok, raw) = match rx.recv_timeout(wait) {
            Ok(reply) => reply,
            Err(_) => {
                eprintln!("membership provider: {method}: reply channel timed out");
                return Err(provider_failure(method));
            }
        };
        if !ok {
            let message = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or(raw);
            eprintln!("membership provider: {method}: lp error: {message}");
            return Err(provider_failure(method));
        }
        raw
    };
    let value = lp_result_to_string(&raw);
    if value.is_empty() {
        return Err(provider_failure(method));
    }
    Ok(value)
}

// ------------------------------------------------- fire-and-record submission

/// Boxed-callback plumbing shared by the fire-and-record submit paths (the
/// funded register_member, the delegated gifter request). The reply lands on
/// the owner thread after the dispatching handler has returned, so the
/// callback may freely take the store lock.
struct SubmitReply {
    method: &'static str,
    on_done: Option<RegisterCallback>,
}

extern "C" fn submit_trampoline(ok: c_int, json: *const c_char, user_data: *mut std::ffi::c_void) {
    if user_data.is_null() {
        return;
    }
    let mut reply = unsafe { Box::from_raw(user_data as *mut SubmitReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned()
    };
    let value = if ok != 0 { lp_result_to_string(&raw) } else { String::new() };
    if let Some(cb) = reply.on_done.take() {
        if value.is_empty() {
            cb(Err(provider_failure(reply.method)));
        } else {
            cb(Ok(value));
        }
    }
}

/// Dispatch one fire-and-record call: `on_done` receives the target's QString
/// reply (or the transport error) once it lands.
fn invoke_async_recorded(
    client: *mut lp::LpClient,
    method: &'static str,
    args: &serde_json::Value,
    timeout_ms: c_int,
    on_done: RegisterCallback,
) -> Result<(), ApiError> {
    let (Ok(method_c), Ok(args_c)) = (CString::new(method), CString::new(args.to_string())) else {
        return Err(ApiError::internal("submit args not CString-safe"));
    };
    let user_data = Box::into_raw(Box::new(SubmitReply {
        method,
        on_done: Some(on_done),
    })) as *mut std::ffi::c_void;
    let rc = unsafe {
        lp::lp_invoke_async(
            client,
            method_c.as_ptr(),
            args_c.as_ptr(),
            timeout_ms,
            submit_trampoline,
            user_data,
        )
    };
    if rc != lp::LP_OK {
        drop(unsafe { Box::from_raw(user_data as *mut SubmitReply) });
        return Err(ApiError::new(
            ErrorKind::ProviderFailure,
            &format!("{method} dispatch failed rc={rc}"),
        ));
    }
    Ok(())
}

// ------------------------------------------------------------ gifter delegate

/// The delegated-registration executor (RLN Membership Allocation Protocol):
/// the co-located gifter client module. NOT declared in metadata.json
/// dependencies — deployments without a gifter module must still load.
const GIFTER_MODULE: &str = "rln_gifter_module";
/// The gifter request budget: client-side payload production by the vector's
/// provider module (≤120s — keycard capture with a slow tap sets the bar)
/// plus the dial and the server-side on-chain register (≤205s), with
/// dispatch margin.
const GIFTER_REQUEST_TIMEOUT_MS: c_int = 340_000;

static GIFTER_CLIENT: Mutex<Option<ClientHandle>> = Mutex::new(None);

/// Owner-thread-lazy client to the gifter module — created on first delegated
/// register, never at init.
fn gifter_client(method: &str) -> Result<*mut lp::LpClient, ApiError> {
    if lock(&GIFTER_CLIENT).is_none() {
        let owner = *lock(&PROVIDER_OWNER);
        if owner.is_none() || owner == Some(std::thread::current().id()) {
            if let (Ok(target), Ok(origin)) = (CString::new(GIFTER_MODULE), CString::new("core")) {
                let raw = unsafe {
                    lp::lp_client_create(
                        target.as_ptr(),
                        origin.as_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                };
                if raw.is_null() {
                    eprintln!("membership provider: lp_client_create failed for {GIFTER_MODULE}");
                } else {
                    *lock(&GIFTER_CLIENT) = Some(ClientHandle(raw));
                }
            }
        }
    }
    match lock(&GIFTER_CLIENT).as_ref() {
        Some(h) => Ok(h.0),
        None => Err(ApiError::new(
            ErrorKind::ProviderFailure,
            &format!("{GIFTER_MODULE}.{method}: no lp client (is the gifter module loaded?)"),
        )),
    }
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
    let client = gifter_client("request")?;
    invoke_async_recorded(
        client,
        "request",
        &serde_json::json!([args_json]),
        GIFTER_REQUEST_TIMEOUT_MS,
        on_done,
    )
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
    /// poller's read-back) or the submission error. Runs on the owner
    /// thread after the current dispatch returns.
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
        let raw = provider_call(
            "get_membership",
            &serde_json::json!([registry.account, id_commitment_hex]),
            READ_TIMEOUT_MS,
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

        let client = owner_client("register_member")?;
        let args = serde_json::json!([registry.account, funding, id_commitment_hex, rate_limit]);
        invoke_async_recorded(client, "register_member", &args, REGISTER_TIMEOUT_MS, on_done)
    }

    fn get_merkle_proof(
        &self,
        registry: &CanonicalRegistryId,
        leaf_index: u64,
    ) -> Result<serde_json::Value, ApiError> {
        let raw = provider_call(
            "get_merkle_proofs",
            &serde_json::json!([registry.account, format!("[{leaf_index}]")]),
            READ_TIMEOUT_MS,
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
        let raw = provider_call(
            "get_valid_roots",
            &serde_json::json!([registry.account]),
            READ_TIMEOUT_MS,
        )?;
        serde_json::from_str::<Vec<String>>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("roots reply parse: {e}"))
        })
    }

    fn get_registry_bounds(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<serde_json::Value, ApiError> {
        let raw = provider_call(
            "get_registry_bounds",
            &serde_json::json!([registry.account]),
            READ_TIMEOUT_MS,
        )?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("bounds reply parse: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_id;

    // With the test lp stub (rc = -3, no client), every provider path must
    // degrade to provider_failure — never panic, never wedge.
    #[test]
    fn stubbed_transport_degrades_to_provider_failure() {
        let registry = registry_id::parse(&format!("logos:local:{}", "ab".repeat(32))).unwrap();
        let provider = provider_for("logos").unwrap();
        assert!(provider.get_membership(&registry, &"11".repeat(32)).is_err());
        assert!(provider.get_merkle_proof(&registry, 0).is_err());
        assert!(provider.get_valid_roots(&registry).is_err());
        let err = provider
            .register_async(
                &registry,
                &format!(r#"{{"funding_holding_account_id":"{}"}}"#, "cd".repeat(32)),
                &"11".repeat(32),
                300,
                Box::new(|_| {}),
            )
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::ProviderFailure);
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
