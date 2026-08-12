//! liblogos_lez_rln_module — the LEZ RLN registry provider.
//!
//! Serves the membership stack's chain access: registry reads (roots, merkle
//! proofs, membership PDA + lifecycle state, registry bounds), the Register
//! tx, and the faucet funding flow (claim_tokens / get_token_balance). The
//! chain logic lives in-crate (`mod rln_core`, plain Rust — no C ABI), and
//! wallet access is over raw `lp_*` protocol calls to the wallet module
//! (`logos_execution_zone`) with per-call timeouts (60s reads, 180s
//! registration tx) — the SDK's generated typed client has no per-call
//! timeout and would cap every call at the 20s protocol default.
//!
//! Identity and credential generation live in the membership
//! module (secrets never cross the module wire); this module only ever sees
//! the public id_commitment.
//!
//! Concurrency is SINGLE: dispatch runs on the module's own event loop, and
//! the blocking lp_invoke's QtRO wait loop pumps that same loop, so wallet
//! round-trips do not deadlock the process.

use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod rln_core;
use rln_core as native;
use rln_core::{bytes_to_hex, RlnRegisterPlan};

// Live-registry integration tests (env-gated, read-only): see the module's
// header for the LEZ_RLN_TESTNET_TESTS gate and deployment selection.
#[cfg(test)]
mod testnet_tests;

mod generated {
    #![allow(warnings)]
    #![allow(clippy::all)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
pub(crate) use generated::*;

const WALLET_MODULE: &str = "logos_execution_zone";
/// Timeout on account_id_from_base58 / get_account_public.
const READ_TIMEOUT_MS: c_int = 60_000;
/// Timeout on send_generic_public_transaction.
const TX_TIMEOUT_MS: c_int = 180_000;

// ---------------------------------------------------------------- lp raw ABI
//
// The lp_* consumer C ABI (the symbols resolve against the protocol archive
// linked into this plugin), declared here because the SDK's PluginProxy
// hardcodes timeout_ms = 0 (the 20s protocol default) with no public escape
// hatch. One shared client for the wallet target.
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

// The unit-test binary has no protocol archive to resolve lp_* against
// (the SDK leaves them for final plugin link); stub them as "no client".
#[cfg(test)]
mod lp {
    use std::ffi::{c_char, c_int};

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

struct WalletHandle(*mut lp::LpClient);
unsafe impl Send for WalletHandle {}

static WALLET_CLIENT: Mutex<Option<WalletHandle>> = Mutex::new(None);
static WALLET_OWNER: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

/// Lock a mutex, recovering the guard from a poisoned lock (a panicked
/// handler must not wedge every later one).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// In-flight registration dedup: one `(reply, inserted_at)` entry per
/// membership PDA this session; callers after the first get the first
/// submission's reply. Delivery fires register_member on two paths within
/// seconds, the on-chain pre-check cannot see a submission still confirming
/// (60-90s on testnet), and a duplicate Register submit poisons the gifter
/// wallet's nonce sequence for the whole confirmation window.
///
/// The key is the membership PDA hex — the canonical `(tree_id,
/// id_commitment)` identity — NOT the raw caller strings: equivalent but
/// differently-formatted inputs (`0xAB..` vs `ab..`, base58 vs 64-hex) must
/// land in the same slot.
type RegInFlightMap = std::collections::HashMap<String, (String, Instant)>;

static REG_IN_FLIGHT: Mutex<Option<RegInFlightMap>> = Mutex::new(None);

/// A submission that never applies on-chain must be re-submittable in the
/// same session, so entries expire; 300s still covers both the seconds-apart
/// double-fire and the 60-90s testnet confirmation delay.
const REG_IN_FLIGHT_TTL: Duration = Duration::from_secs(300);

fn reg_in_flight<R>(f: impl FnOnce(&mut RegInFlightMap) -> R) -> R {
    let mut guard = lock(&REG_IN_FLIGHT);
    let map = guard.get_or_insert_with(RegInFlightMap::new);
    map.retain(|_, (_, inserted_at)| inserted_at.elapsed() < REG_IN_FLIGHT_TTL);
    f(map)
}

/// Create the process-lifetime wallet lp client. MUST run on the host's main
/// Qt thread: lp_client_create makes the calling thread the client's owner
/// thread, the owner thread must run a Qt event loop (logos_protocol.h), and
/// async results are delivered FROM that thread. on_context_ready fires at
/// module load on the loader's thread — the main Qt loop — which is the only
/// thread of ours guaranteed to keep pumping for the process lifetime.
/// (Creating the client lazily inside a handler pins it to an ephemeral
/// concurrency:"multi" dispatch worker, and every reply is lost.)
fn init_wallet_client() {
    let mut slot = lock(&WALLET_CLIENT);
    if slot.is_some() {
        return;
    }
    let (Ok(target), Ok(origin)) = (CString::new(WALLET_MODULE), CString::new("core")) else {
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
        eprintln!("wallet_call: lp_client_create failed for {WALLET_MODULE}");
        return;
    }
    *slot = Some(WalletHandle(raw));
    *lock(&WALLET_OWNER) = Some(std::thread::current().id());
}

/// Reply slot for one in-flight wallet invoke: the trampoline reclaims the
/// box and sends (ok, raw json) exactly once, from the client's owner thread.
struct WalletReply {
    tx: std::sync::mpsc::Sender<(bool, String)>,
}

extern "C" fn wallet_reply_trampoline(
    ok: c_int,
    json: *const c_char,
    user_data: *mut std::ffi::c_void,
) {
    if user_data.is_null() {
        return;
    }
    let reply = unsafe { Box::from_raw(user_data as *mut WalletReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(json) }.to_string_lossy().into_owned()
    };
    let _ = reply.tx.send((ok != 0, raw));
}

/// The JSON string value of a raw lp result, or "" for anything else.
fn lp_result_to_string(raw: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// JSON-array args in, string result out. Failure (lp error, timeout,
/// non-string result) yields "".
///
/// Two paths by thread, per the lp_client owner-thread contract
/// (logos_protocol.h):
/// - On the owner thread (single-concurrency dispatch runs there): the
///   synchronous lp_invoke — its internal QtRO wait loop keeps pumping the
///   owner loop, so wallet round-trips do not deadlock dispatch.
/// - Off the owner thread: lp_invoke_async ("safe to call from any thread")
///   + a channel wait; the reply is delivered from the owner thread
///   whenever it pumps.
fn wallet_call(method: &str, args: &serde_json::Value, timeout_ms: c_int) -> String {
    let client = {
        let slot = lock(&WALLET_CLIENT);
        match slot.as_ref() {
            Some(h) => h.0,
            None => {
                eprintln!("wallet_call: {method} no wallet client");
                return String::new();
            }
        }
    };
    let (Ok(method_c), Ok(args_c)) = (
        CString::new(method),
        CString::new(args.to_string()),
    ) else {
        eprintln!("wallet_call: {method} args not CString-safe");
        return String::new();
    };

    let on_owner_thread = lock(&WALLET_OWNER)
        .map(|id| id == std::thread::current().id())
        .unwrap_or(false);
    if on_owner_thread {
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
                eprintln!("wallet_call: {method} lp error {rc}: {message}");
                unsafe { lp::lp_string_free(error_json) };
            } else {
                eprintln!("wallet_call: {method} lp error {rc}");
            }
            return String::new();
        }
        let raw = if result_json.is_null() {
            String::new()
        } else {
            let s = unsafe { CStr::from_ptr(result_json) }
                .to_string_lossy()
                .into_owned();
            unsafe { lp::lp_string_free(result_json) };
            s
        };
        return lp_result_to_string(&raw);
    }

    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let user_data = Box::into_raw(Box::new(WalletReply { tx })) as *mut std::ffi::c_void;
    let rc = unsafe {
        lp::lp_invoke_async(
            client,
            method_c.as_ptr(),
            args_c.as_ptr(),
            timeout_ms,
            wallet_reply_trampoline,
            user_data,
        )
    };
    if rc != lp::LP_OK {
        eprintln!("wallet_call: {method} lp_invoke_async dispatch failed rc={rc}");
        return String::new();
    }

    // The protocol owns timeout enforcement (timeout_ms above); the margin
    // only guards against a callback that never fires.
    let wait = Duration::from_millis(timeout_ms as u64 + 10_000);
    let (ok, raw) = match rx.recv_timeout(wait) {
        Ok(reply) => reply,
        Err(_) => {
            eprintln!("wallet_call: {method} reply channel timed out");
            return String::new();
        }
    };
    if !ok {
        let message = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
            .unwrap_or(raw);
        eprintln!("wallet_call: {method} lp error: {message}");
        return String::new();
    }
    lp_result_to_string(&raw)
}

// ------------------------------------------------------------------- helpers

/// Trim whitespace and strip an optional 0x/0X prefix.
fn strip_hex_prefix(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2 && (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
        &trimmed[2..]
    } else {
        trimmed
    }
}

/// Trims whitespace, strips an optional 0x/0X prefix, requires an even
/// number of hex digits and (when expected_len is given) an exact decoded
/// length.
fn hex_to_bytes(hex: &str, expected_len: Option<usize>) -> Option<Vec<u8>> {
    let digits = strip_hex_prefix(hex);
    if digits.len() % 2 != 0 {
        return None;
    }
    let bytes = digits.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    if let Some(expected) = expected_len {
        if out.len() != expected {
            return None;
        }
    }
    Some(out)
}

fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    hex_to_bytes(hex, Some(32)).map(|v| {
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    })
}

/// 64-hex (with optional 0x) passes through; anything else goes to the
/// wallet's account_id_from_base58 with the ORIGINAL untrimmed id. Empty
/// string on failure.
fn resolve_account_id(id: &str) -> String {
    let stripped = strip_hex_prefix(id);
    if stripped.len() == 64 {
        return stripped.to_string();
    }
    wallet_call(
        "account_id_from_base58",
        &serde_json::json!([id]),
        READ_TIMEOUT_MS,
    )
}

/// Tri-state fetch: Present / legitimately Absent (empty data) / Error
/// (RPC failure, malformed JSON or hex). Logs nothing.
enum FetchOutcome {
    Present(Vec<u8>),
    Absent,
    Error,
}

fn fetch_account_data_tri_state(account_id_hex: &str) -> FetchOutcome {
    let json = wallet_call(
        "get_account_public",
        &serde_json::json!([account_id_hex]),
        READ_TIMEOUT_MS,
    );
    if json.is_empty() {
        return FetchOutcome::Error;
    }
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&json) else {
        return FetchOutcome::Error;
    };
    let Some(obj) = doc.as_object() else {
        return FetchOutcome::Error;
    };
    let data_hex = obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
    if data_hex.is_empty() {
        return FetchOutcome::Absent;
    }
    match hex_to_bytes(data_hex, None) {
        Some(bytes) => FetchOutcome::Present(bytes),
        None => FetchOutcome::Error,
    }
}

/// Some(data) only for a populated, well-formed account; logs nothing. Used
/// where "not yet present" is an expected state (register_member pre-check,
/// membership polls).
fn fetch_account_data_quiet(account_id_hex: &str) -> Option<Vec<u8>> {
    match fetch_account_data_tri_state(account_id_hex) {
        FetchOutcome::Present(data) => Some(data),
        _ => None,
    }
}

/// Loud fetch: logs each failure mode. Optionally extracts and validates the
/// 32-byte program_owner; an empty owner field is tolerated and leaves
/// `owner_out` empty.
fn fetch_account_data(account_id_hex: &str, owner_out: Option<&mut Vec<u8>>) -> Option<Vec<u8>> {
    let json = wallet_call(
        "get_account_public",
        &serde_json::json!([account_id_hex]),
        READ_TIMEOUT_MS,
    );
    if json.is_empty() {
        eprintln!("fetchAccountData failed: empty response for {account_id_hex}");
        return None;
    }
    let parsed = serde_json::from_str::<serde_json::Value>(&json).ok();
    let Some(obj) = parsed.as_ref().and_then(|v| v.as_object()) else {
        let head: String = json.chars().take(200).collect();
        eprintln!("fetchAccountData failed: not a JSON object for {account_id_hex} got: {head}");
        return None;
    };
    let data_hex = obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
    if data_hex.is_empty() {
        eprintln!("fetchAccountData failed: empty data for {account_id_hex}");
        return None;
    }
    if let Some(owner_out) = owner_out {
        let owner_hex = obj
            .get("program_owner")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !owner_hex.is_empty() {
            match hex_to_bytes(owner_hex, Some(32)) {
                Some(owner) => *owner_out = owner,
                None => {
                    let head: String = owner_hex.chars().take(80).collect();
                    eprintln!("fetchAccountData: malformed program_owner hex: {head}");
                    return None;
                }
            }
        }
    }
    hex_to_bytes(data_hex, None)
}

/// The resolved config account (64-hex + raw data) and its 32-byte program
/// owner — the inputs every on-chain entry point needs.
struct RlnConfigContext {
    config_hex: String,
    config_data: Vec<u8>,
    program_owner: [u8; 32],
}

fn resolve_config_context(config_account_id: &str, who: &str) -> Option<RlnConfigContext> {
    let config_hex = resolve_account_id(config_account_id);
    if config_hex.is_empty() {
        eprintln!("{who}: failed to resolve config account");
        return None;
    }
    let mut owner_bytes = Vec::new();
    let Some(config_data) = fetch_account_data(&config_hex, Some(&mut owner_bytes)) else {
        eprintln!("{who}: failed to fetch config account");
        return None;
    };
    if owner_bytes.len() != 32 {
        eprintln!("{who}: invalid program_owner size {}", owner_bytes.len());
        return None;
    }
    let mut program_owner = [0u8; 32];
    program_owner.copy_from_slice(&owner_bytes);
    Some(RlnConfigContext {
        config_hex,
        config_data,
        program_owner,
    })
}

/// The risc0-serde u32 instruction words as the JSON array
/// `send_generic_public_transaction` expects.
fn words_to_json(words: &[u32]) -> Vec<serde_json::Value> {
    words.iter().map(|&w| serde_json::Value::from(w)).collect()
}

/// Submit one `send_generic_public_transaction` — the frozen 4-element args
/// array `[account_ids, signing_reqs, instruction_words, program_id]` — with
/// the 180s tx timeout (a sequencer submit can far outlive the 20s protocol
/// default). `None` = failed, already logged.
fn send_generic_tx(
    who: &str,
    account_ids: Vec<String>,
    signing_reqs: Vec<bool>,
    instruction_words: Vec<serde_json::Value>,
    program_id_hex: String,
) -> Option<String> {
    let send_result = wallet_call(
        "send_generic_public_transaction",
        &serde_json::json!([account_ids, signing_reqs, instruction_words, program_id_hex]),
        TX_TIMEOUT_MS,
    );
    if send_result.is_empty() {
        eprintln!("{who}: transaction failed");
        return None;
    }
    Some(send_result)
}

/// Funding-method entry (claim_tokens): reject negative amounts, resolve
/// the config context and the destination account. `None` = failed, already
/// logged. Returns `(amount as u128, config context, dest 64-hex)`.
fn funding_prologue(
    who: &str,
    config_account_id: &str,
    dest_account_id: &str,
    amount: i64,
) -> Option<(u128, RlnConfigContext, String)> {
    if amount < 0 {
        eprintln!("{who}: negative amount");
        return None;
    }
    let ctx = resolve_config_context(config_account_id, who)?;
    let dest_hex = resolve_account_id(dest_account_id);
    if dest_hex.is_empty() {
        eprintln!("{who}: failed to resolve dest account");
        return None;
    }
    Some((amount as u128, ctx, dest_hex))
}

fn derive_register_plan(
    ctx: &RlnConfigContext,
    id_commitment: &[u8; 32],
    who: &str,
) -> Option<RlnRegisterPlan> {
    let accounts_plan =
        match native::merkle_proofs_plan(&ctx.config_data, &ctx.program_owner, &[]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{who}: derive tree main failed: {e}");
                return None;
            }
        };
    let tree_main_hex = bytes_to_hex(&accounts_plan.main_account_id);
    let Some(tree_main_data) = fetch_account_data(&tree_main_hex, None) else {
        eprintln!("{who}: fetch tree main failed");
        return None;
    };
    match native::register_plan(
        &ctx.config_data,
        &tree_main_data,
        &ctx.program_owner,
        id_commitment,
    ) {
        Ok(plan) => Some(plan),
        Err(e) => {
            eprintln!("{who}: register_plan FFI failed: {e}");
            None
        }
    }
}

fn roots_to_json_array(roots: &[[u8; 32]]) -> serde_json::Value {
    serde_json::Value::Array(
        roots
            .iter()
            .map(|r| serde_json::Value::String(bytes_to_hex(r)))
            .collect(),
    )
}

/// Serialize proofs plus the shared `valid_roots` array to the wire JSON.
/// `serde_json::Value` objects are BTreeMaps, so keys serialize
/// alphabetically — the frozen wire order (pinned by
/// `augmented_proofs_match_legacy_string_roundtrip`).
fn proofs_with_roots_json(proofs: &[native::ProofJson], roots_array: &serde_json::Value) -> String {
    let augmented: Vec<serde_json::Value> = proofs
        .iter()
        .map(|p| {
            let mut obj = match serde_json::to_value(p) {
                Ok(serde_json::Value::Object(obj)) => obj,
                _ => serde_json::Map::new(),
            };
            obj.insert("valid_roots".to_string(), roots_array.clone());
            serde_json::Value::Object(obj)
        })
        .collect();
    serde_json::Value::Array(augmented).to_string()
}

// ------------------------------------------------------------- method bodies

fn get_valid_roots_impl(rln_account_id_hex: &str) -> String {
    let Some(ctx) = resolve_config_context(rln_account_id_hex, "get_valid_roots") else {
        return String::new();
    };

    // Derive tree main account via merkle_proofs_plan (no leaves needed).
    let plan = match native::merkle_proofs_plan(&ctx.config_data, &ctx.program_owner, &[]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("get_valid_roots: merkle_proofs_plan FFI error: {e}");
            return String::new();
        }
    };

    let main_hex = bytes_to_hex(&plan.main_account_id);
    let Some(main_data) = fetch_account_data(&main_hex, None) else {
        eprintln!("get_valid_roots: failed to fetch tree main account {main_hex}");
        return String::new();
    };

    let roots = match native::get_valid_roots(&main_data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("get_valid_roots: get_valid_roots FFI error: {e}");
            return String::new();
        }
    };

    roots_to_json_array(&roots).to_string()
}

fn get_merkle_proofs_impl(config_account_id: &str, leaf_indices_json: &str) -> String {
    let indices_doc = serde_json::from_str::<serde_json::Value>(leaf_indices_json).ok();
    let Some(indices_array) = indices_doc.as_ref().and_then(|v| v.as_array()) else {
        eprintln!("get_merkle_proofs: leaf_indices_json is not a JSON array");
        return String::new();
    };
    if indices_array.is_empty() {
        return "[]".to_string();
    }
    let mut leaf_indices: Vec<u64> = Vec::with_capacity(indices_array.len());
    for val in indices_array {
        if !val.is_number() {
            eprintln!("get_merkle_proofs: leaf index is not a number");
            return String::new();
        }
        // Non-integer numbers truncate toward zero.
        let idx = val
            .as_u64()
            .or_else(|| val.as_i64().map(|v| v as u64))
            .or_else(|| val.as_f64().map(|v| v as u64))
            .unwrap_or(0);
        leaf_indices.push(idx);
    }

    let Some(ctx) = resolve_config_context(config_account_id, "get_merkle_proofs") else {
        return String::new();
    };

    let plan = match native::merkle_proofs_plan(&ctx.config_data, &ctx.program_owner, &leaf_indices)
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("get_merkle_proofs: plan FFI error: {e}");
            return String::new();
        }
    };

    // Stable-snapshot loop: the wallet's reads aren't snapshot-bound, so the
    // subtree reads are bracketed by two main-account fetches; equal
    // valid_roots windows prove no mutation occurred and the (main, subtree)
    // pair is consistent.
    const K_MAX_SNAPSHOT_ATTEMPTS: usize = 5;
    let main_hex = bytes_to_hex(&plan.main_account_id);
    let subtree_count = plan.subtree_count as usize;

    let mut proofs: Vec<native::ProofJson> = Vec::new();
    let mut stable_roots: Vec<[u8; 32]> = Vec::new();
    let mut consistent = false;

    for attempt in 0..K_MAX_SNAPSHOT_ATTEMPTS {
        // Snapshot A — opens the read window.
        let Some(main_data) = fetch_account_data(&main_hex, None) else {
            eprintln!("get_merkle_proofs: failed to fetch main account {main_hex}");
            return String::new();
        };
        let roots_a = match native::get_valid_roots(&main_data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("get_merkle_proofs: get_valid_roots(A) FFI error: {e}");
                return String::new();
            }
        };

        // Subtree fetches are tri-state: Absent (not yet initialized) is
        // legitimate; Error routes into the snapshot retry instead of
        // silently substituting "empty" for an existing subtree.
        let mut subtrees: Vec<(u32, Vec<u8>)> = Vec::with_capacity(subtree_count);
        let mut subtree_fetch_errored = false;
        for i in 0..subtree_count {
            let subtree_hex = bytes_to_hex(&plan.subtree_account_ids[i]);
            match fetch_account_data_tri_state(&subtree_hex) {
                FetchOutcome::Present(data) => subtrees.push((plan.subtree_ids[i], data)),
                FetchOutcome::Absent => subtrees.push((plan.subtree_ids[i], Vec::new())),
                FetchOutcome::Error => {
                    eprintln!(
                        "get_merkle_proofs: subtree fetch errored {subtree_hex} (attempt {attempt}) — retrying snapshot"
                    );
                    subtree_fetch_errored = true;
                    break;
                }
            }
        }
        if subtree_fetch_errored {
            continue;
        }

        // Snapshot B — closes the read window.
        let Some(main_data_b) = fetch_account_data(&main_hex, None) else {
            eprintln!("get_merkle_proofs: refetch main account failed (attempt {attempt})");
            continue;
        };
        let roots_b = match native::get_valid_roots(&main_data_b) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("get_merkle_proofs: get_valid_roots(B) FFI error: {e}");
                return String::new();
            }
        };
        if roots_a != roots_b {
            eprintln!(
                "get_merkle_proofs: tree advanced during subtree reads; retrying for a consistent snapshot (attempt {attempt})"
            );
            continue;
        }

        // Stable window: build proofs from snapshot A's main data.
        let subtree_refs: Vec<(u32, &[u8])> = subtrees
            .iter()
            .map(|(id, data)| (*id, data.as_slice()))
            .collect();
        proofs = match native::merkle_proofs_exec(&main_data, &subtree_refs, &leaf_indices) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("get_merkle_proofs: exec FFI error: {e}");
                return String::new();
            }
        };
        stable_roots = roots_b;
        consistent = true;
        break;
    }

    if !consistent {
        // Never ship an internally-inconsistent proof (the poller keeps its
        // previous consistent cachedProof instead).
        eprintln!(
            "get_merkle_proofs: no consistent tree snapshot after {K_MAX_SNAPSHOT_ATTEMPTS} attempts"
        );
        return String::new();
    }

    // Inject valid_roots into each proof object so a single RPC returns both.
    proofs_with_roots_json(&proofs, &roots_to_json_array(&stable_roots))
}

// -------------------------------------------------------------------- module

#[derive(Default)]
struct LogosLezRlnModuleImpl;

impl LiblogosLezRlnModule for LogosLezRlnModuleImpl {
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {
        init_wallet_client();
    }

    fn get_valid_roots(&mut self, rln_account_id_hex: String) -> String {
        get_valid_roots_impl(&rln_account_id_hex)
    }

    fn get_merkle_proofs(&mut self, config_account_id: String, leaf_indices_json: String) -> String {
        get_merkle_proofs_impl(&config_account_id, &leaf_indices_json)
    }

    fn register_member(
        &mut self,
        config_account_id: String,
        user_holding_account_id: String,
        id_commitment_hex: String,
        rate_limit: i64,
    ) -> String {
        let Some(id_commitment) = hex_to_bytes32(&id_commitment_hex) else {
            eprintln!("register_member: invalid id_commitment hex");
            return String::new();
        };

        let Some(ctx) = resolve_config_context(&config_account_id, "register_member") else {
            return String::new();
        };

        let user_holding_hex = resolve_account_id(&user_holding_account_id);
        if user_holding_hex.is_empty() {
            eprintln!("register_member: failed to resolve user holding account");
            return String::new();
        }

        let Some(plan) = derive_register_plan(&ctx, &id_commitment, "register_member") else {
            return String::new();
        };

        let membership_pda_hex = bytes_to_hex(&plan.membership_account_id);

        // Idempotency pre-check: if the membership PDA is already populated
        // for this (tree_id, id_commitment), recover its leaf_index instead
        // of resubmitting — the on-chain Register handler enforces uniqueness
        // via Claim::Pda, so a resubmit always fails.
        if let Some(existing) = fetch_account_data_quiet(&membership_pda_hex) {
            if existing.len() >= 64 {
                if let Ok(membership) = native::decode_membership(&existing) {
                    eprintln!(
                        "register_member: membership already exists at leaf {} — skipping resubmit",
                        membership.leaf_index
                    );
                    return serde_json::json!({
                        "leaf_index": membership.leaf_index as i64,
                        "already_registered": true,
                    })
                    .to_string();
                }
            }
        }

        // In-flight dedup (see REG_IN_FLIGHT): the first caller submits;
        // concurrent and repeat callers get the first submission's reply.
        let reg_key = membership_pda_hex.clone();
        let placeholder = serde_json::json!({
            "leaf_index": plan.next_leaf_index as i64,
            "pending": true,
        })
        .to_string();
        let prior = reg_in_flight(|m| match m.get(&reg_key) {
            Some((reply, _)) => Some(reply.clone()),
            None => {
                m.insert(reg_key.clone(), (placeholder.clone(), Instant::now()));
                None
            }
        });
        if let Some(reply) = prior {
            eprintln!(
                "register_member: registration already submitted this session — returning prior reply"
            );
            return reply;
        }

        let instruction = match native::register_build_instruction(
            &plan.tree_id,
            &id_commitment,
            rate_limit as u64,
            plan.subtree_id,
        ) {
            Ok(words) => words,
            Err(e) => {
                eprintln!("register_member: build_instruction FFI error: {e}");
                reg_in_flight(|m| m.remove(&reg_key));
                return String::new();
            }
        };
        let instruction_words = words_to_json(&instruction);

        // Account order must match methods/guest/src/program.rs::register:
        //   config, tree_main, user_holding (signer), treasury, bottom_subtree,
        //   clock_account, membership (init).
        let account_ids: Vec<String> = vec![
            bytes_to_hex(&plan.config_account_id),
            bytes_to_hex(&plan.tree_main_account_id),
            user_holding_hex.clone(),
            bytes_to_hex(&plan.treasury_account_id),
            bytes_to_hex(&plan.subtree_account_id),
            bytes_to_hex(&plan.clock_account_id),
            bytes_to_hex(&plan.membership_account_id),
        ];
        // Only the user-holding (payer) account signs; the rest are read/PDA/init.
        let signing_reqs: Vec<bool> = account_ids
            .iter()
            .map(|a| *a == user_holding_hex)
            .collect();

        let Some(send_result) = send_generic_tx(
            "register_member",
            account_ids,
            signing_reqs,
            instruction_words,
            bytes_to_hex(&ctx.program_owner),
        ) else {
            reg_in_flight(|m| m.remove(&reg_key));
            return String::new();
        };

        // Return once the sequencer accepts the submission; don't block on
        // confirmation — next_leaf_index is only a pre-submit estimate.
        // Callers poll get_membership() for the authoritative leaf_index
        // from the membership PDA.
        let reply = serde_json::json!({
            "leaf_index": plan.next_leaf_index as i64,
            "tx_result": send_result,
            "pending": true,
        })
        .to_string();
        reg_in_flight(|m| m.insert(reg_key, (reply.clone(), Instant::now())));
        reply
    }

    fn claim_tokens(
        &mut self,
        config_account_id: String,
        dest_account_id: String,
        amount: i64,
    ) -> String {
        let Some((amount_u128, ctx, dest_hex)) =
            funding_prologue("claim_tokens", &config_account_id, &dest_account_id, amount)
        else {
            return String::new();
        };
        let (payment_def_id, instruction) =
            match native::claim_plan(&ctx.config_data, &ctx.program_owner, amount_u128) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("claim_tokens: plan error: {e}");
                    return String::new();
                }
            };
        let payment_def_hex = bytes_to_hex(&payment_def_id);
        // Claim tx accounts: [config, payment_def, dest (signer)]; config +
        // payment_def are program-authorized PDAs, only the destination signs.
        // Submitted under the REGISTRATION program (the config's program_owner).
        let Some(send_result) = send_generic_tx(
            "claim_tokens",
            vec![ctx.config_hex.clone(), payment_def_hex.clone(), dest_hex],
            vec![false, false, true],
            words_to_json(&instruction),
            bytes_to_hex(&ctx.program_owner),
        ) else {
            return String::new();
        };
        serde_json::json!({
            "tx_result": send_result,
            "payment_definition": payment_def_hex,
            "pending": true,
        })
        .to_string()
    }

    fn get_token_balance(&mut self, account_id: String) -> String {
        let account_hex = resolve_account_id(&account_id);
        if account_hex.is_empty() {
            eprintln!("get_token_balance: failed to resolve account");
            return String::new();
        }
        // Tri-state: Error ("" — sequencer/RPC failure, NOT zero) vs Absent
        // ({exists:false} — account not credited yet) vs Present.
        match fetch_account_data_tri_state(&account_hex) {
            FetchOutcome::Error => String::new(),
            FetchOutcome::Absent => {
                serde_json::json!({ "exists": false, "balance": "0" }).to_string()
            }
            FetchOutcome::Present(data) => match native::token_holding_info(&data) {
                Ok((definition_id, balance)) => serde_json::json!({
                    "exists": true,
                    "balance": balance.to_string(),
                    "definition": bytes_to_hex(&definition_id),
                })
                .to_string(),
                Err(e) => {
                    eprintln!("get_token_balance: holding decode error: {e}");
                    String::new()
                }
            },
        }
    }

    // ---- v1.1 additive surface (see the lidl): registry-provider reads for
    // the membership management module. Same conventions as the frozen
    // methods: "" = error, compact alphabetical JSON otherwise.

    fn get_membership(&mut self, config_account_id: String, id_commitment_hex: String) -> String {
        let Some(id_commitment) = hex_to_bytes32(&id_commitment_hex) else {
            eprintln!("get_membership: invalid id_commitment hex");
            return String::new();
        };

        // Same derivation path as register_member so the membership PDA
        // address is computed identically.
        let Some(ctx) = resolve_config_context(&config_account_id, "get_membership") else {
            return String::new();
        };
        let Some(plan) = derive_register_plan(&ctx, &id_commitment, "get_membership") else {
            return String::new();
        };

        // Absent covers both never-registered and erased/slashed (those empty
        // the PDA data entirely) — indistinguishable on this registry class.
        // Error is a transport/RPC failure and MUST NOT collapse into
        // "registered": false: the membership poller treats an authoritative
        // "not registered" as proof a live membership was erased and acts
        // destructively. "" maps to provider_failure, which the poller leaves
        // the record untouched for — the intended safe path.
        let membership_pda_hex = bytes_to_hex(&plan.membership_account_id);
        let data = match fetch_account_data_tri_state(&membership_pda_hex) {
            FetchOutcome::Present(data) => data,
            FetchOutcome::Absent => {
                return serde_json::json!({ "registered": false }).to_string();
            }
            FetchOutcome::Error => {
                eprintln!("get_membership: membership PDA fetch failed for {membership_pda_hex}");
                return String::new();
            }
        };
        let membership = match native::decode_membership(&data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("get_membership: membership decode error: {e}");
                return String::new();
            }
        };

        // Lifecycle state MUST come from chain time; the sequencer refreshes
        // CLOCK_50 every 50 blocks and the guest judges extend/erase against
        // it, so a local clock would disagree with the registry's view.
        let Some(clock_data) = fetch_account_data(&bytes_to_hex(&plan.clock_account_id), None)
        else {
            eprintln!("get_membership: failed to fetch clock account");
            return String::new();
        };
        let now = match native::decode_clock_timestamp(&clock_data) {
            Ok(ts) => ts,
            Err(e) => {
                eprintln!("get_membership: clock decode error: {e}");
                return String::new();
            }
        };

        serde_json::json!({
            "clock_timestamp": now,
            "grace_period_duration": membership.grace_period_duration,
            "grace_period_start_timestamp": membership.grace_period_start_timestamp,
            "leaf_index": membership.leaf_index as i64,
            "rate_limit": membership.rate_limit as i64,
            "registered": true,
            "state": native::membership_status(
                membership.grace_period_start_timestamp,
                membership.grace_period_duration,
                now,
            ),
        })
        .to_string()
    }

    fn get_registry_bounds(&mut self, config_account_id: String) -> String {
        let Some(ctx) = resolve_config_context(&config_account_id, "get_registry_bounds") else {
            return String::new();
        };
        if ctx.config_data.len() < native::CONFIG_STATE_MIN_SIZE {
            eprintln!("get_registry_bounds: config data too short");
            return String::new();
        }
        let cfg = &ctx.config_data;
        serde_json::json!({
            "active_duration":
                native::config_field_u32(cfg, native::CONFIG_OFFSET_ACTIVE_DURATION),
            "current_total_rate_limit":
                native::config_field_u64(cfg, native::CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT),
            "grace_period_duration":
                native::config_field_u32(cfg, native::CONFIG_OFFSET_GRACE_DURATION),
            "max_rate_limit": native::MAX_RATE_LIMIT,
            "max_total_rate_limit":
                native::config_field_u64(cfg, native::CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT),
            "min_rate_limit": native::MIN_RATE_LIMIT,
            // u128 exceeds JSON number precision → decimal string, like
            // get_token_balance's balance.
            "price_per_unit":
                native::config_field_u128(cfg, native::CONFIG_OFFSET_PRICE_PER_UNIT).to_string(),
            "total_registrations":
                native::config_field_u64(cfg, native::CONFIG_OFFSET_TOTAL_REGISTRATIONS),
        })
        .to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosLezRlnModuleImpl>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_mirrors_cpp_hex_to_bytes() {
        let hex = "00".repeat(31) + "ff";
        let b = hex_to_bytes32(&hex).unwrap();
        assert_eq!(b[31], 0xff);
        assert_eq!(bytes_to_hex(&b), hex);
        assert!(hex_to_bytes32(&(String::from("0x") + &hex)).is_some());
        assert!(hex_to_bytes32("zz").is_none());
        assert!(hex_to_bytes("abc", None).is_none());
        assert_eq!(hex_to_bytes(" 00ff ", None).unwrap(), vec![0x00, 0xff]);
    }

    // TTL eviction: a stale entry (Failed registration awaiting retry) must
    // fall out of the dedup map, while a fresh entry keeps deduping.
    #[test]
    fn reg_in_flight_entries_expire_after_ttl() {
        let stale_key = "aa".repeat(32);
        let fresh_key = "bb".repeat(32);
        let Some(back_dated) =
            Instant::now().checked_sub(REG_IN_FLIGHT_TTL + Duration::from_secs(1))
        else {
            eprintln!("reg_in_flight ttl test: uptime too short to back-date; skipping");
            return;
        };
        reg_in_flight(|m| {
            m.insert(stale_key.clone(), ("stale".to_string(), back_dated));
            m.insert(fresh_key.clone(), ("fresh".to_string(), Instant::now()));
        });
        reg_in_flight(|m| {
            assert!(!m.contains_key(&stale_key), "stale entry must be evicted");
            assert_eq!(m.get(&fresh_key).map(|(r, _)| r.as_str()), Some("fresh"));
            m.remove(&fresh_key);
        });
    }

    // Pins proofs_with_roots_json to the byte output of the string
    // round-trip (serialize → re-parse as Value → insert valid_roots →
    // re-serialize) that defines the frozen wire format.
    #[test]
    fn augmented_proofs_match_legacy_string_roundtrip() {
        let proofs = vec![native::ProofJson {
            leaf: "aa".repeat(32),
            root: "bb".repeat(32),
            leaf_index: 5,
            depth: 2,
            path_elements: vec!["cc".repeat(32), "dd".repeat(32)],
            path_indices: vec![1, 0],
        }];
        let roots_array = roots_to_json_array(&[[0xEE; 32]]);

        let legacy_json = serde_json::to_string(&proofs).unwrap();
        let legacy_parsed = serde_json::from_str::<serde_json::Value>(&legacy_json)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let legacy: Vec<serde_json::Value> = legacy_parsed
            .into_iter()
            .map(|p| {
                let mut obj = p.as_object().cloned().unwrap_or_default();
                obj.insert("valid_roots".to_string(), roots_array.clone());
                serde_json::Value::Object(obj)
            })
            .collect();
        let legacy_str = serde_json::Value::Array(legacy).to_string();

        let current_str = proofs_with_roots_json(&proofs, &roots_array);
        assert_eq!(current_str, legacy_str);
        // Alphabetical keys, valid_roots last.
        assert!(current_str.starts_with("[{\"depth\":2,\"leaf\":\"aa"));
        assert!(current_str.contains("\"root\":\"bb"));
        let expected_tail = format!("\"valid_roots\":[\"{}\"]}}]", "ee".repeat(32));
        assert!(current_str.ends_with(&expected_tail));
    }

    #[test]
    fn merkle_proofs_input_validation_shortcircuits() {
        // These paths return before any wallet call.
        assert_eq!(get_merkle_proofs_impl("cfg", "notjson"), "");
        assert_eq!(get_merkle_proofs_impl("cfg", "{}"), "");
        assert_eq!(get_merkle_proofs_impl("cfg", "[]"), "[]");
        assert_eq!(get_merkle_proofs_impl("cfg", "[\"x\"]"), "");
    }
}
