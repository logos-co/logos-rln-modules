//! liblogos_lez_rln_module — the LEZ RLN registry provider.
//!
//! Serves the membership stack's chain access: registry reads (roots, merkle
//! proofs, membership PDA + lifecycle state, registry bounds), the Register
//! tx, and the faucet funding flow (claim_tokens / get_token_balance). The
//! chain logic lives in-crate (`mod rln_core`, plain Rust — no C ABI), and
//! wallet access goes through the SDK's `PluginProxy` to the wallet module
//! (`lez_core`) with per-call timeouts (60s reads, 180s registration tx)
//! via `call_json_async_with_timeout` — no raw `lp_*` ABI in this crate.
//!
//! Identity and credential generation live in the membership
//! module (secrets never cross the module wire); this module only ever sees
//! the public id_commitment.
//!
//! Concurrency is "multi" (metadata.json, since 2.1.0): handlers run on Qt
//! worker threads and overlap, so one wallet round-trip stuck in a slow
//! sequencer read no longer wedges every other call. Every handler reaches
//! the wallet through the ASYNC call plus a channel wait (`wallet_call`): the
//! SDK delivers the reply from the module's Qt event loop, so the worker only
//! blocks on its channel and the loop stays free. The synchronous twin is
//! never used from a worker — it would marshal onto the main thread and
//! serialize every in-flight call behind one nested wait.

// Author code is unsafe-free: every outbound call goes through the SDK's
// safe `PluginProxy`. Three sites are exempted from `deny(unsafe_code)`, all
// of them C-ABI boundaries rather than logic: the generated module-impl
// scaffold, the install hook it resolves by linkage, and the test-only link
// stubs that stand in for the host's `lp_*` symbols.
#![deny(unsafe_code)]

use std::sync::Mutex;
use std::time::{Duration, Instant};


mod base58;
mod rln_core;
mod wallet;
use rln_core as native;
use rln_core::{bytes_to_hex, RlnRegisterPlan};

// Live-registry integration tests (env-gated, read-only): see the module's
// header for the LEZ_RLN_TESTNET_TESTS gate and deployment selection.
#[cfg(test)]
mod testnet_tests;

mod generated {
    #![allow(warnings)]
    #![allow(clippy::all)]
    #![allow(unsafe_code)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
pub(crate) use generated::*;

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

static REG_IN_FLIGHT: std::sync::LazyLock<Mutex<RegInFlightMap>> =
    std::sync::LazyLock::new(|| Mutex::new(RegInFlightMap::new()));

/// A submission that never applies on-chain must be re-submittable in the
/// same session, so entries expire; 300s still covers both the seconds-apart
/// double-fire and the 60-90s testnet confirmation delay.
const REG_IN_FLIGHT_TTL: Duration = Duration::from_secs(300);

fn reg_in_flight<R>(f: impl FnOnce(&mut RegInFlightMap) -> R) -> R {
    let mut map = lock(&REG_IN_FLIGHT);
    map.retain(|_, (_, inserted_at)| inserted_at.elapsed() < REG_IN_FLIGHT_TTL);
    f(&mut map)
}


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

// ------------------------------------------------------------------- helpers

/// Trim whitespace and strip an optional 0x/0X prefix.
fn strip_hex_prefix(s: &str) -> &str {
    let trimmed = s.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

/// Trims whitespace, strips an optional 0x/0X prefix, requires an even
/// number of hex digits and (when expected_len is given) an exact decoded
/// length.
fn hex_to_bytes(hex: &str, expected_len: Option<usize>) -> Option<Vec<u8>> {
    let digits = strip_hex_prefix(hex);
    if !digits.len().is_multiple_of(2) {
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
    wallet::account_id_from_base58(id)
}

/// Tri-state fetch: Present / legitimately Absent (empty data) / Error
/// (RPC failure, malformed JSON or hex). Logs nothing.
enum FetchOutcome {
    Present(Vec<u8>),
    Absent,
    Error,
}

fn fetch_account_data_tri_state(account_id_hex: &str) -> FetchOutcome {
    let json = wallet::get_account_public(account_id_hex);
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
/// where "not yet present" is an expected state — today only
/// register_member's idempotency pre-check.
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
    let json = wallet::get_account_public(account_id_hex);
    if json.is_empty() {
        eprintln!("fetch_account_data failed: empty response for {account_id_hex}");
        return None;
    }
    let parsed = serde_json::from_str::<serde_json::Value>(&json).ok();
    let Some(obj) = parsed.as_ref().and_then(|v| v.as_object()) else {
        let head: String = json.chars().take(200).collect();
        eprintln!("fetch_account_data failed: not a JSON object for {account_id_hex} got: {head}");
        return None;
    };
    let data_hex = obj.get("data").and_then(|v| v.as_str()).unwrap_or("");
    if data_hex.is_empty() {
        eprintln!("fetch_account_data failed: empty data for {account_id_hex}");
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
                    eprintln!("fetch_account_data: malformed program_owner hex: {head}");
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

/// The account that pays a transaction's fee, as 32-byte hex, or empty to let
/// the wallet charge the signing account.
///
/// v0.2.5 charges every public transaction, and the fee is reserved from a
/// *native* balance. A freshly created holding has tokens and no native
/// balance at all, so making the signer pay means a registration is refused
/// before it runs, with only "Incorrect fee" to say why.
///
/// `LEZ_RLN_PAYER` names a funded account the wallet already holds a key for —
/// the same variable the host tools use. It accepts base58 or hex, since the
/// tooling that mints the payer prints base58 and the wallet interface wants
/// hex. Unset means self-pay, which is right wherever the signing account is
/// itself funded.
fn fee_payer_hex() -> String {
    let Ok(raw) = std::env::var("LEZ_RLN_PAYER") else {
        return String::new();
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    if hex_to_bytes32(raw).is_some() {
        return raw.to_ascii_lowercase();
    }
    let resolved = wallet::account_id_from_base58(raw);
    if resolved.is_empty() {
        eprintln!("LEZ_RLN_PAYER is neither 32-byte hex nor a base58 account id: {raw}");
    }
    resolved
}

/// Submit one public transaction through the module's own wallet. `None` =
/// failed, already logged.
fn send_generic_tx(
    who: &str,
    account_ids: Vec<String>,
    signing_reqs: Vec<bool>,
    instruction: Vec<u8>,
    program_id_hex: String,
    payer_hex: String,
) -> Option<String> {
    let send_result = wallet::send_generic_public_transaction(
        &account_ids,
        &signing_reqs,
        &instruction,
        &program_id_hex,
        &payer_hex,
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
            eprintln!("{who}: register_plan failed: {e}");
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
            eprintln!("get_valid_roots: merkle_proofs_plan failed: {e}");
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
            eprintln!("get_valid_roots: valid_roots_from_main failed: {e}");
            return String::new();
        }
    };

    // The depth rides along because the consumer cannot use these roots
    // without it: a registry shallower than the prover's circuit has every
    // root lifted to the circuit's depth before it is compared with a root a
    // proof carries. It costs nothing — the header is already fetched.
    let depth = match native::tree_depth(&main_data) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("get_valid_roots: tree depth unreadable: {e}");
            return String::new();
        }
    };

    serde_json::json!({ "depth": depth, "valid_roots": roots_to_json_array(&roots) })
        .to_string()
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
            eprintln!("get_merkle_proofs: merkle_proofs_plan failed: {e}");
            return String::new();
        }
    };

    // Stable-snapshot loop: the wallet's reads aren't snapshot-bound, so the
    // subtree reads are bracketed by two main-account fetches; equal
    // valid_roots windows prove no mutation occurred and the (main, subtree)
    // pair is consistent.
    const MAX_SNAPSHOT_ATTEMPTS: usize = 5;
    let main_hex = bytes_to_hex(&plan.main_account_id);
    let subtree_count = plan.subtree_count as usize;

    let mut proofs: Vec<native::ProofJson> = Vec::new();
    let mut stable_roots: Vec<[u8; 32]> = Vec::new();
    let mut consistent = false;

    for attempt in 0..MAX_SNAPSHOT_ATTEMPTS {
        // Snapshot A — opens the read window.
        let Some(main_data) = fetch_account_data(&main_hex, None) else {
            eprintln!("get_merkle_proofs: failed to fetch main account {main_hex}");
            return String::new();
        };
        let roots_a = match native::get_valid_roots(&main_data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("get_merkle_proofs: valid_roots(A) failed: {e}");
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
                eprintln!("get_merkle_proofs: valid_roots(B) failed: {e}");
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
                eprintln!("get_merkle_proofs: merkle_proofs_exec failed: {e}");
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
            "get_merkle_proofs: no consistent tree snapshot after {MAX_SNAPSHOT_ATTEMPTS} attempts"
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
    /// Derive a fresh public account in this module's own wallet. The
    /// accounts it signs with have to be ones its own storage knows, so a
    /// consumer that needs a holding to fund and register with asks here.
    fn create_holding_account(&self) -> String {
        wallet::create_holding_account()
    }

    /// Whether the wallet this module owns is usable. Never fails — a
    /// consumer polls it to tell "still coming up" from "broken", because
    /// every chain-facing method answers "" in both cases.
    fn wallet_status(&self) -> String {
        wallet::status_json()
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        // Bring-up runs on its own thread: this hook fires on the host's Qt
        // main thread, and opening a wallet calibrates sequencers and then
        // syncs the chain — work the loop must not be holding.
        wallet::spawn_bring_up(&ctx.instance_persistence_path);
    }

    fn get_valid_roots(&self, rln_account_id_hex: String) -> String {
        get_valid_roots_impl(&rln_account_id_hex)
    }

    fn get_merkle_proofs(&self, config_account_id: String, leaf_indices_json: String) -> String {
        get_merkle_proofs_impl(&config_account_id, &leaf_indices_json)
    }

    fn register_member(
        &self,
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
        // decode_membership carries its own length guard (DataTooShort), so
        // a short or absent account simply fails to decode.
        if let Some(membership) = fetch_account_data_quiet(&membership_pda_hex)
            .and_then(|existing| native::decode_membership(&existing).ok())
        {
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
                eprintln!("register_member: register_build_instruction failed: {e}");
                reg_in_flight(|m| m.remove(&reg_key));
                return String::new();
            }
        };
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
            instruction,
            bytes_to_hex(&ctx.program_owner),
            fee_payer_hex(),
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
        &self,
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
            vec![ctx.config_hex.clone(), payment_def_hex.clone(), dest_hex.clone()],
            vec![false, false, true],
            instruction,
            bytes_to_hex(&ctx.program_owner),
            fee_payer_hex(),
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

    fn get_token_balance(&self, account_id: String) -> String {
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

    // ---- registry-provider reads, consumed by the membership management
    // module. Same conventions as the rest of the contract: "" = error,
    // compact alphabetical JSON otherwise.

    fn get_membership(&self, config_account_id: String, id_commitment_hex: String) -> String {
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

    fn get_registry_bounds(&self, config_account_id: String) -> String {
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

// The one `no_mangle` the scaffold contract requires of author code: the
// generated `__logos_install_hook` resolves this symbol by linkage.
#[allow(unsafe_code)]
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
