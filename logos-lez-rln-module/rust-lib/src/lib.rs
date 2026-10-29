//! liblogos_lez_rln_module — the LEZ RLN registry provider.
//!
//! Serves the membership stack's chain access: registry reads (membership PDA
//! and lifecycle state, registry bounds) and the Register tx. Since 7.0.0 the
//! program keeps no merkle tree: a zone service builds it off chain from the
//! program's events, and the membership module asks that service for roots
//! and proofs. The leaf index is this module's: it records the claim of each
//! Register it sends (`leaf_claims.rs`). The
//! chain logic lives in-crate (`mod rln_core`, plain Rust — no C ABI), and
//! wallet access goes to the wallet module (`lez_core`, since 7.0.0 again)
//! through a typed client generated from `deps/lez_core.lidl`, with per-call
//! timeouts (60s reads, 180s registration tx) — no raw `lp_*` ABI in this
//! crate. This module opens that wallet itself when nothing else has
//! (`wallet.rs`).
//!
//! Identity and credential generation live in the membership
//! module (secrets never cross the module wire); this module only ever sees
//! the public id_commitment.
//!
//! Concurrency is "multi" (metadata.json, since 2.1.0): handlers run on Qt
//! worker threads and overlap, so one wallet round-trip stuck in a slow
//! sequencer read no longer wedges every other call. Every handler reaches
//! the wallet through the ASYNC call plus a channel wait (`await_reply` in
//! `wallet.rs`): the
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
mod fee_state;
mod leaf_claims;
mod networks;
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

/// The native token program's id: the shard key of an account's native
/// balance (LEZ v0.3.0 `NATIVE_TOKEN_PROGRAM_ID`).
const NATIVE_TOKEN_PROGRAM: [u8; 32] = [0; 32];

/// Tri-state fetch: Present / legitimately Absent (no such shard, or an empty
/// one) / Error (RPC failure, malformed JSON or hex). Logs nothing.
enum FetchOutcome {
    Present(Vec<u8>),
    Absent,
    Error,
}

/// Every shard of an account as `(program, data)`, or `None` when the read
/// failed. An account that does not exist reads as no shards.
///
/// LEZ v0.3.0 shards an account's data by owning program, so "the account's
/// data" is no longer one thing: callers name the program whose shard they
/// mean.
fn fetch_shards(account_id_hex: &str) -> Option<Vec<([u8; 32], Vec<u8>)>> {
    let json = wallet::get_account_public(account_id_hex);
    if json.is_empty() {
        return None;
    }
    let doc = serde_json::from_str::<serde_json::Value>(&json).ok()?;
    let shards = doc.as_object()?.get("shards")?.as_object()?;
    let mut out = Vec::with_capacity(shards.len());
    for (program_hex, data) in shards {
        let program = hex_to_bytes32(program_hex)?;
        let data = hex_to_bytes(data.as_str()?, None)?;
        out.push((program, data));
    }
    Some(out)
}

fn fetch_shard_tri_state(account_id_hex: &str, program: &[u8; 32]) -> FetchOutcome {
    let Some(shards) = fetch_shards(account_id_hex) else {
        return FetchOutcome::Error;
    };
    match shards.into_iter().find(|(p, _)| p == program) {
        Some((_, data)) if !data.is_empty() => FetchOutcome::Present(data),
        _ => FetchOutcome::Absent,
    }
}

/// Some(data) only for a populated shard; logs nothing. Used where "not yet
/// present" is an expected state — today only register_member's idempotency
/// pre-check.
fn fetch_shard_quiet(account_id_hex: &str, program: &[u8; 32]) -> Option<Vec<u8>> {
    match fetch_shard_tri_state(account_id_hex, program) {
        FetchOutcome::Present(data) => Some(data),
        _ => None,
    }
}

/// Loud fetch of one program's shard: logs each failure mode.
fn fetch_shard(account_id_hex: &str, program: &[u8; 32], who: &str) -> Option<Vec<u8>> {
    match fetch_shard_tri_state(account_id_hex, program) {
        FetchOutcome::Present(data) => Some(data),
        FetchOutcome::Absent => {
            eprintln!(
                "{who}: {account_id_hex} has no shard of program {}",
                bytes_to_hex(program)
            );
            None
        }
        FetchOutcome::Error => {
            eprintln!("{who}: reading {account_id_hex} failed");
            None
        }
    }
}

/// The resolved config and the program every on-chain entry point needs: the
/// registration program (the config's owner, and the program every PDA hangs
/// off).
struct RlnConfigContext {
    config_data: Vec<u8>,
    registration_program: [u8; 32],
}

/// Why a config account cannot serve as a registry here. `status` is the
/// machine-readable kind check_registry reports; `detail` says it for a person.
struct RegistryProblem {
    status: &'static str,
    detail: String,
}

impl RegistryProblem {
    fn new(status: &'static str, detail: String) -> Self {
        Self { status, detail }
    }
}

fn resolve_config_context(config_account_id: &str, who: &str) -> Option<RlnConfigContext> {
    config_context(config_account_id)
        .map_err(|p| eprintln!("{who}: {}", p.detail))
        .ok()
}

fn config_context(config_account_id: &str) -> Result<RlnConfigContext, RegistryProblem> {
    let config_hex = resolve_account_id(config_account_id);
    if config_hex.is_empty() {
        return Err(RegistryProblem::new(
            "invalid",
            format!("'{config_account_id}' is not an account id"),
        ));
    }
    if let Some(reason) = network_conflict(wallet::bound_network().as_deref(), &config_hex) {
        return Err(RegistryProblem::new("network_conflict", reason));
    }
    let Some(shards) = fetch_shards(&config_hex) else {
        return Err(RegistryProblem::new(
            "unreachable",
            format!("could not read config account {config_hex} from the sequencer"),
        ));
    };
    // On LEZ v0.3.0 a program's id is the header account its deployer created,
    // not derivable from anything a registry id carries. The config is the
    // registration program's PDA and holds exactly one program shard — that
    // program's — so its shard key IS the registration program id. A native
    // balance shard (someone sent it tokens) is not a program and is skipped.
    let mut program_shards = shards
        .into_iter()
        .filter(|(p, data)| *p != NATIVE_TOKEN_PROGRAM && !data.is_empty());
    let Some((registration_program, config_data)) = program_shards.next() else {
        // What a reset zone looks like: the URL still answers, every account
        // is gone. The same answer for a registry that never existed here.
        return Err(RegistryProblem::new(
            "not_deployed",
            format!(
                "config account {config_hex} holds no program state on this chain — the registry \
                 is not deployed here (the network may have been reset)"
            ),
        ));
    };
    if program_shards.next().is_some() {
        return Err(RegistryProblem::new(
            "unexpected_layout",
            format!("config account {config_hex} holds more than one program shard"),
        ));
    }
    // The one place a config account is admitted, and so the one place its
    // generation is checked. Every field below is read by byte offset and
    // ConfigState carries no version discriminator, so a config from another
    // program generation does not fail to decode — it decodes to a plausible
    // wrong treasury and a plausible wrong price. Length is the only signal.
    if config_data.len() != native::CONFIG_STATE_SIZE {
        return Err(RegistryProblem::new(
            "wrong_generation",
            format!(
                "config shard is {} bytes, expected {} — this is a config from a different \
                 program generation, not a short read",
                config_data.len(),
                native::CONFIG_STATE_SIZE,
            ),
        ));
    }
    Ok(RlnConfigContext {
        config_data,
        registration_program,
    })
}

/// Why a config account must not be read through this wallet, if it must not.
///
/// A home bound to one network cannot serve a registry the table places on
/// another: the account either does not exist there or, worse, is someone
/// else's. Only a recorded binding is checked — an operator-configured home
/// has no network name to compare — and only a config the table knows, since
/// an unlisted registry may well live on the bound chain.
fn network_conflict(bound: Option<&str>, config_hex: &str) -> Option<String> {
    let bound = bound?;
    let listed = networks::network_of_config(config_hex)?;
    (listed.reference != bound).then(|| {
        format!(
            "config account {config_hex} is on network {}, but this wallet is bound to {bound}",
            listed.reference
        )
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
/// `LEZ_RLN_PAYER` as 64-hex, or "" when unset. Read at bring-up to decide the
/// module's payer; `fee_payer_hex` is what every send actually uses.
pub(crate) fn fee_payer_env_hex() -> String {
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

/// The account a transaction declares as its fee payer.
///
/// Empty used to mean "self-pay by the signer", which was right when the
/// signer was a token holding that held no native balance and something else
/// had to pay. The signer now IS the payer, so the fallback is the account the
/// wallet would pay with now — configured, or the best-funded account in it.
fn fee_payer_hex() -> String {
    let configured = fee_payer_env_hex();
    if !configured.is_empty() {
        return configured;
    }
    wallet::payer_hex()
}

/// Submit one public transaction through the `lez_core` wallet. `None` =
/// failed, already logged.
fn send_generic_tx(
    who: &str,
    mentions: Vec<wallet::Mention>,
    instruction: Vec<u8>,
    program_hex: String,
    payer_hex: String,
) -> Option<String> {
    let send_result =
        wallet::send_generic_public_transaction(&mentions, &instruction, &program_hex, &payer_hex);
    if send_result.is_empty() {
        eprintln!("{who}: transaction failed");
        return None;
    }
    Some(send_result)
}

fn derive_register_plan(
    ctx: &RlnConfigContext,
    id_commitment: &[u8; 32],
    who: &str,
) -> Option<RlnRegisterPlan> {
    match native::register_plan(&ctx.config_data, &ctx.registration_program, id_commitment) {
        Ok(plan) => Some(plan),
        Err(e) => {
            eprintln!("{who}: register_plan failed: {e}");
            None
        }
    }
}

/// CLOCK_50's timestamp, from the clock program's shard of the clock account —
/// the chain time the registry judges lifecycles by and `Register` claims.
fn chain_now_ms(who: &str) -> Option<u64> {
    let clock_hex = bytes_to_hex(&rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES);
    let data = fetch_shard(&clock_hex, &rln_layouts::clock_program_account_id(), who)?;
    match native::decode_clock_timestamp_ms(&data) {
        Ok(ts) => Some(ts),
        Err(e) => {
            eprintln!("{who}: clock decode error: {e}");
            None
        }
    }
}

/// The `tx_hash` of a send reply (`{success, tx_hash, error}`), or "".
fn tx_hash_of(send_result: &str) -> String {
    serde_json::from_str::<serde_json::Value>(send_result)
        .ok()
        .and_then(|v| v.get("tx_hash").and_then(|h| h.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

/// Build and send one `Register` with claims read from the chain now.
/// `None` = not submitted, already logged.
fn submit_register(
    ctx: &RlnConfigContext,
    plan: &RlnRegisterPlan,
    id_commitment: &[u8; 32],
    rate_limit: u64,
    payer_hex: &str,
    who: &str,
) -> Option<String> {
    // now_ms is a claim the guest asserts against the clock shard, so it is
    // read last, just before sending.
    let now_ms = chain_now_ms(who)?;
    let instruction = match native::register_build_instruction(plan, id_commitment, rate_limit, now_ms) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{who}: register_build_instruction failed: {e}");
            return None;
        }
    };
    // Account order and shard per account must match the guest's Register
    // (lez-rln methods/guest registration.rs), which asserts both:
    //   config      registration shard
    //   payer       native balance, signs
    //   treasury    native balance
    //   clock       CLOCK_50, clock program shard
    //   membership  registration shard (created)
    let registration_hex = bytes_to_hex(&ctx.registration_program);
    let native_hex = bytes_to_hex(&NATIVE_TOKEN_PROGRAM);
    let mention = |account: &[u8; 32], signs: bool, shard: &str| wallet::Mention {
        account_hex: bytes_to_hex(account),
        signs,
        shard_program_hex: shard.to_string(),
    };
    let Some(payer_bytes) = hex_to_bytes32(payer_hex) else {
        eprintln!("{who}: payer {payer_hex} is not 32-byte hex");
        return None;
    };
    let mentions = vec![
        mention(&plan.config_account_id, false, &registration_hex),
        mention(&payer_bytes, true, &native_hex),
        mention(&plan.treasury_account_id, false, &native_hex),
        mention(
            &rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES,
            false,
            &bytes_to_hex(&rln_layouts::clock_program_account_id()),
        ),
        mention(&plan.membership_account_id, false, &registration_hex),
    ];
    let send_result = send_generic_tx(who, mentions, instruction, registration_hex, fee_payer_hex())?;
    // The sender is the only party that knows a member's leaf: record the
    // claim of every send the sequencer took (see leaf_claims.rs).
    if !tx_hash_of(&send_result).is_empty() {
        leaf_claims::record(&bytes_to_hex(&plan.membership_account_id), plan.leaf_index);
    }
    Some(send_result)
}

/// How often the watcher looks at the chain, and how many times a reverted
/// registration is re-sent before the watcher gives up and frees the slot for
/// a later caller.
const REG_WATCH_INTERVAL: Duration = Duration::from_secs(2);
const REG_MAX_RESUBMITS: u32 = 5;

struct RegisterWatch {
    config_account_id: String,
    payer_hex: String,
    id_commitment: [u8; 32],
    rate_limit: u64,
    reg_key: String,
    tx_hash: String,
}

/// Follow a submitted registration until its membership appears, re-sending it
/// with fresh claims if it reverted.
///
/// On LEZ v0.3.0 a registration whose claims no longer hold (its clock claim
/// outside the registry's tolerance, a price or duration changed under it, its
/// leaf index taken by a registration that landed first) is
/// still included in a block — charged, with no effect, and nothing sent back
/// to the submitter. So the fate is read from the chain: the membership
/// appearing is success; the transaction in a block without it is a revert,
/// re-planned and re-sent. A transaction the sequencer still holds (deferred on
/// the block gas cap, which fits one registration per block) is left alone:
/// re-sending it would race the original, and the loser pays a full
/// registration's gas for nothing.
/// Storage bytes a Register declares beside its gas limit when the fee
/// reserve is sized; the same allowance liblogos_rln_module reserves for.
const REGISTER_DATA_ALLOWANCE: u128 = 100_000;

/// Everything the guest would refuse that can be known before signing:
/// rln_core::check_register's argument and capacity checks, and whether the
/// payer can cover the price plus the fee reserve at the next block's base fee
/// ceiling (skipped when no fee quote can be had — an outage is not a refusal).
/// LEZ v0.3.0 has no transaction simulation, so this is the only way to keep a
/// doomed registration from being signed and charged.
fn preflight_register(
    ctx: &RlnConfigContext,
    plan: &RlnRegisterPlan,
    id_commitment: &[u8; 32],
    rate_limit: u64,
    payer_hex: &str,
) -> Result<(), String> {
    native::check_register(&ctx.config_data, id_commitment, rate_limit)?;
    let quote: Option<serde_json::Value> = serde_json::from_str(&fee_state::get_fee_state()).ok();
    let ceiling = |key: &str| {
        quote
            .as_ref()
            .and_then(|q| q.get(key))
            .and_then(serde_json::Value::as_u64)
            .map(u128::from)
    };
    let (Some(exec), Some(stor)) = (ceiling("next_base_fee_exec_ceiling"), ceiling("next_base_fee_stor_ceiling"))
    else {
        return Ok(());
    };
    let Some((_, balance)) = wallet::native_balance(payer_hex) else {
        return Ok(());
    };
    let price = plan.price_per_unit.saturating_mul(u128::from(rate_limit));
    let reserve = u128::from(wallet::GAS_LIMIT)
        .saturating_mul(exec)
        .saturating_add(REGISTER_DATA_ALLOWANCE.saturating_mul(stor));
    let needed = price.saturating_add(reserve);
    if balance < needed {
        return Err(format!(
            "insufficient_balance: payer {payer_hex} holds {balance}, a registration needs {needed} \
             ({price} price + {reserve} fee reserve at the next block's base fee ceiling)"
        ));
    }
    Ok(())
}

fn spawn_register_watch(w: RegisterWatch) {
    let spawned = std::thread::Builder::new()
        .name("lez-rln-register-watch".into())
        .spawn(move || register_watch(w));
    if let Err(e) = spawned {
        eprintln!("register_member: could not start the confirmation watcher: {e}");
    }
}

fn register_watch(mut w: RegisterWatch) {
    const WHO: &str = "register_member(watch)";
    let deadline = Instant::now() + REG_IN_FLIGHT_TTL;
    let mut resubmits = 0u32;
    while Instant::now() < deadline {
        std::thread::sleep(REG_WATCH_INTERVAL);
        let Some(ctx) = resolve_config_context(&w.config_account_id, WHO) else {
            continue;
        };
        let Some(plan) = derive_register_plan(&ctx, &w.id_commitment, WHO) else {
            continue;
        };
        let membership_hex = bytes_to_hex(&plan.membership_account_id);
        let landed = || {
            fetch_shard_quiet(&membership_hex, &ctx.registration_program)
                .and_then(|data| native::decode_membership(&data).ok())
        };
        if landed().is_some() {
            eprintln!("{WHO}: registered");
            return;
        }
        if fee_state::tx_included(&w.tx_hash) != Some(true) {
            continue;
        }
        // Included: re-read once, in case it applied between the two reads.
        if landed().is_some() {
            continue;
        }
        if resubmits >= REG_MAX_RESUBMITS {
            eprintln!(
                "{WHO}: membership still absent after {REG_MAX_RESUBMITS} re-sends — giving up; \
                 a later register_member call starts afresh"
            );
            reg_in_flight(|m| m.remove(&w.reg_key));
            return;
        }
        // A revert that fresh claims cannot fix (an argument the guest refuses,
        // a full registry, a payer that cannot pay) would revert, and be
        // charged, on every re-send.
        if let Err(why) = preflight_register(&ctx, &plan, &w.id_commitment, w.rate_limit, &w.payer_hex) {
            eprintln!("{WHO}: tx {} reverted and a re-send would too — not re-sending: {why}", w.tx_hash);
            let reply = serde_json::json!({ "error": why }).to_string();
            reg_in_flight(|m| m.insert(w.reg_key.clone(), (reply, Instant::now())));
            return;
        }
        eprintln!(
            "{WHO}: tx {} is in a block but registered nothing — it reverted; re-sending with \
             fresh claims",
            w.tx_hash
        );
        resubmits += 1;
        let Some(send_result) =
            submit_register(&ctx, &plan, &w.id_commitment, w.rate_limit, &w.payer_hex, WHO)
        else {
            continue;
        };
        w.tx_hash = tx_hash_of(&send_result);
        let reply = serde_json::json!({
            "leaf_index": plan.leaf_index,
            "tx_result": send_result,
            "pending": true,
        })
        .to_string();
        reg_in_flight(|m| m.insert(w.reg_key.clone(), (reply, Instant::now())));
    }
    eprintln!("{WHO}: no membership within {}s", REG_IN_FLIGHT_TTL.as_secs());
}

// ------------------------------------------------------------- method bodies

// -------------------------------------------------------------------- module

#[derive(Default)]
struct LogosLezRlnModuleImpl;

impl LiblogosLezRlnModule for LogosLezRlnModuleImpl {
    /// Live NATIVE balance, of `account_id` or of this module's own payer when
    /// empty. A caller asks this to decide whether a registration can be paid
    /// for, which is why "" on error must never be read as zero — an
    /// unreachable sequencer is not an empty account.
    fn get_native_balance(&self, account_id: String) -> String {
        let Some((account, balance)) = wallet::native_balance(&account_id) else {
            return String::new();
        };
        serde_json::json!({
            "account": account,
            // Decimal string: a u128 balance exceeds JSON number precision,
            // and a consumer comparing against a price must not lose digits.
            "balance": balance.to_string(),
        })
        .to_string()
    }

    /// Whether the wallet this module owns is usable. Never fails — a
    /// consumer polls it to tell "still coming up" from "broken", because
    /// every chain-facing method answers "" in both cases.
    fn wallet_status(&self) -> String {
        wallet::status_json()
    }

    /// Bind the wallet to the network a consumer's registry id names, or say
    /// whether it already is. Never touches the chain.
    fn use_network(&self, reference: String) -> String {
        wallet::use_network(&reference)
    }

    /// The head fee market of the wallet's sequencer, so a caller can size
    /// what a registration's fee will hold back. Needs the network, not the
    /// wallet: it answers during bring-up.
    fn get_fee_state(&self) -> String {
        fee_state::get_fee_state()
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        // Bring-up runs on its own thread: this hook fires on the host's Qt
        // main thread, and asking lez_core for its wallet dir, opening the
        // wallet (which calibrates the sequencer client) and picking a payer
        // are calls the loop must not be holding.
        wallet::spawn_bring_up(&ctx.instance_persistence_path);
    }

    fn register_member(
        &self,
        config_account_id: String,
        payer_account_id: String,
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

        // One account signs the Register tx, pays the registry price from its
        // NATIVE balance and pays the fee. Empty means "this module's own
        // payer", which is what a registry-agnostic consumer passes; a caller
        // paying on someone else's behalf names an account whose key this
        // wallet holds, because the signature is what authorizes the debit.
        let payer_hex = if payer_account_id.trim().is_empty() {
            wallet::payer_hex()
        } else {
            resolve_account_id(&payer_account_id)
        };
        if payer_hex.is_empty() {
            eprintln!("register_member: no payer — the wallet has not resolved one yet");
            return String::new();
        }

        let Some(plan) = derive_register_plan(&ctx, &id_commitment, "register_member") else {
            return String::new();
        };

        let membership_pda_hex = bytes_to_hex(&plan.membership_account_id);

        // Idempotency pre-check: if the membership PDA is already populated
        // for this (tree_id, id_commitment), say so instead of resubmitting —
        // the on-chain Register handler enforces uniqueness via the one-shot
        // membership init, so a resubmit always fails. The membership account
        // does not record its leaf index; this module knows it only if it sent
        // the registration (leaf_claims.rs).
        // decode_membership carries its own length guard (DataTooShort), so
        // a short or absent account simply fails to decode.
        if fetch_shard_quiet(&membership_pda_hex, &ctx.registration_program)
            .and_then(|existing| native::decode_membership(&existing).ok())
            .is_some()
        {
            eprintln!("register_member: membership already exists — skipping resubmit");
            let mut reply = serde_json::json!({ "already_registered": true });
            if let Some(leaf_index) = leaf_claims::lookup(&membership_pda_hex) {
                reply["leaf_index"] = leaf_index.into();
            }
            return reply.to_string();
        }

        if let Err(why) =
            preflight_register(&ctx, &plan, &id_commitment, rate_limit as u64, &payer_hex)
        {
            eprintln!("register_member: not submitting: {why}");
            return serde_json::json!({ "error": why }).to_string();
        }

        // In-flight dedup (see REG_IN_FLIGHT): the first caller submits;
        // concurrent and repeat callers get the first submission's reply.
        let reg_key = membership_pda_hex.clone();
        let placeholder = serde_json::json!({ "pending": true }).to_string();
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

        let Some(send_result) =
            submit_register(&ctx, &plan, &id_commitment, rate_limit as u64, &payer_hex, "register_member")
        else {
            reg_in_flight(|m| m.remove(&reg_key));
            return String::new();
        };

        // Return once the sequencer accepts the submission; don't block on
        // confirmation. Callers poll get_membership() for the membership and
        // its leaf index: the claim here is not final, since a registration
        // landing first takes it (StaleLeafIndex) and the watcher re-sends
        // with the next one.
        let reply = serde_json::json!({
            "leaf_index": plan.leaf_index,
            "tx_result": send_result,
            "pending": true,
        })
        .to_string();
        reg_in_flight(|m| m.insert(reg_key.clone(), (reply.clone(), Instant::now())));
        spawn_register_watch(RegisterWatch {
            config_account_id,
            payer_hex,
            id_commitment,
            rate_limit: rate_limit as u64,
            reg_key,
            tx_hash: tx_hash_of(&send_result),
        });
        reply
    }

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
        let data = match fetch_shard_tri_state(&membership_pda_hex, &ctx.registration_program) {
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
        let Some(now_ms) = chain_now_ms("get_membership") else {
            return String::new();
        };
        let mut reply = serde_json::json!({
            "clock_timestamp": now_ms,
            "grace_period_duration": membership.grace_period_duration_sec,
            "grace_period_start_timestamp": membership.grace_period_start_timestamp_ms,
            "rate_limit": membership.rate_limit as i64,
            "registered": true,
            "state": native::membership_status(
                membership.grace_period_start_timestamp_ms,
                membership.grace_period_duration_sec,
                now_ms,
            ),
        });
        // The membership exists, so the latest claim this module sent for it
        // is its leaf (leaf_claims.rs). Absent when another sender registered it.
        if let Some(leaf_index) = leaf_claims::lookup(&membership_pda_hex) {
            reply["leaf_index"] = leaf_index.into();
        }
        reply.to_string()
    }

    fn check_registry(&self, config_account_id: String) -> String {
        let mut out = match config_context(&config_account_id) {
            Ok(ctx) => serde_json::json!({
                "status": "ok",
                "registration_program": bytes_to_hex(&ctx.registration_program),
            }),
            Err(p) => serde_json::json!({"status": p.status, "detail": p.detail}),
        };
        if let Some(sequencer) = wallet::sequencer_addr() {
            out["sequencer"] = serde_json::json!(sequencer);
        }
        if let Some(head) = fee_state::chain_head() {
            out["chain_head"] = serde_json::json!(head);
        }
        out.to_string()
    }

    fn get_registry_bounds(&self, config_account_id: String) -> String {
        let Some(ctx) = resolve_config_context(&config_account_id, "get_registry_bounds") else {
            return String::new();
        };
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

    #[test]
    fn a_listed_config_on_another_network_is_refused() {
        let devnet_config = "9d6c0f59718f05ecb3f6ae58259821bfff6594e20866d6cd2a214c53e4ec0511";
        assert!(network_conflict(Some("devnet"), devnet_config).is_none());
        let reason = network_conflict(Some("testnet"), devnet_config).expect("conflict");
        assert!(reason.contains("on network devnet") && reason.contains("bound to testnet"));
        // Operator-configured (no recorded binding): never checked.
        assert!(network_conflict(None, devnet_config).is_none());
        // Not in the table: it may well live on the bound chain.
        assert!(network_conflict(Some("testnet"), &"ab".repeat(32)).is_none());
    }
}
