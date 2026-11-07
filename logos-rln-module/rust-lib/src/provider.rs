//! Registry provider layer: the spec's provider interface as the `Registry`
//! and `Payer` traits beside `tree::TreeSource`, namespace → `Backend` routing,
//! and the lez-rln provider — a client of the lez module
//! (`liblogos_lez_rln_module`) through the SDK's generated typed
//! client (`modules().liblogos_lez_rln_module`), plus the generated client of
//! the gifter module (`RlnGifterModuleClient`), a declared dependency too.
//!
//! Every outbound call carries its own timeout (`READ_TIMEOUT`,
//! `REGISTER_TIMEOUT`, `GIFTER_REQUEST_TIMEOUT`) through the SDK's
//! `*_with_timeout` entry points.
//!
//! Threading contract. Handlers run on `concurrency:"multi"` worker threads
//! and reach the lez module through the ASYNC twins plus a channel wait
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

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use logos_rust_sdk::LogosError;

use crate::generated::liblogos_lez_rln_module::LiblogosLezRlnModuleClient;
use crate::generated::rln_gifter_module::RlnGifterModuleClient;
use crate::lifecycle::MembershipState;
use crate::registry_id::CanonicalRegistryId;
use crate::tree::{MerkleProof, RootSet, TreeSource};
use crate::util::lock;
use crate::error::{ApiError, ErrorKind};

const TARGET_MODULE: &str = "liblogos_lez_rln_module";
/// The lez module's reads run up to 60s against the wallet; add hop margin.
const READ_TIMEOUT: Duration = Duration::from_secs(70);
/// The lez module's register_member submits with a 180s tx timeout.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(190);
/// the lez module bounds its getFeeState round trip at 5s connect + 10s I/O.
/// Shorter than READ_TIMEOUT because the funding wait asks on every balance
/// read, and a stalled quote only means falling back to the fixed reserve.
const FEE_STATE_TIMEOUT: Duration = Duration::from_secs(30);
/// The protocol owns timeout enforcement; this margin only guards the channel
/// wait against a callback that never fires.
const REPLY_MARGIN: Duration = Duration::from_secs(10);

// ------------------------------------------------------------ shared clients

static LEZ_CLIENT: Mutex<Option<Arc<LiblogosLezRlnModuleClient>>> = Mutex::new(None);
static GIFTER_CLIENT: Mutex<Option<Arc<RlnGifterModuleClient>>> = Mutex::new(None);

/// Warm the process-lifetime clients. Called from `on_context_ready` on the
/// host's main Qt thread so the one-time construction happens at load rather
/// than inside the first dispatch; safe to re-call.
pub(crate) fn init_client() {
    let _ = lez_client();
    let _ = gifter_client();
}

/// The shared typed client to the lez module, created on first use. The lock is
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
/// collapse to the lez module's provider_failure (logged), so callers just `?`.
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

/// One read of the lez module: its QString reply, where an empty reply is the
/// lez module's own ""-means-error convention and so a provider_failure.
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

/// Fire-and-record dispatch: a
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

// ----------------------------------------------------------- network gate

/// What the lez module said about serving a network, per CAIP-2 reference. Only
/// definitive answers are kept: an accepted network stays accepted and a
/// refused one stays refused for the life of the process (the lez module never
/// re-points a wallet home), while a "not yet" is asked again next time.
static NETWORK_GATE: std::sync::LazyLock<Mutex<HashMap<String, Result<(), String>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// A `use_network` reply, decoded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    Accepted,
    /// Final; the lez module's reason.
    Refused(String),
    /// Not answerable yet (its wallet home is not resolved), or a reply that
    /// did not say — ask again.
    Retry,
}

/// Decode a `use_network` reply. Anything that is not an explicit answer —
/// "", garbage, a reply missing `accepted` — is `Retry`, never `Refused`: a
/// refusal is remembered for the life of the process, and must not be
/// inferred from a reply that never made one.
pub(crate) fn interpret_use_network(raw: &str) -> Gate {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Gate::Retry;
    };
    match v.get("accepted").and_then(serde_json::Value::as_bool) {
        Some(true) => Gate::Accepted,
        Some(false) if v.get("retry").and_then(serde_json::Value::as_bool) == Some(false) => {
            Gate::Refused(
                v.get("detail")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("refused")
                    .to_owned(),
            )
        }
        _ => Gate::Retry,
    }
}

/// Keep a definitive answer; drop a `Retry`.
fn remember(gate: &mut HashMap<String, Result<(), String>>, reference: &str, answer: &Gate) {
    match answer {
        Gate::Accepted => {
            gate.insert(reference.to_owned(), Ok(()));
        }
        Gate::Refused(detail) => {
            gate.insert(reference.to_owned(), Err(detail.clone()));
        }
        Gate::Retry => {}
    }
}

fn network_refused(registry: &CanonicalRegistryId, detail: &str) -> ApiError {
    ApiError::new(
        ErrorKind::UnknownRegistry,
        &format!(
            "{}: {TARGET_MODULE} will not serve network '{}': {detail}",
            registry.canonical, registry.reference
        ),
    )
}

/// Make sure the lez module's wallet serves the network this registry's id
/// names — binding an unconfigured wallet to it, the first time one is asked.
/// A refusal is `unknown_registry`; a wallet home the lez module has not resolved
/// yet is `not_ready`; a sibling that does not answer is `provider_failure`
/// (and is asked again next time).
pub(crate) fn ensure_network(registry: &CanonicalRegistryId) -> Result<(), ApiError> {
    if let Some(known) = lock(&NETWORK_GATE).get(&registry.reference) {
        return known.clone().map_err(|d| network_refused(registry, &d));
    }
    let client = lez_client();
    let raw = await_reply("use_network", READ_TIMEOUT, |done| {
        client.use_network_async_with_timeout(&registry.reference, READ_TIMEOUT, done)
    })?;
    let answer = interpret_use_network(&raw);
    remember(&mut lock(&NETWORK_GATE), &registry.reference, &answer);
    match answer {
        Gate::Accepted => Ok(()),
        Gate::Refused(detail) => {
            let err = network_refused(registry, &detail);
            eprintln!("membership provider: {}", err.message);
            Err(err)
        }
        Gate::Retry => Err(ApiError::new(
            ErrorKind::NotReady,
            &format!(
                "{TARGET_MODULE} cannot select network '{}' yet (its wallet home is not resolved)",
                registry.reference
            ),
        )),
    }
}

/// The registries whose network `select_networks` asks about: the first of
/// each distinct `logos` reference, in configuration order.
fn networks_in_order(tracked: &[String]) -> Vec<CanonicalRegistryId> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for raw in tracked {
        let Ok(registry) = crate::registry_id::parse(raw) else {
            continue;
        };
        if registry.namespace != "logos" || seen.contains(&registry.reference) {
            continue;
        }
        seen.push(registry.reference.clone());
        out.push(registry);
    }
    out
}

/// Put the configured networks to the lez module in configuration order, so the
/// FIRST registry id binds an unconfigured wallet — deterministically, rather
/// than whichever registry the root refresher or provisioning happens to
/// reach first. A registry on a different network is then refused and says
/// so through `get_membership_state`; nothing here fails `start()`. A network
/// the lez module cannot answer for yet is asked again by the next provider call.
pub(crate) fn select_networks(tracked: &[String]) {
    for registry in networks_in_order(tracked) {
        match ensure_network(&registry) {
            Ok(()) => eprintln!("membership start: network '{}' selected", registry.reference),
            Err(e) => eprintln!(
                "membership start: network '{}': {}",
                registry.reference, e.message
            ),
        }
    }
}

// ------------------------------------------------------------ gifter delegate

/// The delegated-registration executor (RLN Membership Allocation Protocol):
/// the co-located gifter client module, a declared dependency (its generated
/// client; logoscore loads it, and libp2p_module through it, before this
/// module).
/// The gifter request budget: client-side payload production by the vector's
/// provider module (≤120s — keycard capture with a slow tap sets the bar)
/// plus the dial and the server-side on-chain register (≤205s), with
/// dispatch margin.
pub(crate) const GIFTER_REQUEST_TIMEOUT: Duration = Duration::from_secs(340);

fn gifter_client() -> Arc<RlnGifterModuleClient> {
    let mut slot = lock(&GIFTER_CLIENT);
    Arc::clone(slot.get_or_insert_with(|| Arc::new(RlnGifterModuleClient::new())))
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
    let args_json = args_json.to_string();
    dispatch_recorded("request", on_done, |done| {
        client.request_async_with_timeout(&args_json, GIFTER_REQUEST_TIMEOUT, done)
    })
}

// ---------------------------------------------------------- provider traits

/// The registry's view of one commitment it holds (the spec provider's
/// `get_membership` return: state + authoritative leaf_index/rate_limit).
pub(crate) struct ProviderMembership {
    /// active | grace_period | expired.
    pub(crate) state: MembershipState,
    /// None when the source does not know the leaf; the stored leaf stands.
    pub(crate) leaf_index: Option<u64>,
    pub(crate) rate_limit: u64,
}

pub(crate) type RegisterCallback = Box<dyn FnOnce(Result<String, ApiError>) + Send>;

/// The registry's membership records and parameters: what a registration
/// writes and what the poller confirms against. One instance serves every
/// registry of its namespace (the anchor account travels in
/// `CanonicalRegistryId`).
pub(crate) trait Registry: Send + Sync {
    fn get_membership(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
    ) -> Result<Option<ProviderMembership>, ApiError>;

    /// Submit a registration without blocking: `on_done` receives the
    /// submission reply (acceptance, NOT application — confirmation is the
    /// poller's read-back) or the submission error. Runs on the module's
    /// event loop after the current dispatch returns.
    fn register_async(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
        rate_limit: u64,
        on_done: RegisterCallback,
    ) -> Result<(), ApiError>;

    /// The registry's parameters (spec RegistryParameters — max_rate_limit and
    /// friends) as the lez module's raw bounds object. Backs the quota read.
    fn get_registry_bounds(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<serde_json::Value, ApiError>;

    /// Whether the registry is deployed on the chain the provider reads, as
    /// the lez module's raw check object (`{status, detail?, sequencer?,
    /// chain_head?}`). An error means the question could not be asked.
    fn check_registry(&self, registry: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError>;
}

/// The wallet that pays for a self-funded registration.
pub(crate) trait Payer: Send + Sync {
    /// Whether the chain-access module's own wallet is usable, and which
    /// account it pays with: `{detail, payer, ready, state}`. Local to that
    /// module — it does not touch the chain, so it answers before a sync and
    /// is safe to poll.
    fn wallet_status(&self) -> Result<serde_json::Value, ApiError>;

    /// Live NATIVE balance of the account that would pay for a registration.
    ///
    /// An error means the question could not be answered, never that the
    /// balance is zero: a caller waiting to afford a registration would read
    /// an unreachable sequencer as a permanently broke account and stop
    /// waiting.
    fn payer_balance(&self) -> Result<u128, ApiError>;

    /// The chain's head fee market, as the raw quote object: what a
    /// registration's fee reserve is sized from. An error means no quote — an
    /// older chain-access module without the method included — and the
    /// caller falls back to a fixed reserve.
    fn fee_state(&self) -> Result<serde_json::Value, ApiError>;
}

/// The three sources of truth serving one namespace.
#[derive(Clone, Copy)]
pub(crate) struct Backend {
    pub tree: &'static dyn TreeSource,
    pub registry: &'static dyn Registry,
    pub payer: &'static dyn Payer,
}

/// The registry statuses that mean "this registry cannot work here", as
/// opposed to "could not tell" (`unreachable`, or no answer at all).
const REGISTRY_PROBLEMS: [&str; 5] =
    ["not_deployed", "wrong_generation", "unexpected_layout", "network_conflict", "invalid"];

/// A sentence for the caller when the registry is known not to be usable on
/// the provider's chain: a reset network, a registry from another program
/// version, the wrong network. None when it is fine or the check could not
/// be made — a transient outage must not read as a missing registry.
pub(crate) fn registry_problem(
    prov: &dyn Registry,
    registry: &CanonicalRegistryId,
) -> Option<String> {
    let check = prov.check_registry(registry).ok()?;
    registry_problem_from(&registry.canonical, &check)
}

fn registry_problem_from(canonical: &str, check: &serde_json::Value) -> Option<String> {
    let status = check.get("status")?.as_str()?;
    if !REGISTRY_PROBLEMS.contains(&status) {
        return None;
    }
    let detail = check.get("detail").and_then(|d| d.as_str()).unwrap_or(status);
    let at = match (
        check.get("sequencer").and_then(|s| s.as_str()),
        check.get("chain_head").and_then(serde_json::Value::as_u64),
    ) {
        (Some(seq), Some(head)) => format!(" on {seq} (chain at block {head})"),
        (Some(seq), None) => format!(" on {seq}"),
        _ => String::new(),
    };
    Some(format!("registry {canonical} is not usable{at}: {status} — {detail}"))
}

/// A failed registry read, explained when the registry itself is the cause:
/// an empty reply from the lez module says nothing, so ask it whether the
/// registry is there at all and, if not, say that instead.
fn explained(
    prov: &dyn Registry,
    registry: &CanonicalRegistryId,
    e: ApiError,
) -> ApiError {
    if e.kind != ErrorKind::ProviderFailure {
        return e;
    }
    match registry_problem(prov, registry) {
        Some(msg) => ApiError::new(ErrorKind::UnknownRegistry, &msg),
        None => e,
    }
}

static LEZ_RLN: LezRlnProvider = LezRlnProvider;

/// Namespace routing (spec MUST). Unknown namespaces are the caller's
/// `unknown_registry` error.
pub(crate) fn backend_for(namespace: &str) -> Option<Backend> {
    match namespace {
        "logos" => Some(Backend { tree: &LEZ_RLN, registry: &LEZ_RLN, payer: &LEZ_RLN }),
        #[cfg(test)]
        "fakens" => *lock(&crate::test_support::INSTALLED_BACKEND),
        _ => None,
    }
}

// ---------------------------------------------------------- lez-rln provider

/// The `logos` namespace: lez-rln registries, anchored on the registration
/// program's config PDA, reached through the lez module liblogos_lez_rln_module.
struct LezRlnProvider;

fn provider_failure(method: &str) -> ApiError {
    ApiError::new(
        ErrorKind::ProviderFailure,
        &format!("{TARGET_MODULE}.{method} failed (empty reply)"),
    )
}

/// Decode a `get_membership` reply. Every field the lez module promises is
/// required: a missing one is a provider fault, never a defaultable value.
/// `registered` most of all — the poller treats an authoritative "not
/// registered" as proof a live membership was erased and acts destructively,
/// so a reply that never said it must degrade to `ProviderFailure`, which
/// leaves the record untouched. (`leaf_index` has the same hazard from the
/// other side: leaf 0 is a VALID leaf, so defaulting would prove against the
/// wrong membership.)
fn parse_membership_reply(raw: &str) -> Result<Option<ProviderMembership>, ApiError> {
    let fault = |msg: String| ApiError::new(ErrorKind::ProviderFailure, &msg);
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| fault(format!("get_membership reply parse: {e}")))?;
    let registered = v
        .get("registered")
        .and_then(|x| x.as_bool())
        .ok_or_else(|| fault("get_membership: reply carries no registered flag".to_string()))?;
    if !registered {
        return Ok(None);
    }
    let required = |key: &str| {
        v.get(key)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| fault(format!("get_membership: registered member missing {key}")))
    };
    Ok(Some(ProviderMembership {
        state: serde_json::from_value::<MembershipState>(
            v.get("state").cloned().unwrap_or(serde_json::Value::Null),
        )
        .map_err(|_| fault("get_membership: unrecognized state".to_string()))?,
        leaf_index: Some(required("leaf_index")?),
        rate_limit: required("rate_limit")?,
    }))
}

impl Registry for LezRlnProvider {
    fn get_membership(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
    ) -> Result<Option<ProviderMembership>, ApiError> {
        ensure_network(registry)?;
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
        )
        .map_err(|e| explained(self, registry, e))?;
        parse_membership_reply(&raw)
    }

    fn register_async(
        &self,
        registry: &CanonicalRegistryId,
        id_commitment_hex: &str,
        rate_limit: u64,
        on_done: RegisterCallback,
    ) -> Result<(), ApiError> {
        // The wire carries `int`; a rate the lez module could not even receive
        // is the caller's error, not a submission to be recorded.
        let rate_limit = i64::try_from(rate_limit).map_err(|_| {
            ApiError::new(ErrorKind::InvalidArgument, "rate_limit exceeds the wire's i64")
        })?;

        // After argument validation, so a malformed call is still the
        // caller's error whatever the network.
        ensure_network(registry)?;
        let client = lez_client();
        dispatch_recorded("register_member", on_done, |done| {
            client.register_member_async_with_timeout(
                &registry.account,
                // "" = the provider's own payer.
                "",
                id_commitment_hex,
                rate_limit,
                REGISTER_TIMEOUT,
                done,
            )
        })
    }

    fn get_registry_bounds(
        &self,
        registry: &CanonicalRegistryId,
    ) -> Result<serde_json::Value, ApiError> {
        ensure_network(registry)?;
        let client = lez_client();
        let raw = read_reply(
            "get_registry_bounds",
            await_reply("get_registry_bounds", READ_TIMEOUT, |done| {
                client.get_registry_bounds_async_with_timeout(&registry.account, READ_TIMEOUT, done)
            }),
        )
        .map_err(|e| explained(self, registry, e))?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("bounds reply parse: {e}"))
        })
    }

    fn check_registry(&self, registry: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
        ensure_network(registry)?;
        let client = lez_client();
        let raw = read_reply(
            "check_registry",
            await_reply("check_registry", READ_TIMEOUT, |done| {
                client.check_registry_async_with_timeout(&registry.account, READ_TIMEOUT, done)
            }),
        )?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("check_registry parse: {e}"))
        })
    }
}

impl Payer for LezRlnProvider {
    fn wallet_status(&self) -> Result<serde_json::Value, ApiError> {
        let client = lez_client();
        let raw = read_reply(
            "wallet_status",
            await_reply("wallet_status", READ_TIMEOUT, |done| {
                client.wallet_status_async_with_timeout(READ_TIMEOUT, done)
            }),
        )?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("wallet_status parse: {e}"))
        })
    }

    fn payer_balance(&self) -> Result<u128, ApiError> {
        let client = lez_client();
        // "" selects that module's own payer. This module is
        // registry-agnostic and holds no account ids, so it could not name
        // one even if it wanted to.
        let raw = read_reply(
            "get_native_balance",
            await_reply("get_native_balance", READ_TIMEOUT, |done| {
                client.get_native_balance_async_with_timeout("", READ_TIMEOUT, done)
            }),
        )?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("balance reply parse: {e}"))
        })?;
        // A decimal STRING on the wire: a u128 balance exceeds JSON number
        // precision, and a truncated one compared against a price is worse
        // than no answer.
        parsed
            .get("balance")
            .and_then(|b| b.as_str())
            .and_then(|b| b.parse::<u128>().ok())
            .ok_or_else(|| {
                ApiError::new(ErrorKind::ProviderFailure, "balance reply has no decimal balance")
            })
    }

    fn fee_state(&self) -> Result<serde_json::Value, ApiError> {
        let client = lez_client();
        let raw = read_reply(
            "get_fee_state",
            await_reply("get_fee_state", FEE_STATE_TIMEOUT, |done| {
                client.get_fee_state_async_with_timeout(FEE_STATE_TIMEOUT, done)
            }),
        )?;
        serde_json::from_str::<serde_json::Value>(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("fee state parse: {e}"))
        })
    }
}

impl TreeSource for LezRlnProvider {
    fn merkle_proof(
        &self,
        registry: &CanonicalRegistryId,
        leaf_index: u64,
    ) -> Result<MerkleProof, ApiError> {
        ensure_network(registry)?;
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
        )
        .map_err(|e| explained(self, registry, e))?;
        let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("proofs reply parse: {e}"))
        })?;
        let first = v.as_array().and_then(|arr| arr.first()).ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, "empty proof array (leaf out of range?)")
        })?;
        MerkleProof::from_provider_json(first)
    }

    fn valid_roots(&self, registry: &CanonicalRegistryId) -> Result<RootSet, ApiError> {
        ensure_network(registry)?;
        let client = lez_client();
        let raw = read_reply(
            "get_valid_roots",
            await_reply("get_valid_roots", READ_TIMEOUT, |done| {
                client.get_valid_roots_async_with_timeout(&registry.account, READ_TIMEOUT, done)
            }),
        )
        .map_err(|e| explained(self, registry, e))?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            ApiError::new(ErrorKind::ProviderFailure, &format!("roots reply parse: {e}"))
        })?;
        RootSet::from_provider_json(&parsed)
    }
}

// ------------------------------------------------------------------ fakes

/// In-memory sources for tests, served under the `fakens` namespace once
/// installed with `test_support::install_backend`.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    fn unanswered(what: &str) -> ApiError {
        ApiError::new(ErrorKind::ProviderFailure, &format!("fake {what}: no answer configured"))
    }

    /// Serves its proof and roots replies through the same decoders the lez
    /// provider uses.
    #[derive(Default)]
    pub(crate) struct FakeTree {
        pub proof: Option<serde_json::Value>,
        pub roots: Option<serde_json::Value>,
    }

    impl TreeSource for FakeTree {
        fn merkle_proof(&self, _: &CanonicalRegistryId, _: u64) -> Result<MerkleProof, ApiError> {
            MerkleProof::from_provider_json(self.proof.as_ref().ok_or_else(|| unanswered("merkle_proof"))?)
        }

        fn valid_roots(&self, _: &CanonicalRegistryId) -> Result<RootSet, ApiError> {
            RootSet::from_provider_json(self.roots.as_ref().ok_or_else(|| unanswered("valid_roots"))?)
        }
    }

    /// `membership`: None = no answer, Some(None) = not registered,
    /// Some(Some((state, leaf_index, rate_limit))) = registered.
    #[derive(Default)]
    pub(crate) struct FakeRegistry {
        pub membership: Option<Option<(MembershipState, Option<u64>, u64)>>,
        pub bounds: Option<serde_json::Value>,
    }

    impl Registry for FakeRegistry {
        fn get_membership(
            &self,
            _: &CanonicalRegistryId,
            _: &str,
        ) -> Result<Option<ProviderMembership>, ApiError> {
            let answer = self.membership.ok_or_else(|| unanswered("get_membership"))?;
            Ok(answer.map(|(state, leaf_index, rate_limit)| ProviderMembership {
                state,
                leaf_index,
                rate_limit,
            }))
        }

        fn register_async(
            &self,
            _: &CanonicalRegistryId,
            _: &str,
            _: u64,
            _: RegisterCallback,
        ) -> Result<(), ApiError> {
            Err(unanswered("register_async"))
        }

        fn get_registry_bounds(&self, _: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
            self.bounds.clone().ok_or_else(|| unanswered("get_registry_bounds"))
        }

        fn check_registry(&self, _: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
            Ok(serde_json::json!({ "status": "ok" }))
        }
    }

    #[derive(Default)]
    pub(crate) struct FakePayer {
        pub balance: Option<u128>,
    }

    impl Payer for FakePayer {
        fn wallet_status(&self) -> Result<serde_json::Value, ApiError> {
            Ok(serde_json::json!({ "detail": "", "payer": "fake", "ready": true, "state": "ready" }))
        }

        fn payer_balance(&self) -> Result<u128, ApiError> {
            self.balance.ok_or_else(|| unanswered("payer_balance"))
        }

        fn fee_state(&self) -> Result<serde_json::Value, ApiError> {
            Err(unanswered("fee_state"))
        }
    }

    /// A backend over leaked fakes, for `test_support::install_backend`.
    pub(crate) fn backend(tree: FakeTree, registry: FakeRegistry, payer: FakePayer) -> Backend {
        Backend {
            tree: Box::leak(Box::new(tree)),
            registry: Box::leak(Box::new(registry)),
            payer: Box::leak(Box::new(payer)),
        }
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

    // A reply that never claimed "not registered" must not be read as one:
    // the poller acts on an authoritative absence by erasing the membership.
    #[test]
    fn a_missing_registry_is_explained_and_an_outage_is_not() {
        let gone = serde_json::json!({
            "status": "not_deployed",
            "detail": "config account ab holds no program state",
            "sequencer": "https://testnet.lez.logos.co/",
            "chain_head": 12,
        });
        let msg = registry_problem_from("logos:testnet:ab", &gone).expect("explained");
        assert!(msg.contains("not_deployed"), "{msg}");
        assert!(msg.contains("https://testnet.lez.logos.co/ (chain at block 12)"), "{msg}");
        for status in ["ok", "unreachable", "something_new"] {
            let check = serde_json::json!({"status": status});
            assert!(registry_problem_from("logos:testnet:ab", &check).is_none(), "{status}");
        }
        assert!(registry_problem_from("logos:testnet:ab", &serde_json::json!({})).is_none());
    }

    #[test]
    fn a_reply_without_registered_is_a_provider_failure() {
        for raw in [
            r#"{"state":"active","leaf_index":7,"rate_limit":100}"#,
            r#"{"registered":"false"}"#,
            r#"{"registered":null}"#,
            r#"{}"#,
        ] {
            let Err(err) = parse_membership_reply(raw) else {
                panic!("{raw} must not read as an authoritative absence");
            };
            assert_eq!(err.kind, ErrorKind::ProviderFailure, "{raw}");
            assert!(err.message.contains("registered"), "{raw}: {}", err.message);
        }
    }

    #[test]
    fn an_authoritative_absence_still_reads_as_not_registered() {
        let Ok(pm) = parse_membership_reply(r#"{"registered":false}"#) else {
            panic!("an explicit registered:false is a valid answer");
        };
        assert!(pm.is_none());
    }

    #[test]
    fn a_registered_member_needs_every_contract_field() {
        let Ok(Some(pm)) = parse_membership_reply(
            r#"{"registered":true,"state":"active","leaf_index":0,"rate_limit":100}"#,
        ) else {
            panic!("a complete reply must decode");
        };
        assert_eq!(pm.leaf_index, Some(0), "leaf 0 is a valid leaf");
        assert_eq!(pm.rate_limit, 100);

        for raw in [
            r#"{"registered":true,"state":"active","rate_limit":100}"#,
            r#"{"registered":true,"state":"active","leaf_index":7}"#,
            r#"{"registered":true,"leaf_index":7,"rate_limit":100}"#,
        ] {
            let Err(err) = parse_membership_reply(raw) else {
                panic!("{raw} is missing a contract field");
            };
            assert_eq!(err.kind, ErrorKind::ProviderFailure, "{raw}");
        }
    }

    // With the test transport (no client), every provider path must degrade
    // to provider_failure — never panic, never wedge.
    #[test]
    fn stubbed_transport_degrades_to_provider_failure() {
        let registry = registry_id::parse(&format!("logos:local:{}", "ab".repeat(32))).unwrap();
        let backend = backend_for("logos").unwrap();
        assert!(backend.registry.get_membership(&registry, &"11".repeat(32)).is_err());
        assert!(backend.tree.merkle_proof(&registry, 0).is_err());
        assert!(backend.tree.valid_roots(&registry).is_err());
        assert!(backend.payer.fee_state().is_err());
        // Fire-and-record: a submission the SDK cannot dispatch (no client)
        // is a synchronous provider_failure, and the callback is NOT also
        // invoked — the record's owner handles the failure exactly once.
        let fired = Arc::new(Mutex::new(false));
        let seen = Arc::clone(&fired);
        let err = backend
            .registry
            .register_async(
                &registry,
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

    /// The logos namespace needs nothing from the caller to name a payer:
    /// `ProviderFailure` is the dead-transport error from the neighbouring
    /// test, so reaching it means the call got past argument validation.
    #[test]
    fn a_register_gets_past_validation() {
        let registry = registry_id::parse(&format!("logos:local:{}", "ab".repeat(32))).unwrap();
        let backend = backend_for("logos").unwrap();
        let err = backend
            .registry
            .register_async(&registry, &"11".repeat(32), 300, Box::new(|_| {}))
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::ProviderFailure);
    }

    #[test]
    fn use_network_replies_decode_to_a_gate() {
        assert_eq!(
            interpret_use_network(
                r#"{"accepted":true,"detail":"","network":"devnet","retry":false,"source":"table"}"#
            ),
            Gate::Accepted
        );
        assert_eq!(
            interpret_use_network(
                r#"{"accepted":false,"detail":"bound to devnet","network":"devnet","retry":false,"source":""}"#
            ),
            Gate::Refused("bound to devnet".to_owned())
        );
        assert_eq!(
            interpret_use_network(r#"{"accepted":false,"detail":"","retry":true}"#),
            Gate::Retry
        );
        // Nothing that failed to say "refused" may be read as a refusal.
        for raw in ["", "garbage", "[]", r#"{"accepted":false}"#, r#"{"retry":false}"#] {
            assert_eq!(interpret_use_network(raw), Gate::Retry, "{raw:?}");
        }
    }

    #[test]
    fn only_definitive_answers_are_remembered() {
        let mut gate = HashMap::new();
        remember(&mut gate, "devnet", &Gate::Retry);
        assert!(gate.is_empty(), "a retry must be asked again");
        remember(&mut gate, "devnet", &Gate::Accepted);
        remember(&mut gate, "testnet", &Gate::Refused("bound to devnet".to_owned()));
        assert_eq!(gate.get("devnet"), Some(&Ok(())));
        assert_eq!(gate.get("testnet"), Some(&Err("bound to devnet".to_owned())));
    }

    /// The first registry id binds an unconfigured wallet, so the order the
    /// networks are put to the lez module is the order `start()` named them.
    #[test]
    fn networks_are_selected_in_configuration_order() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        let tracked = vec![
            format!("logos:testnet:{a}"),
            format!("eip155:1:0x{a}"),
            format!("logos:devnet:{b}"),
            format!("logos:testnet:{c}"),
            "not a registry id".to_owned(),
        ];
        let picked: Vec<String> =
            networks_in_order(&tracked).into_iter().map(|r| r.canonical).collect();
        assert_eq!(
            picked,
            vec![format!("logos:testnet:{a}"), format!("logos:devnet:{b}")]
        );
    }

    #[test]
    fn a_remembered_refusal_is_unknown_registry() {
        let registry =
            registry_id::parse(&format!("logos:gate-refused-test:{}", "ab".repeat(32))).unwrap();
        lock(&NETWORK_GATE)
            .insert(registry.reference.clone(), Err("bound to devnet".to_owned()));
        let err = ensure_network(&registry).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnknownRegistry);
        assert!(err.message.contains("bound to devnet"), "{}", err.message);
        // And every provider method that takes the registry refuses with it.
        let backend = backend_for("logos").unwrap();
        assert_eq!(
            backend.tree.valid_roots(&registry).err().expect("refused").kind,
            ErrorKind::UnknownRegistry
        );
        lock(&NETWORK_GATE).remove(&registry.reference);
    }

    #[test]
    fn unknown_namespace_has_no_provider() {
        assert!(backend_for("eip155").is_none());
    }
}
