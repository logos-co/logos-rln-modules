//! The wallet, through the `lez_core` module.
//!
//! From 3.0.0 to 6.x this module linked `wallet_ffi` and held a wallet handle
//! of its own, because `lez_core` holds exactly one handle per host, opened
//! with whatever config the first opener chose, and a registration needed
//! ~9.1M gas against the stock 2,000,000. With the registry's tree off chain a
//! Register costs ~52k gas and the heaviest call (a slash) ~650k, so the
//! shared wallet serves, and 7.0.0 goes back to it: every registry read and
//! every transaction is a call to `lez_core` over the protocol (`Core` below,
//! a typed client generated from `deps/lez_core.lidl`).
//!
//! Nothing on a headless node opens `lez_core` for us — a delivery node has no
//! wallet app — so this module does: in `lez_core.wallet_dir()` (its own
//! persistence dir, the place any other consumer on the host will look), or
//! in the home `LEE_WALLET_HOME_DIR` names. If a wallet is already open (an
//! app got there first), `open` refuses — with the same code as a real
//! failure, since `lez_core` has no "is open" query — so the open wallet's
//! sequencer is asked: one on this registry's network is adopted as it
//! stands, one on another chain is refused.
//!
//! The payer is any account in that wallet with funds: `LEZ_RLN_PAYER` when
//! it names one, otherwise the best-funded public account, re-picked whenever
//! a chain-facing call needs it. When none holds anything, the module
//! publishes one account to fund (`wallet_status().payer`) — recorded in its
//! own persistence dir so the answer is stable across restarts. Native
//! balance enters an account only at genesis, over the L1 bridge or by
//! transfer, so funding is the operator's one manual step.
//!
//! Which chain a home talks to is decided once, by `plan_home` at bring-up
//! or, when nothing configured one, by the first `use_network` — the
//! membership module calls it with the reference of its first registry id,
//! looked up in the built-in table (`networks.rs`). The choice is recorded in
//! the home's `network.json`, and a home is never re-pointed afterwards.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::base58;
use crate::networks;
use crate::rln_core::bytes_to_hex;

/// An existing wallet home to use instead of `lez_core.wallet_dir()`. This is
/// the variable the LEZ wallet itself reads and the one the e2e harness and
/// Basecamp already export, so a home staged by `tools/deployments/stage.sh`
/// — config and storage together — is adopted whole.
const HOME_ENV: &str = "LEE_WALLET_HOME_DIR";

/// The sequencer a home we provision ourselves should point at. No default on
/// purpose: the wallet would otherwise write a config aimed at the public
/// testnet, and a module silently talking to the wrong chain is worse than one
/// that refuses to start.
const SEQUENCER_ENV: &str = "LEZ_RLN_SEQUENCER";

/// A network from the built-in table (`networks.rs`), by CAIP-2 reference.
/// Alone it provisions a home pointed at that network's sequencer; beside
/// `LEZ_RLN_SEQUENCER` it only labels the home, so `use_network` can refuse a
/// registry on another chain.
const NETWORK_ENV: &str = "LEZ_RLN_NETWORK";

/// The wallet's own config inside a home. Its presence is what makes a home
/// "configured": this module never rewrites one.
const CONFIG_FILE: &str = "wallet_config.json";

/// The wallet's storage inside a home: `open` when it exists, `create_new`
/// when it does not.
const STORAGE_FILE: &str = "storage.json";

/// Which network a home was provisioned for, `{"network":s,"source":s}`,
/// written beside the config whenever the network is known by name. A home
/// without one was configured by its operator and is not checked.
const NETWORK_FILE: &str = "network.json";

/// What `wallet_status` says while nothing has told this module which chain
/// to use.
const AWAIT_DETAIL: &str = "no network selected — no wallet_config.json, LEZ_RLN_SEQUENCER \
     unset; liblogos_rln_module.start selects one from its registry ids";

/// Before 7.0.0, a funded key to import into the module's own wallet.
/// `lez_core` has no import, so it is ignored — with one line saying so, since
/// an operator who set it expects that account to pay.
const PAYER_KEY_ENV: &str = "LEZ_RLN_PAYER_KEY";

/// The account this module published for funding, recorded in its own
/// persistence dir (not the wallet home, which is `lez_core`'s): with no
/// funded account in the wallet, `wallet_status` keeps naming the same one
/// across restarts instead of whichever the wallet lists first.
const PAYER_FILE: &str = "payer.json";

/// How long a handler waits for bring-up before giving up. Consumers already
/// retry a failed read; blocking a dispatch thread for a whole wallet open
/// would wedge the module under `concurrency:"multi"`.
const READY_WAIT: Duration = Duration::from_secs(30);

/// The execution gas a transaction declares, used to size the fee reserve the
/// payer must hold (`preflight_register`). Gas is cycles. The wallet's own
/// default, which the config this module writes leaves in force: a Register
/// costs ~52k, a slash ~650k. (While the program inserted into an on-chain
/// merkle tree a registration cost ~9.1M, which is why 3.0.0 to 6.x ran a
/// wallet of their own declaring 10M.)
pub(crate) const GAS_LIMIT: u64 = 2_000_000;

/// `lez_core` reads: the wallet answers from the sequencer, so a slow chain
/// is the bound. A send waits for the sequencer to accept it.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const SEND_TIMEOUT: Duration = Duration::from_secs(180);
/// Opening calibrates the sequencer client (3 probes, see `wallet_config_json`)
/// before it returns.
const OPEN_TIMEOUT: Duration = Duration::from_secs(120);
/// The protocol owns timeout enforcement; this margin only guards the channel
/// wait against a callback that never fires.
const REPLY_MARGIN: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ lez_core

/// The `lez_core` calls this module makes. `Err` is a transport failure (the
/// module did not answer); `lez_core`'s own failures arrive as values — "",
/// an empty list, a non-zero code — exactly as its contract spells them.
/// A trait so the decisions below can be tested against a fake wallet.
pub(crate) trait Core: Send + Sync {
    fn wallet_dir(&self) -> Result<String, String>;
    fn open(&self, config_path: &str, storage_path: &str) -> Result<i64, String>;
    fn create_new(&self, config_path: &str, storage_path: &str, password: &str)
        -> Result<String, String>;
    fn save(&self) -> Result<i64, String>;
    fn list_accounts(&self) -> Result<serde_json::Value, String>;
    fn create_account_public(&self) -> Result<String, String>;
    fn get_balance(&self, account_id_hex: &str, is_public: bool) -> Result<String, String>;
    fn get_account_public(&self, account_id_hex: &str) -> Result<String, String>;
    fn send_generic_public_transaction(&self, tx: &GenericTx) -> Result<String, String>;
    fn get_sequencer_addr(&self) -> Result<String, String>;
}

/// The arguments of `send_generic_public_transaction`, in `lez_core`'s
/// parallel-array form.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GenericTx {
    pub(crate) account_ids: Vec<String>,
    pub(crate) signing_requirements: Vec<bool>,
    pub(crate) instruction: Vec<u8>,
    pub(crate) program_id_hex: String,
    pub(crate) payer_account_id_hex: String,
    pub(crate) shard_program_account_ids_hex: Vec<String>,
}

/// The real `lez_core`, over the generated client. Every call is the async
/// twin with a per-call timeout, waited on here: this module runs
/// `concurrency:"multi"`, so a handler is on a worker thread, and a sync call
/// there would wait out the protocol default (20s) whatever the call needs.
struct LezCore {
    client: crate::lez_core::LezCoreClient,
}

/// Run one bounded async call and wait for its reply.
fn await_reply<T: Send + 'static>(
    method: &str,
    timeout: Duration,
    start: impl FnOnce(Box<dyn FnOnce(Result<T, logos_rust_sdk::LogosError>) + Send + 'static>),
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    start(Box::new(move |result| {
        let _ = tx.send(result);
    }));
    match rx.recv_timeout(timeout + REPLY_MARGIN) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("lez_core.{method}: {e}")),
        Err(_) => Err(format!("lez_core.{method}: no reply within {timeout:?}")),
    }
}

impl Core for LezCore {
    fn wallet_dir(&self) -> Result<String, String> {
        await_reply("wallet_dir", READ_TIMEOUT, |cb| {
            self.client.wallet_dir_async_with_timeout(READ_TIMEOUT, cb)
        })
    }

    fn open(&self, config_path: &str, storage_path: &str) -> Result<i64, String> {
        await_reply("open", OPEN_TIMEOUT, |cb| {
            self.client.open_async_with_timeout(config_path, storage_path, OPEN_TIMEOUT, cb)
        })
    }

    fn create_new(&self, config_path: &str, storage_path: &str, password: &str)
        -> Result<String, String> {
        await_reply("create_new", OPEN_TIMEOUT, |cb| {
            self.client
                .create_new_async_with_timeout(config_path, storage_path, password, OPEN_TIMEOUT, cb)
        })
    }

    fn save(&self) -> Result<i64, String> {
        await_reply("save", READ_TIMEOUT, |cb| self.client.save_async_with_timeout(READ_TIMEOUT, cb))
    }

    fn list_accounts(&self) -> Result<serde_json::Value, String> {
        await_reply("list_accounts", READ_TIMEOUT, |cb| {
            self.client.list_accounts_async_with_timeout(READ_TIMEOUT, cb)
        })
    }

    fn create_account_public(&self) -> Result<String, String> {
        await_reply("create_account_public", READ_TIMEOUT, |cb| {
            self.client.create_account_public_async_with_timeout(READ_TIMEOUT, cb)
        })
    }

    fn get_balance(&self, account_id_hex: &str, is_public: bool) -> Result<String, String> {
        await_reply("get_balance", READ_TIMEOUT, |cb| {
            self.client.get_balance_async_with_timeout(account_id_hex, is_public, READ_TIMEOUT, cb)
        })
    }

    fn get_account_public(&self, account_id_hex: &str) -> Result<String, String> {
        await_reply("get_account_public", READ_TIMEOUT, |cb| {
            self.client.get_account_public_async_with_timeout(account_id_hex, READ_TIMEOUT, cb)
        })
    }

    fn send_generic_public_transaction(&self, tx: &GenericTx) -> Result<String, String> {
        let ids = serde_json::json!(tx.account_ids);
        let signs = serde_json::json!(tx.signing_requirements);
        let shards = serde_json::json!(tx.shard_program_account_ids_hex);
        await_reply("send_generic_public_transaction", SEND_TIMEOUT, |cb| {
            self.client.send_generic_public_transaction_async_with_timeout(
                &ids,
                &signs,
                &tx.instruction,
                &tx.program_id_hex,
                &tx.payer_account_id_hex,
                &shards,
                SEND_TIMEOUT,
                cb,
            )
        })
    }

    fn get_sequencer_addr(&self) -> Result<String, String> {
        await_reply("get_sequencer_addr", READ_TIMEOUT, |cb| {
            self.client.get_sequencer_addr_async_with_timeout(READ_TIMEOUT, cb)
        })
    }
}

/// The process-lifetime `lez_core` client. Created on the host's main thread
/// by `spawn_bring_up`, so construction happens at load rather than inside a
/// dispatch worker.
static CORE: Mutex<Option<Arc<dyn Core>>> = Mutex::new(None);

fn core() -> Arc<dyn Core> {
    let mut slot = lock(&CORE);
    Arc::clone(slot.get_or_insert_with(|| {
        Arc::new(LezCore { client: crate::lez_core::LezCoreClient::new() }) as Arc<dyn Core>
    }))
}

// --------------------------------------------------------------------- state

pub(crate) enum Readiness {
    /// Bring-up has not finished: resolving the home, opening the wallet or
    /// choosing a payer. The string says what it is waiting on, for a human
    /// reading `wallet_status`; empty until bring-up has something more
    /// specific to report.
    Pending(String),
    /// Open, with a payer to publish.
    Ready,
    /// Bring-up gave up; the string is the reason, already logged.
    Failed(String),
}

struct State {
    readiness: Readiness,
    /// The account a registration would pay with now, as last picked; ""
    /// until bring-up settles. `wallet_status` reports it without a chain
    /// read; the paths that spend re-pick (`payer_hex`).
    payer_hex: String,
    /// The sequencer of a wallet another consumer opened and this module
    /// adopted, when the home's config does not name one.
    adopted_sequencer: Option<String>,
}

static STATE: Mutex<State> = Mutex::new(State {
    readiness: Readiness::Pending(String::new()),
    payer_hex: String::new(),
    adopted_sequencer: None,
});

/// This module's own persistence dir (where `payer.json` lives); "" when the
/// host gave none.
static PERSISTENCE: Mutex<String> = Mutex::new(String::new());

/// Held across a submission and nothing else.
///
/// A transaction's nonce is read from confirmed on-chain state, not from a
/// local counter, and it only advances once the transaction settles. Two
/// submissions from one account that overlap that window therefore build with
/// the same nonce and one is dropped.
///
/// `REG_IN_FLIGHT` does not cover this — it keys on the membership PDA, so
/// two DIFFERENT memberships still race. Reads are deliberately outside: the
/// `single` -> `multi` bump exists to keep them concurrent.
static SEND_LOCK: Mutex<()> = Mutex::new(());

/// Signalled once bring-up settles, either way.
static SETTLED: Condvar = Condvar::new();

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ------------------------------------------------------------ network choice

/// Who decided which network a home talks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// The built-in table, from `LEZ_RLN_NETWORK` or `use_network`.
    Table,
    /// `LEZ_RLN_NETWORK` naming the chain `LEZ_RLN_SEQUENCER` points at.
    Env,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Table => "table",
            Source::Env => "env",
        }
    }
}

/// What a home is known to be pointed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Binding {
    /// Configured outside the table — a staged home without a marker, or
    /// `LEZ_RLN_SEQUENCER` alone. Its network has no name here, so nothing is
    /// checked against it.
    Operator,
    /// Recorded in `network.json`.
    Recorded { network: String, source: Source },
}

/// The environment `plan_home` reads, trimmed; empty means unset. A struct
/// rather than `std::env` so the tests can say what they mean without
/// mutating the process environment under a parallel test runner.
pub(crate) struct EnvView {
    pub(crate) sequencer: String,
    /// Lowercased: a CAIP-2 `logos` reference is.
    pub(crate) network: String,
}

impl EnvView {
    fn from_env() -> Self {
        let read = |name: &str| std::env::var(name).unwrap_or_default().trim().to_owned();
        Self {
            sequencer: read(SEQUENCER_ENV),
            network: read(NETWORK_ENV).to_ascii_lowercase(),
        }
    }
}

/// How bring-up should treat a home, decided before anything is written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// The home is configured already: open it as it stands.
    Adopt(Binding),
    /// Write a config for `sequencer` (and the marker the binding implies),
    /// then open.
    Provision { sequencer: String, binding: Binding },
    /// Nothing says which chain: wait for `use_network`.
    AwaitSelection,
    /// Bring-up cannot start, and waiting will not change that.
    Failed(String),
}

/// Decide what a home needs, in precedence order: an existing config (never
/// rewritten — adopting a home means adopting the chain it already points at,
/// and re-pointing a wallet that holds registered memberships would strand
/// them), then `LEZ_RLN_SEQUENCER` (optionally labelled by `LEZ_RLN_NETWORK`),
/// then `LEZ_RLN_NETWORK` alone through the table, then nothing — which is not
/// a failure since 4.1.0, because the consumer's registry id can still name
/// the network.
pub(crate) fn plan_home(home: &Path, env: &EnvView) -> Plan {
    if home.join(CONFIG_FILE).exists() {
        return match read_marker(home) {
            Ok(binding) => Plan::Adopt(binding.unwrap_or(Binding::Operator)),
            Err(e) => Plan::Failed(e),
        };
    }
    if !env.sequencer.is_empty() {
        let binding = if env.network.is_empty() {
            Binding::Operator
        } else {
            Binding::Recorded { network: env.network.clone(), source: Source::Env }
        };
        return Plan::Provision { sequencer: env.sequencer.clone(), binding };
    }
    if !env.network.is_empty() {
        return match networks::network(&env.network) {
            Some(n) => Plan::Provision {
                sequencer: n.sequencer.clone(),
                binding: Binding::Recorded { network: n.reference.clone(), source: Source::Table },
            },
            None => Plan::Failed(format!(
                "{NETWORK_ENV}: {}",
                unknown_network(&env.network)
            )),
        };
    }
    Plan::AwaitSelection
}

fn unknown_network(reference: &str) -> String {
    format!(
        "unknown network '{reference}' (known: {}); set {SEQUENCER_ENV} or {HOME_ENV}",
        networks::known_references().join(", ")
    )
}

/// The home's `network.json`, if it has one. A marker that exists but does not
/// parse is an error rather than "no marker": reading it as operator-configured
/// would silently switch the network check off.
fn read_marker(home: &Path) -> Result<Option<Binding>, String> {
    let path = home.join(NETWORK_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let network = doc.get("network").and_then(|v| v.as_str()).unwrap_or_default();
    let source = match doc.get("source").and_then(|v| v.as_str()) {
        Some("table") => Source::Table,
        Some("env") => Source::Env,
        other => return Err(format!("{}: unknown source {other:?}", path.display())),
    };
    if network.is_empty() {
        return Err(format!("{} names no network", path.display()));
    }
    Ok(Some(Binding::Recorded { network: network.to_owned(), source }))
}

/// Write a home's config and marker. The marker goes first: a crash between
/// the two leaves a marker with no config, which the next start ignores and
/// overwrites, whereas the other order would leave a config that reads as
/// operator-configured and so is never checked. Each file is written to a
/// sibling and renamed into place, so neither is ever seen half-written.
fn provision_home(home: &Path, sequencer: &str, binding: &Binding) -> Result<(), String> {
    std::fs::create_dir_all(home).map_err(|e| format!("create {}: {e}", home.display()))?;
    let marker = home.join(NETWORK_FILE);
    match binding {
        Binding::Recorded { network, source } => {
            let doc = serde_json::json!({ "network": network, "source": source.as_str() });
            write_atomic(&marker, &doc.to_string())?;
        }
        // A marker left by an interrupted provisioning must not outlive it and
        // bind a home the operator has since pointed elsewhere.
        Binding::Operator => match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove {}: {e}", marker.display())),
        },
    }
    write_atomic(&home.join(CONFIG_FILE), &wallet_config_json(sequencer))
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

/// Where network selection stands.
enum Selection {
    /// `on_context_ready` has not run, so the home is not known yet.
    Unresolved,
    /// The home is known and unconfigured; bring-up waits for `use_network`.
    Awaiting(PathBuf),
    /// Configured; bring-up has been started for it.
    Bound { home: PathBuf, binding: Binding },
    /// Bring-up cannot start; the reason, already reported.
    Failed(String),
}

struct Selector {
    selection: Selection,
    /// `use_network` against an operator-configured home says once that it is
    /// not checking, not once per registry per restart of the consumer.
    operator_noted: bool,
}

/// Serializes network selection: two consumers naming two networks at once
/// must not both find the home unconfigured.
///
/// Lock order: `SELECTION` before `STATE`, never the reverse — `pending` and
/// `fail` take `STATE` while this is held.
static SELECTION: Mutex<Selector> = Mutex::new(Selector {
    selection: Selection::Unresolved,
    operator_noted: false,
});

/// What a selection step asks the caller to do once it has decided.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    None,
    Start(PathBuf),
    Await,
    Fail(String),
}

/// Run an `Action`. Kept apart from the decisions so the tests can make them
/// without spawning a bring-up thread or touching the shared state.
fn perform(action: Action) {
    match action {
        Action::None => {}
        Action::Start(home) => start_bring_up(home),
        Action::Await => pending(AWAIT_DETAIL),
        Action::Fail(reason) => fail(&reason),
    }
}

/// Record a plan's outcome and say what to do about it.
fn apply_plan(sel: &mut Selector, home: PathBuf, plan: Plan) -> Action {
    match plan {
        Plan::Adopt(binding) => {
            log_binding("adopting", &home, &binding);
            sel.selection = Selection::Bound { home: home.clone(), binding };
            Action::Start(home)
        }
        Plan::Provision { sequencer, binding } => {
            if let Err(e) = provision_home(&home, &sequencer, &binding) {
                sel.selection = Selection::Failed(e.clone());
                return Action::Fail(e);
            }
            log_binding(&format!("provisioned for {sequencer}"), &home, &binding);
            sel.selection = Selection::Bound { home: home.clone(), binding };
            Action::Start(home)
        }
        Plan::AwaitSelection => {
            eprintln!("lez-rln wallet: {} — {AWAIT_DETAIL}", home.display());
            sel.selection = Selection::Awaiting(home);
            Action::Await
        }
        Plan::Failed(reason) => {
            sel.selection = Selection::Failed(reason.clone());
            Action::Fail(reason)
        }
    }
}

fn log_binding(what: &str, home: &Path, binding: &Binding) {
    match binding {
        Binding::Operator => eprintln!("lez-rln wallet: {what} {} (operator-configured)", home.display()),
        Binding::Recorded { network, source } => eprintln!(
            "lez-rln wallet: {what} {} (network {network}, from {})",
            home.display(),
            source.as_str()
        ),
    }
}

/// `use_network`'s reply.
#[derive(Debug, PartialEq, Eq)]
struct NetworkReply {
    accepted: bool,
    detail: String,
    /// The network the home serves under the requested name: the recorded
    /// one, the requested one for an operator-configured home, "" if none.
    network: String,
    /// Not accepted YET: the home is not known, ask again.
    retry: bool,
    /// "table" | "env" | "operator"; "" when nothing is bound.
    source: &'static str,
}

impl NetworkReply {
    fn refused(detail: String, network: &str) -> Self {
        Self { accepted: false, detail, network: network.to_owned(), retry: false, source: "" }
    }

    fn to_json(&self) -> String {
        serde_json::json!({
            "accepted": self.accepted,
            "detail": self.detail,
            "network": self.network,
            "retry": self.retry,
            "source": self.source,
        })
        .to_string()
    }
}

/// Decide a `use_network` request against where selection stands. Writes the
/// home's files when it binds one; the returned `Action` is what the caller
/// still has to do.
fn select_network(sel: &mut Selector, reference: &str) -> (NetworkReply, Action) {
    let reference = reference.trim().to_ascii_lowercase();
    let home = match &sel.selection {
        Selection::Unresolved => {
            return (
                NetworkReply {
                    accepted: false,
                    detail: "the wallet home is not resolved yet".to_owned(),
                    network: String::new(),
                    retry: true,
                    source: "",
                },
                Action::None,
            )
        }
        Selection::Failed(reason) => {
            return (
                NetworkReply::refused(format!("the wallet cannot come up: {reason}"), ""),
                Action::None,
            )
        }
        Selection::Bound { home, binding } => {
            return (answer_bound(home, binding, &reference, &mut sel.operator_noted), Action::None)
        }
        Selection::Awaiting(home) => home.clone(),
    };

    // Re-checked under the lock: a home someone configured since bring-up
    // looked is adopted as it stands, never overwritten.
    if home.join(CONFIG_FILE).exists() {
        let action = apply_plan(sel, home.clone(), plan_home(&home, &EnvView {
            sequencer: String::new(),
            network: String::new(),
        }));
        let reply = match &sel.selection {
            Selection::Bound { home, binding } => {
                answer_bound(home, binding, &reference, &mut sel.operator_noted)
            }
            Selection::Failed(reason) => {
                NetworkReply::refused(format!("the wallet cannot come up: {reason}"), "")
            }
            _ => NetworkReply::refused("the wallet home changed under selection".to_owned(), ""),
        };
        return (reply, action);
    }

    let Some(network) = networks::network(&reference) else {
        return (NetworkReply::refused(unknown_network(&reference), ""), Action::None);
    };
    let binding = Binding::Recorded { network: network.reference.clone(), source: Source::Table };
    let action = apply_plan(
        sel,
        home,
        Plan::Provision { sequencer: network.sequencer.clone(), binding },
    );
    let reply = match &action {
        Action::Fail(e) => NetworkReply::refused(e.clone(), ""),
        _ => NetworkReply {
            accepted: true,
            detail: String::new(),
            network: network.reference.clone(),
            retry: false,
            source: Source::Table.as_str(),
        },
    };
    (reply, action)
}

fn answer_bound(
    home: &Path,
    binding: &Binding,
    reference: &str,
    operator_noted: &mut bool,
) -> NetworkReply {
    match binding {
        Binding::Operator => {
            if !*operator_noted {
                *operator_noted = true;
                eprintln!(
                    "lez-rln wallet: {} was configured by its operator — network '{reference}' \
                     is not checked against it",
                    home.display()
                );
            }
            NetworkReply {
                accepted: true,
                detail: "operator-configured home; the network is not checked".to_owned(),
                network: reference.to_owned(),
                retry: false,
                source: "operator",
            }
        }
        Binding::Recorded { network, source } if network == reference => NetworkReply {
            accepted: true,
            detail: String::new(),
            network: network.clone(),
            retry: false,
            source: source.as_str(),
        },
        Binding::Recorded { network, .. } => NetworkReply::refused(
            format!(
                "wallet home {} is bound to network {network}; refusing to re-point it to \
                 {reference}",
                home.display()
            ),
            network,
        ),
    }
}

/// Bind this module's wallet to the network a consumer's registry id names,
/// if nothing has bound it yet; otherwise say whether it matches. See
/// `select_network` and the `.lidl` for the reply.
pub(crate) fn use_network(reference: &str) -> String {
    let mut sel = lock(&SELECTION);
    let (reply, action) = select_network(&mut sel, reference);
    if !reply.retry {
        eprintln!(
            "lez-rln wallet: use_network({reference}) -> accepted={} {}",
            reply.accepted, reply.detail
        );
    }
    perform(action);
    reply.to_json()
}

/// The network the wallet's home is recorded as bound to; `None` while
/// unbound or operator-configured.
pub(crate) fn bound_network() -> Option<String> {
    match &lock(&SELECTION).selection {
        Selection::Bound { binding: Binding::Recorded { network, .. }, .. } => {
            Some(network.clone())
        }
        _ => None,
    }
}

/// The sequencer the wallet's home is configured with; `None` until a network
/// is selected, or when the config names none. Read from the file rather than
/// the wallet, so it answers while bring-up is still opening the wallet.
pub(crate) fn sequencer_addr() -> Option<String> {
    let home = match &lock(&SELECTION).selection {
        Selection::Bound { home, .. } => home.clone(),
        _ => return None,
    };
    let path = home.join(CONFIG_FILE);
    let from_config = std::fs::read_to_string(&path)
        .map_err(|e| eprintln!("lez-rln wallet: read {}: {e}", path.display()))
        .ok()
        .and_then(|raw| sequencer_of_config(&raw));
    // A wallet another consumer opened answers for its own sequencer when
    // the home's config names none (an operator home, or none at all).
    from_config.or_else(|| lock(&STATE).adopted_sequencer.clone())
}

/// `sequencer.sequencer_addr`, else `sequencers[0].sequencer_addr`, else the
/// flat `sequencer_addr` — the shapes `wallet_config_json` writes, since an
/// adopted home may carry any of them.
fn sequencer_of_config(raw: &str) -> Option<String> {
    let config: serde_json::Value = serde_json::from_str(raw).ok()?;
    config
        .pointer("/sequencer/sequencer_addr")
        .or_else(|| config.pointer("/sequencers/0/sequencer_addr"))
        .or_else(|| config.get("sequencer_addr"))
        .and_then(|s| s.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

// ------------------------------------------------------------------ bring-up

/// Start bring-up. Called from `on_context_ready`, which runs on the host's
/// Qt main thread — so the only work done here is creating the `lez_core`
/// client. Asking `lez_core` where its wallet lives, opening it and picking a
/// payer are calls to another module and run on their own thread.
pub(crate) fn spawn_bring_up(persistence_path: &str) {
    if !matches!(lock(&SELECTION).selection, Selection::Unresolved)
        || RESOLVE_STARTED.swap(true, Ordering::SeqCst)
    {
        eprintln!("lez-rln wallet: bring-up already resolved, ignoring the repeat");
        return;
    }
    *lock(&PERSISTENCE) = persistence_path.to_owned();
    let core = core();
    std::thread::Builder::new()
        .name("lez-rln-wallet-home".to_owned())
        .spawn(move || resolve_and_plan(core.as_ref()))
        .map(|_| ())
        .unwrap_or_else(|e| {
            let reason = format!("cannot spawn the wallet bring-up thread: {e}");
            lock(&SELECTION).selection = Selection::Failed(reason.clone());
            fail(&reason);
        });
}

/// Guards `spawn_bring_up` against a second entry.
static RESOLVE_STARTED: AtomicBool = AtomicBool::new(false);

/// Find the home, then decide what it needs exactly as before 7.0.0.
fn resolve_and_plan(core: &dyn Core) {
    let home = match resolve_home(core) {
        Ok(home) => home,
        Err(reason) => {
            lock(&SELECTION).selection = Selection::Failed(reason.clone());
            fail(&reason);
            return;
        }
    };
    let mut sel = lock(&SELECTION);
    let plan = plan_home(&home, &EnvView::from_env());
    let action = apply_plan(&mut sel, home, plan);
    drop(sel);
    perform(action);
}

/// `LEE_WALLET_HOME_DIR`, else `lez_core`'s own dir. `lez_core` not answering
/// is an outage and is waited out (`pending`); `lez_core` answering that it
/// has no dir is final.
fn resolve_home(core: &dyn Core) -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(HOME_ENV) {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir.trim()));
        }
    }
    let start = Instant::now();
    loop {
        match core.wallet_dir() {
            Ok(dir) => return home_of_wallet_dir(&dir),
            Err(e) => {
                let waited = start.elapsed();
                pending(&format!("asking lez_core where its wallet lives: {e}"));
                if waited.is_zero() || waited >= Duration::from_secs(600) {
                    eprintln!("lez-rln wallet: {e}");
                }
                sleep_in_slices(open_retry_interval(waited));
            }
        }
    }
}

/// `lez_core.wallet_dir()`'s answer as a home: "-" (or nothing) is
/// `LEZ_NO_WALLET_DIR`, a host that gave `lez_core` no persistence path.
fn home_of_wallet_dir(dir: &str) -> Result<PathBuf, String> {
    let dir = dir.trim();
    if dir.is_empty() || dir == "-" {
        return Err(format!(
            "lez_core has no persistence dir to keep a wallet in, and {HOME_ENV} is unset"
        ));
    }
    Ok(PathBuf::from(dir))
}

/// Open a configured home on its own thread.
fn start_bring_up(home: PathBuf) {
    // One bring-up per process, ever. It retries an unreachable sequencer
    // indefinitely, so a second call would leave two loops opening the same
    // home against each other.
    if BRINGUP_STARTED.swap(true, Ordering::SeqCst) {
        eprintln!("lez-rln wallet: bring-up already running, ignoring the repeat");
        return;
    }
    std::thread::Builder::new()
        .name("lez-rln-wallet".to_owned())
        .spawn(move || bring_up(&home))
        .map(|_| ())
        .unwrap_or_else(|e| {
            BRINGUP_STARTED.store(false, Ordering::SeqCst);
            fail(&format!("cannot spawn the wallet bring-up thread: {e}"));
        });
}

/// Guards `start_bring_up` against a second entry; see there.
static BRINGUP_STARTED: AtomicBool = AtomicBool::new(false);

fn fail(reason: &str) {
    eprintln!("lez-rln wallet: {reason}");
    let mut state = lock(&STATE);
    state.readiness = Readiness::Failed(reason.to_owned());
    SETTLED.notify_all();
}

/// Say what bring-up is waiting on, without settling it.
///
/// Deliberately does not notify `SETTLED`: nothing has settled, and waking
/// every waiting handler to tell it to keep waiting would only spin them
/// against `READY_WAIT`.
fn pending(detail: &str) {
    let mut state = lock(&STATE);
    state.readiness = Readiness::Pending(detail.to_owned());
}

/// Open the wallet, then pick a payer. No sync: the wallet answers no reads
/// while `sync_to_block` runs, a fresh sync takes tens of minutes on a public
/// chain, and nothing here needs one — account reads and the nonce a send
/// uses come from the sequencer.
fn bring_up(home: &Path) {
    let core = core();
    let config = home.join(CONFIG_FILE);
    let storage = home.join(STORAGE_FILE);
    match open_with_retry(core.as_ref(), &config, &storage) {
        Ok(Opened::Ours) => eprintln!("lez-rln wallet: opened {}", storage.display()),
        Ok(Opened::Adopted(sequencer)) => {
            eprintln!(
                "lez-rln wallet: lez_core already holds a wallet on {sequencer}; using it"
            );
            lock(&STATE).adopted_sequencer = Some(sequencer);
        }
        Err(reason) => {
            fail(&reason);
            return;
        }
    }
    if std::env::var(PAYER_KEY_ENV).is_ok_and(|v| !v.trim().is_empty()) {
        eprintln!(
            "lez-rln wallet: {PAYER_KEY_ENV} is ignored since 7.0.0 — lez_core cannot import \
             a key; fund an account in the wallet (wallet_status names one) or name one it \
             holds in LEZ_RLN_PAYER"
        );
    }
    let payer = match payer_with_retry(core.as_ref()) {
        Ok(p) => p,
        Err(reason) => {
            fail(&reason);
            return;
        }
    };
    let mut state = lock(&STATE);
    state.payer_hex = payer;
    state.readiness = Readiness::Ready;
    SETTLED.notify_all();
    eprintln!("lez-rln wallet: ready ({}, payer {})", home.display(), state.payer_hex);
}

/// How the wallet came to be open.
#[derive(Debug, PartialEq, Eq)]
enum Opened {
    /// This module opened (or created) the home's storage.
    Ours,
    /// Another consumer had `lez_core` open already, on this sequencer.
    Adopted(String),
}

/// Why an open did not happen: worth retrying, or not.
#[derive(Debug, PartialEq, Eq)]
enum OpenError {
    Retry(String),
    Fatal(String),
}

/// One attempt to have `lez_core` hold this home's wallet.
fn open_or_adopt(core: &dyn Core, config: &Path, storage: &Path) -> Result<Opened, OpenError> {
    let c = config.to_string_lossy();
    let s = storage.to_string_lossy();
    let transport = |e: String| OpenError::Retry(e);
    let opened = if storage.exists() {
        let code = core.open(&c, &s).map_err(transport)?;
        code == 0
    } else {
        // Loud on purpose: a home that was meant to carry a staged wallet and
        // gets an empty one registers nothing, and says why only much later.
        // This wallet build does not encrypt storage with the password
        // (storage.json is plaintext either way), and the recovery mnemonic
        // is not needed: the payer is any funded account, recreatable.
        let mnemonic = core.create_new(&c, &s, "").map_err(transport)?;
        if mnemonic.is_empty() {
            false
        } else {
            eprintln!("lez-rln wallet: no storage at {s} — created an empty wallet");
            let _ = core.save();
            true
        }
    };
    if opened {
        return Ok(Opened::Ours);
    }
    // Refused or failed — the code is the same. A wallet that answers for its
    // sequencer is open: someone else's.
    let open_on = core.get_sequencer_addr().map_err(transport)?;
    let open_on = open_on.trim();
    if open_on.is_empty() {
        return Err(OpenError::Retry(format!("lez_core could not open {s}")));
    }
    let wanted = std::fs::read_to_string(config).ok().and_then(|raw| sequencer_of_config(&raw));
    match wanted {
        Some(wanted) if !same_sequencer(&wanted, open_on) => Err(OpenError::Fatal(format!(
            "lez_core already holds a wallet on {open_on}, but this module's home is for \
             {wanted}; lez_core opens one wallet per host and cannot be re-pointed"
        ))),
        _ => Ok(Opened::Adopted(open_on.to_owned())),
    }
}

fn same_sequencer(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Open the wallet, retrying for as long as it takes.
///
/// Opening a wallet is a chain read: the sequencer client calibrates its
/// endpoint first, so an unreachable sequencer fails the open outright. That
/// is the ordinary shape of a node started while the chain is down, and a
/// node that gives up is still broken an hour after the outage ended — so
/// there is no deadline, and the wallet stays `pending` throughout. `failed`
/// is kept for what waiting cannot fix: a wallet open on another chain.
fn open_with_retry(core: &dyn Core, config: &Path, storage: &Path) -> Result<Opened, String> {
    /// Past this much continuous failure, keep retrying but stop implying the
    /// wait is routine: something needs looking at.
    const LATCH_AFTER: Duration = Duration::from_secs(600);

    let start = Instant::now();
    let mut attempt = 0_u64;
    loop {
        attempt += 1;
        match open_or_adopt(core, config, storage) {
            Ok(opened) => {
                if attempt > 1 {
                    eprintln!(
                        "lez-rln wallet: opened on attempt {attempt} after {}s",
                        start.elapsed().as_secs()
                    );
                }
                return Ok(opened);
            }
            Err(OpenError::Fatal(reason)) => return Err(reason),
            Err(OpenError::Retry(e)) => {
                let waited = start.elapsed();
                let detail = if waited >= LATCH_AFTER {
                    format!(
                        "cannot open the wallet after {}s and {attempt} attempts — is the \
                         sequencer reachable? last error: {e}",
                        waited.as_secs()
                    )
                } else {
                    format!("opening the wallet: {e}")
                };
                // Loud on the first failure and then once per escalation, not
                // once per attempt.
                if attempt == 1 || waited >= LATCH_AFTER {
                    eprintln!("lez-rln wallet: {detail}");
                }
                pending(&detail);
                sleep_in_slices(open_retry_interval(waited));
            }
        }
    }
}

/// Read often at first, then rarely — the cadence `logos-rln-module`'s funding
/// wait already settled on: 5s for the first minute, 30s to ten minutes, then
/// every five.
fn open_retry_interval(waited: Duration) -> Duration {
    if waited < Duration::from_secs(60) {
        Duration::from_secs(5)
    } else if waited < Duration::from_secs(600) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(300)
    }
}

/// Sleep in short slices so a five-minute backoff does not keep the process
/// alive for five minutes past a shutdown.
fn sleep_in_slices(total: Duration) {
    const SLICE: Duration = Duration::from_secs(5);
    let mut left = total;
    while left > Duration::ZERO {
        let step = if left < SLICE { left } else { SLICE };
        std::thread::sleep(step);
        left -= step;
    }
}

// --------------------------------------------------------------------- payer

/// Pick the bring-up payer, waiting out a `lez_core` that does not answer.
fn payer_with_retry(core: &dyn Core) -> Result<String, String> {
    let start = Instant::now();
    loop {
        let recorded = read_recorded_payer();
        match pick_payer(core, &crate::fee_payer_env_hex(), &recorded) {
            Ok(pick) => {
                if pick.record {
                    record_payer(&pick.account);
                }
                return Ok(pick.account);
            }
            Err(PayerError::Fatal(reason)) => return Err(reason),
            Err(PayerError::Retry(e)) => {
                pending(&format!("choosing a payer: {e}"));
                sleep_in_slices(open_retry_interval(start.elapsed()));
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PayerPick {
    account: String,
    /// The account was chosen for funding, not for a balance: write it down
    /// so the published payer stays the same across restarts.
    record: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum PayerError {
    Retry(String),
    Fatal(String),
}

/// The wallet's public accounts as hex64, in the wallet's order.
fn public_accounts(core: &dyn Core) -> Result<Vec<String>, String> {
    let listed = core.list_accounts()?;
    // A LogosList may cross the bridge as the array or as its JSON text.
    let listed = match listed {
        serde_json::Value::String(text) => serde_json::from_str(&text).unwrap_or_default(),
        other => other,
    };
    Ok(listed
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|e| e.get("is_public").and_then(|p| p.as_bool()) == Some(true))
                .filter_map(|e| e.get("account_id").and_then(|id| id.as_str()))
                .filter(|id| crate::hex_to_bytes32(id).is_some())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default())
}

/// The account to pay with now. In order:
/// 1. `LEZ_RLN_PAYER` (`configured`), which must be an account the wallet
///    holds — the signature is what authorizes the debit.
/// 2. The best-funded public account.
/// 3. With nothing funded, the account published for funding before
///    (`recorded`), if the wallet still holds it.
/// 4. The wallet's first public account, or a new one if it has none.
fn pick_payer(core: &dyn Core, configured: &str, recorded: &str) -> Result<PayerPick, PayerError> {
    let accounts = public_accounts(core).map_err(PayerError::Retry)?;
    if !configured.is_empty() {
        return if accounts.iter().any(|a| a == configured) {
            Ok(PayerPick { account: configured.to_owned(), record: false })
        } else {
            Err(PayerError::Fatal(format!(
                "LEZ_RLN_PAYER {configured} is not an account in the lez_core wallet — it \
                 cannot sign for it"
            )))
        };
    }
    let mut best: Option<(u128, &String)> = None;
    for account in &accounts {
        // An account whose balance cannot be read is skipped, never read as
        // zero and never as funded.
        let Some(balance) = core.get_balance(account, true).ok().and_then(|b| b.trim().parse::<u128>().ok())
        else {
            continue;
        };
        if balance > 0 && best.is_none_or(|(b, _)| balance > b) {
            best = Some((balance, account));
        }
    }
    if let Some((_, account)) = best {
        return Ok(PayerPick { account: account.clone(), record: false });
    }
    if !recorded.is_empty() && accounts.iter().any(|a| a == recorded) {
        return Ok(PayerPick { account: recorded.to_owned(), record: false });
    }
    if let Some(first) = accounts.first() {
        return Ok(PayerPick { account: first.clone(), record: true });
    }
    let created = core.create_account_public().map_err(PayerError::Retry)?;
    let created = created.trim().to_ascii_lowercase();
    if crate::hex_to_bytes32(&created).is_none() {
        return Err(PayerError::Retry("lez_core could not create an account".to_owned()));
    }
    // Derivation alone does not persist; without a save the account is gone
    // on the next open and nothing can sign for it.
    let _ = core.save();
    eprintln!(
        "lez-rln wallet: created the payer {created} — it holds nothing until something \
         transfers to it"
    );
    Ok(PayerPick { account: created, record: true })
}

/// `name` in this module's own persistence dir; `None` when the host gave
/// none.
pub(crate) fn persistence_file(name: &str) -> Option<PathBuf> {
    let dir = lock(&PERSISTENCE).clone();
    (!dir.is_empty()).then(|| PathBuf::from(dir).join(name))
}

#[cfg(test)]
pub(crate) fn set_persistence_for_test(dir: &str) {
    *lock(&PERSISTENCE) = dir.to_owned();
}

fn payer_file() -> Option<PathBuf> {
    persistence_file(PAYER_FILE)
}

fn read_recorded_payer() -> String {
    payer_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|raw| raw.trim().trim_matches('"').to_ascii_lowercase())
        .filter(|id| crate::hex_to_bytes32(id).is_some())
        .unwrap_or_default()
}

fn record_payer(account: &str) {
    let Some(path) = payer_file() else { return };
    if let Err(e) = std::fs::write(&path, account) {
        eprintln!("lez-rln wallet: write {}: {e}", path.display());
    }
}

/// The account a payment would come from now, re-picked so that funding any
/// account in the wallet is noticed without a restart. Falls back to the last
/// pick when `lez_core` does not answer; "" before bring-up settles.
pub(crate) fn payer_hex() -> String {
    let Some(core) = wallet("payer") else {
        return lock(&STATE).payer_hex.clone();
    };
    match pick_payer(core.as_ref(), &crate::fee_payer_env_hex(), &read_recorded_payer()) {
        Ok(pick) => {
            if pick.record {
                record_payer(&pick.account);
            }
            let mut state = lock(&STATE);
            if state.payer_hex != pick.account {
                eprintln!("lez-rln wallet: paying from {} now", pick.account);
                state.payer_hex = pick.account.clone();
            }
            pick.account
        }
        Err(PayerError::Retry(e) | PayerError::Fatal(e)) => {
            eprintln!("lez-rln wallet: keeping the last payer: {e}");
            lock(&STATE).payer_hex.clone()
        }
    }
}

// ----------------------------------------------------------------- the calls

/// The config this module writes for a home it provisions itself. The shape
/// mirrors what `tools/deployments/stage.sh` emits and what the membership
/// module's `provision_wallet_home` writes, so a home staged by either is
/// readable here and vice versa. No `gas_limit`: the wallet's own default
/// covers every call the program has (see `GAS_LIMIT`).
fn wallet_config_json(sequencer: &str) -> String {
    serde_json::json!({
        // v0.3.1 reads `sequencer`, v0.2.5-v0.3.0 `sequencers`, the rc6-era
        // wallet the flat field. None denies unknown fields, so all ride along.
        "sequencer": { "sequencer_addr": sequencer },
        "sequencer_addr": sequencer,
        "sequencers": [{ "sequencer_addr": sequencer }],
        "seq_poll_timeout": "30s",
        "seq_tx_poll_max_blocks": 15,
        "seq_poll_max_retries": 10,
        "seq_block_poll_max_amount": 100,
        // The default is 100 sequential probes per sequencer, which blocks the
        // open for minutes against a slow chain. One sequencer, 3 probes.
        "multi_sequencer_client_config": { "distribution_limit": 1, "calibration_limit": 3 },
    })
    .to_string()
}

/// `lez_core`, once bring-up has settled. `None` means unusable, and the
/// caller reports the empty string.
fn wallet(who: &str) -> Option<Arc<dyn Core>> {
    let mut state = lock(&STATE);
    loop {
        match &state.readiness {
            Readiness::Ready => break,
            Readiness::Failed(reason) => {
                eprintln!("{who}: wallet unavailable: {reason}");
                return None;
            }
            Readiness::Pending(_) => {
                let (guard, timeout) = SETTLED
                    .wait_timeout(state, READY_WAIT)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state = guard;
                if timeout.timed_out() {
                    eprintln!("{who}: wallet still coming up after {READY_WAIT:?}");
                    return None;
                }
            }
        }
    }
    drop(state);
    Some(core())
}

/// Decode a base58 account id to 64 hex chars; empty string on failure. Needs
/// no wallet, so it answers before bring-up has finished — which matters,
/// because the fee payer is resolved on the register path.
pub(crate) fn account_id_from_base58(id: &str) -> String {
    match base58::decode32(id.trim()) {
        Some(bytes) => bytes_to_hex(&bytes),
        None => {
            eprintln!("account_id_from_base58: {id} is not a base58 account id");
            String::new()
        }
    }
}

/// Public account state as the JSON `{nonce, shards: {<program hex>: <data
/// hex>}}`. LEZ v0.3.0 shards an account's data by owning program; the native
/// balance is the shard of the native token program (`[0; 32]`), a 16-byte LE
/// u128. Empty string on failure.
pub(crate) fn get_account_public(account_id_hex: &str) -> String {
    if crate::hex_to_bytes32(account_id_hex).is_none() {
        eprintln!("get_account_public: {account_id_hex} is not 32-byte hex");
        return String::new();
    }
    let Some(core) = wallet("get_account_public") else {
        return String::new();
    };
    match core.get_account_public(account_id_hex) {
        Ok(raw) => account_json_from_core(&raw).unwrap_or_else(|| {
            if !raw.is_empty() {
                eprintln!("get_account_public({account_id_hex}): unexpected reply {raw}");
            }
            String::new()
        }),
        Err(e) => {
            eprintln!("get_account_public({account_id_hex}): {e}");
            String::new()
        }
    }
}

/// `lez_core`'s `{"nonce":<32 hex, 16 LE bytes>,"shards":[{"program","data"}]}`
/// in the shape the registry reads expect (`fetch_shards`): the nonce as a
/// decimal u128, the shards keyed by program. `None` for anything else — ""
/// included, which is how `lez_core` reports a failed read.
fn account_json_from_core(raw: &str) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_str(raw).ok()?;
    let nonce_hex = doc.get("nonce")?.as_str()?;
    let nonce_bytes: [u8; 16] = crate::hex_to_bytes(nonce_hex, Some(16))?.try_into().ok()?;
    let mut shards = serde_json::Map::new();
    for shard in doc.get("shards")?.as_array()? {
        let program = shard.get("program")?.as_str()?.to_ascii_lowercase();
        let data = shard.get("data").and_then(|d| d.as_str()).unwrap_or_default();
        shards.insert(program, serde_json::Value::String(data.to_ascii_lowercase()));
    }
    Some(
        serde_json::json!({
            "nonce": u128::from_le_bytes(nonce_bytes).to_string(),
            "shards": shards,
        })
        .to_string(),
    )
}

/// One account a transaction mentions: the account, whether it signs, and the
/// program whose shard of it the transaction selects (`[0; 32]` hex for the
/// native balance).
pub(crate) struct Mention {
    pub(crate) account_hex: String,
    pub(crate) signs: bool,
    pub(crate) shard_program_hex: String,
}

/// The `lez_core` arguments for a send, or why there are none. Every id is
/// checked here so a malformed one never reaches the wallet.
fn generic_tx(
    mentions: &[Mention],
    instruction: &[u8],
    program_hex: &str,
    payer_account_id_hex: &str,
) -> Result<GenericTx, String> {
    let mut tx = GenericTx {
        account_ids: Vec::with_capacity(mentions.len()),
        signing_requirements: Vec::with_capacity(mentions.len()),
        instruction: instruction.to_vec(),
        program_id_hex: String::new(),
        payer_account_id_hex: String::new(),
        shard_program_account_ids_hex: Vec::with_capacity(mentions.len()),
    };
    for m in mentions {
        if crate::hex_to_bytes32(&m.account_hex).is_none() {
            return Err(format!("{} is not 32-byte hex", m.account_hex));
        }
        if crate::hex_to_bytes32(&m.shard_program_hex).is_none() {
            return Err(format!("shard program {} is not 32-byte hex", m.shard_program_hex));
        }
        tx.account_ids.push(m.account_hex.to_ascii_lowercase());
        tx.signing_requirements.push(m.signs);
        tx.shard_program_account_ids_hex.push(m.shard_program_hex.to_ascii_lowercase());
    }
    if crate::hex_to_bytes32(program_hex).is_none() {
        return Err(format!("program {program_hex} is not 32-byte hex"));
    }
    tx.program_id_hex = program_hex.to_ascii_lowercase();
    // Empty means self-pay, matching the lez_core contract.
    let payer = payer_account_id_hex.trim();
    if !payer.is_empty() && crate::hex_to_bytes32(payer).is_none() {
        return Err(format!("payer {payer} is not 32-byte hex"));
    }
    tx.payer_account_id_hex = payer.to_ascii_lowercase();
    Ok(tx)
}

/// Submit a generic public transaction, answering the JSON
/// `{success, tx_hash, error}` shape the module already parses.
///
/// `program_hex` is the program's header account id: on LEZ v0.3.0 a program
/// lives at a keyed account its deployer created, not at a hash of its code.
pub(crate) fn send_generic_public_transaction(
    mentions: &[Mention],
    instruction: &[u8],
    program_hex: &str,
    payer_account_id_hex: &str,
) -> String {
    let tx = match generic_tx(mentions, instruction, program_hex, payer_account_id_hex) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("send_generic_public_transaction: {e}");
            return String::new();
        }
    };
    let Some(core) = wallet("send_generic_public_transaction") else {
        return String::new();
    };
    let reply = {
        // One submission at a time; see SEND_LOCK.
        let _serialized = lock(&SEND_LOCK);
        core.send_generic_public_transaction(&tx)
    };
    match reply {
        Ok(raw) => send_reply_from_core(&raw),
        Err(e) => {
            eprintln!("send_generic_public_transaction: {e}");
            String::new()
        }
    }
}

/// `lez_core`'s `{success, tx_hash, secrets, error}` as the module's
/// `{error, success, tx_hash}`; "" when it is not a reply at all.
fn send_reply_from_core(raw: &str) -> String {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
        eprintln!("send_generic_public_transaction: unexpected reply {raw:?}");
        return String::new();
    };
    let success = doc.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
    let tx_hash = doc.get("tx_hash").and_then(|s| s.as_str()).unwrap_or_default();
    let error = doc.get("error").and_then(|s| s.as_str()).unwrap_or_default();
    if !success {
        eprintln!("send_generic_public_transaction failed: {error}");
    }
    serde_json::json!({ "error": error, "success": success, "tx_hash": tx_hash }).to_string()
}

/// Live NATIVE balance of `account_hex`, or of the account this module would
/// pay with when empty (re-picked, so a freshly funded account shows up).
///
/// `None` means the question could not be answered — the wallet is not up, the
/// id is malformed, or the sequencer did not reply. That is deliberately not
/// zero: a caller deciding whether it can afford to register would read an
/// unreachable chain as "broke" and give up permanently.
pub(crate) fn native_balance(account_hex: &str) -> Option<(String, u128)> {
    let id_hex = if account_hex.trim().is_empty() {
        payer_hex()
    } else {
        account_hex.trim().to_ascii_lowercase()
    };
    if id_hex.is_empty() {
        eprintln!("native_balance: no account given and no payer resolved yet");
        return None;
    }
    crate::hex_to_bytes32(&id_hex)?;
    let core = wallet("native_balance")?;
    match core.get_balance(&id_hex, true) {
        Ok(raw) => match raw.trim().parse::<u128>() {
            Ok(balance) => Some((id_hex, balance)),
            Err(_) => {
                eprintln!("native_balance: {id_hex} read failed ({raw:?})");
                None
            }
        },
        Err(e) => {
            eprintln!("native_balance: {id_hex}: {e}");
            None
        }
    }
}

/// What the module can say about its wallet without one being open — the read
/// a consumer uses to tell "still coming up" from "broken".
pub(crate) fn status_json() -> String {
    // Read before `STATE` is taken: see SELECTION's lock order.
    let network = bound_network().unwrap_or_default();
    let state = lock(&STATE);
    // `state` is the field a consumer branches on, because the distinction
    // that matters is not ready-or-not but retry-or-give-up: "pending" means
    // wait, "failed" means waiting longer will not help. `detail` is for a
    // human reading a log.
    let (name, detail) = match &state.readiness {
        Readiness::Ready => ("ready", String::new()),
        Readiness::Pending(detail) if detail.is_empty() => {
            ("pending", "opening the wallet".to_owned())
        }
        Readiness::Pending(detail) => ("pending", detail.clone()),
        Readiness::Failed(reason) => ("failed", reason.clone()),
    };
    // `payer` is the last pick, never a chain read: this method is what a
    // consumer polls to tell "coming up" from "broken", so it must not be
    // able to block or fail on a sequencer round trip. What that account can
    // afford is get_native_balance's question.
    // `network` is the recorded binding, "" while unbound or when the home was
    // configured by its operator (whose network this module cannot name).
    serde_json::json!({
        "detail": detail,
        "network": network,
        "payer": state.payer_hex,
        "ready": name == "ready",
        "state": name,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base58_payer_resolves_without_a_wallet() {
        // The conversion is local now, so it answers before bring-up — which
        // matters, because the fee payer is resolved on the register path.
        assert_eq!(
            account_id_from_base58("FqNyaKjaeUxjMxJszC88Z6SUUL8pxBgN6qRHC4ZsJjgn"),
            "dc6857ef4236ef416fb6357c1f9988a7c7558b07492d7284c411b3864a1fccf3"
        );
        assert_eq!(account_id_from_base58("not an account"), "");
    }

    #[test]
    fn status_never_fails_and_starts_pending() {
        let s = status_json();
        assert!(s.contains(r#""state":"pending""#), "got {s}");
        assert!(s.contains(r#""ready":false"#), "got {s}");
    }

    /// An unreachable sequencer must read as `pending`, never `failed`: the
    /// state is what a consumer branches on to decide whether to keep waiting,
    /// and `logos-rln-module`'s provisioning pass abandons a registry for the
    /// life of the process on `failed`.
    #[test]
    fn a_failed_open_stays_pending_and_says_why() {
        pending("opening the wallet: open /nope/storage.json returned no handle");
        let s = status_json();
        assert!(s.contains(r#""state":"pending""#), "got {s}");
        assert!(s.contains(r#""ready":false"#), "got {s}");
        assert!(s.contains("returned no handle"), "detail is lost: {s}");
        // Leave the shared state as the other tests expect to find it.
        pending("");
    }

    /// The cadence matters more than the numbers: a retry that stayed at 5s
    /// would hammer a dead endpoint for as long as the outage lasts.
    #[test]
    fn the_open_retry_backs_off_but_never_stops() {
        assert_eq!(
            open_retry_interval(Duration::from_secs(0)),
            Duration::from_secs(5)
        );
        assert_eq!(
            open_retry_interval(Duration::from_secs(120)),
            Duration::from_secs(30)
        );
        assert_eq!(
            open_retry_interval(Duration::from_secs(3600)),
            Duration::from_secs(300)
        );
    }

    fn mention(account_hex: &str, shard_program_hex: &str) -> Mention {
        Mention {
            account_hex: account_hex.to_string(),
            signs: true,
            shard_program_hex: shard_program_hex.to_string(),
        }
    }

    #[test]
    fn a_malformed_shard_program_is_refused_before_any_call() {
        // Returns before touching the wallet, so it holds with none open.
        let out = send_generic_public_transaction(
            &[mention(&"ab".repeat(32), "not-hex")],
            &[1, 2, 3],
            &"cd".repeat(32),
            "",
        );
        assert_eq!(out, "");
    }

    // ---------------------------------------------------- network selection

    /// A fresh, empty directory per test; removed first so a rerun starts clean.
    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("lez-rln-wallet-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env(sequencer: &str, network: &str) -> EnvView {
        EnvView { sequencer: sequencer.to_owned(), network: network.to_owned() }
    }

    fn selector(selection: Selection) -> Selector {
        Selector { selection, operator_noted: false }
    }

    fn devnet_sequencer() -> String {
        networks::network("devnet").unwrap().sequencer.clone()
    }

    #[test]
    fn plan_adopts_an_existing_config_whatever_the_env_says() {
        let home = temp_home("plan-adopt");
        std::fs::write(home.join(CONFIG_FILE), "{}").unwrap();
        assert_eq!(
            plan_home(&home, &env("http://elsewhere/", "devnet")),
            Plan::Adopt(Binding::Operator)
        );
        std::fs::write(home.join(NETWORK_FILE), r#"{"network":"devnet","source":"table"}"#)
            .unwrap();
        assert_eq!(
            plan_home(&home, &env("", "")),
            Plan::Adopt(Binding::Recorded { network: "devnet".into(), source: Source::Table })
        );
        // A marker that does not parse must not read as "operator": that
        // would switch the network check off without a word.
        std::fs::write(home.join(NETWORK_FILE), "garbage").unwrap();
        assert!(matches!(plan_home(&home, &env("", "")), Plan::Failed(_)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn plan_provisions_from_the_sequencer_labelled_or_not() {
        let home = temp_home("plan-seq");
        assert_eq!(
            plan_home(&home, &env("http://seq/", "")),
            Plan::Provision { sequencer: "http://seq/".into(), binding: Binding::Operator }
        );
        assert_eq!(
            plan_home(&home, &env("http://seq/", "testnet")),
            Plan::Provision {
                sequencer: "http://seq/".into(),
                binding: Binding::Recorded { network: "testnet".into(), source: Source::Env },
            }
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn plan_looks_a_bare_network_up_in_the_table() {
        let home = temp_home("plan-net");
        assert_eq!(
            plan_home(&home, &env("", "devnet")),
            Plan::Provision {
                sequencer: devnet_sequencer(),
                binding: Binding::Recorded { network: "devnet".into(), source: Source::Table },
            }
        );
        let Plan::Failed(reason) = plan_home(&home, &env("", "nosuch")) else {
            panic!("an unknown network must fail");
        };
        assert!(reason.contains("unknown network 'nosuch'"), "{reason}");
        assert!(reason.contains("devnet"), "the refusal lists what is known: {reason}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Nothing configured is a wait, not a failure: the membership module's
    /// provisioning abandons a registry for good on `failed`, and the registry
    /// id it is about to send can still name the network.
    #[test]
    fn plan_with_nothing_configured_awaits_selection() {
        let home = temp_home("plan-await");
        assert_eq!(plan_home(&home, &env("", "")), Plan::AwaitSelection);
        let mut sel = selector(Selection::Unresolved);
        assert_eq!(apply_plan(&mut sel, home.clone(), Plan::AwaitSelection), Action::Await);
        assert!(matches!(sel.selection, Selection::Awaiting(_)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_sequencer_labelled_with_a_network_writes_the_marker() {
        let home = temp_home("env-marker");
        let mut sel = selector(Selection::Unresolved);
        let plan = plan_home(&home, &env("http://seq/", "devnet"));
        assert_eq!(apply_plan(&mut sel, home.clone(), plan), Action::Start(home.clone()));
        assert_eq!(
            std::fs::read_to_string(home.join(CONFIG_FILE)).unwrap(),
            wallet_config_json("http://seq/")
        );
        assert_eq!(
            read_marker(&home).unwrap(),
            Some(Binding::Recorded { network: "devnet".into(), source: Source::Env })
        );
        let (reply, _) = select_network(&mut sel, "devnet");
        assert!(reply.accepted);
        assert_eq!(reply.source, "env");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn use_network_before_the_home_is_known_asks_to_retry() {
        let mut sel = selector(Selection::Unresolved);
        let (reply, action) = select_network(&mut sel, "devnet");
        assert!(!reply.accepted && reply.retry, "{reply:?}");
        assert_eq!(action, Action::None);
        assert!(reply.to_json().contains(r#""retry":true"#));
    }

    #[test]
    fn use_network_binds_an_unconfigured_home_from_the_table() {
        let home = temp_home("select-bind");
        let mut sel = selector(Selection::Awaiting(home.clone()));
        let (reply, action) = select_network(&mut sel, " DevNet ");
        assert_eq!(
            reply,
            NetworkReply {
                accepted: true,
                detail: String::new(),
                network: "devnet".into(),
                retry: false,
                source: "table",
            }
        );
        assert_eq!(action, Action::Start(home.clone()));
        assert_eq!(
            std::fs::read_to_string(home.join(CONFIG_FILE)).unwrap(),
            wallet_config_json(&devnet_sequencer())
        );
        assert_eq!(
            read_marker(&home).unwrap(),
            Some(Binding::Recorded { network: "devnet".into(), source: Source::Table })
        );
        // Bound now: a repeat is accepted and starts nothing new.
        let (again, action) = select_network(&mut sel, "devnet");
        assert!(again.accepted);
        assert_eq!(action, Action::None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_unknown_network_is_refused_and_writes_nothing() {
        let home = temp_home("select-unknown");
        let mut sel = selector(Selection::Awaiting(home.clone()));
        let (reply, action) = select_network(&mut sel, "nosuch");
        assert!(!reply.accepted && !reply.retry, "{reply:?}");
        assert!(reply.detail.contains("unknown network 'nosuch' (known: devnet"), "{}", reply.detail);
        assert!(reply.detail.contains("LEZ_RLN_SEQUENCER or LEE_WALLET_HOME_DIR"));
        assert_eq!(action, Action::None);
        assert!(!home.join(CONFIG_FILE).exists());
        assert!(!home.join(NETWORK_FILE).exists());
        assert!(matches!(sel.selection, Selection::Awaiting(_)), "still selectable");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_home_bound_to_devnet_refuses_testnet() {
        let home = temp_home("select-refuse");
        let mut sel = selector(Selection::Awaiting(home.clone()));
        assert!(select_network(&mut sel, "devnet").0.accepted);
        let (reply, _) = select_network(&mut sel, "testnet");
        assert!(!reply.accepted && !reply.retry);
        assert_eq!(reply.network, "devnet");
        assert!(
            reply.detail.contains("is bound to network devnet; refusing to re-point it to testnet"),
            "{}",
            reply.detail
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_operator_home_accepts_any_network() {
        let home = temp_home("select-operator");
        let mut sel = selector(Selection::Bound { home: home.clone(), binding: Binding::Operator });
        for reference in ["devnet", "testnet", "anything"] {
            let (reply, action) = select_network(&mut sel, reference);
            assert!(reply.accepted, "{reference}: {reply:?}");
            assert_eq!(reply.source, "operator");
            assert_eq!(reply.network, reference);
            assert_eq!(action, Action::None);
        }
        assert!(sel.operator_noted);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A home configured after bring-up looked (a staged home dropped in) is
    /// adopted byte for byte; use_network never overwrites a config.
    #[test]
    fn an_existing_config_is_left_byte_identical() {
        let home = temp_home("select-keep");
        let staged = r#"{"sequencer_addr":"http://staged/","custom":true}"#;
        std::fs::write(home.join(CONFIG_FILE), staged).unwrap();
        let mut sel = selector(Selection::Awaiting(home.clone()));
        let (reply, action) = select_network(&mut sel, "devnet");
        assert!(reply.accepted);
        assert_eq!(reply.source, "operator");
        assert_eq!(action, Action::Start(home.clone()));
        assert_eq!(std::fs::read_to_string(home.join(CONFIG_FILE)).unwrap(), staged);
        assert!(!home.join(NETWORK_FILE).exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_failed_home_refuses_without_retry() {
        let mut sel = selector(Selection::Failed("no home".into()));
        let (reply, _) = select_network(&mut sel, "devnet");
        assert!(!reply.accepted && !reply.retry);
        assert!(reply.detail.contains("no home"));
    }

    #[test]
    fn the_sequencer_is_read_from_either_config_shape() {
        let seq = devnet_sequencer();
        assert_eq!(sequencer_of_config(&wallet_config_json(&seq)), Some(seq.clone()));
        // A flat-only config (the rc6-era shape) still names it.
        let flat = serde_json::json!({ "sequencer_addr": seq }).to_string();
        assert_eq!(sequencer_of_config(&flat), Some(seq));
        assert_eq!(sequencer_of_config(r#"{"sequencers":[]}"#), None);
        assert_eq!(sequencer_of_config(r#"{"sequencer_addr":" "}"#), None);
        assert_eq!(sequencer_of_config("not json"), None);
    }

    #[test]
    fn status_carries_the_network_field() {
        let s = status_json();
        assert!(s.contains(r#""network":"#), "got {s}");
    }

    #[test]
    fn a_malformed_program_id_is_refused_before_any_call() {
        let out = send_generic_public_transaction(
            &[mention(&"ab".repeat(32), &"00".repeat(32))],
            &[1, 2, 3],
            "not-hex",
            "",
        );
        assert_eq!(out, "");
    }

    // ------------------------------------------------------------ lez_core

    /// An in-memory `lez_core`: one wallet, opened or not, with accounts and
    /// balances. `open_on` set means another consumer opened it first.
    #[derive(Default)]
    struct FakeCore {
        open_on: Mutex<Option<String>>,
        /// `open` / `create_new` refuse even with nothing open (a real failure).
        broken: bool,
        /// (hex, public, balance; None = unreadable)
        accounts: Mutex<Vec<(String, bool, Option<u128>)>>,
        down: bool,
    }

    fn acct(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    impl FakeCore {
        fn with(accounts: &[(String, bool, Option<u128>)]) -> Self {
            Self { accounts: Mutex::new(accounts.to_vec()), ..Self::default() }
        }
        fn up(&self) -> Result<(), String> {
            if self.down { Err("lez_core is not loaded".to_owned()) } else { Ok(()) }
        }
    }

    impl Core for FakeCore {
        fn wallet_dir(&self) -> Result<String, String> {
            self.up().map(|_| "/var/lib/lez_core".to_owned())
        }
        fn open(&self, _c: &str, _s: &str) -> Result<i64, String> {
            self.up()?;
            let mut open = lock(&self.open_on);
            if open.is_some() || self.broken {
                return Ok(99);
            }
            *open = Some("http://ours/".to_owned());
            Ok(0)
        }
        fn create_new(&self, c: &str, s: &str, _p: &str) -> Result<String, String> {
            Ok(if self.open(c, s)? == 0 { "word ".repeat(12) } else { String::new() })
        }
        fn save(&self) -> Result<i64, String> {
            self.up().map(|_| 0)
        }
        fn list_accounts(&self) -> Result<serde_json::Value, String> {
            self.up()?;
            Ok(lock(&self.accounts)
                .iter()
                .map(|(id, public, _)| serde_json::json!({ "account_id": id, "is_public": public }))
                .collect())
        }
        fn create_account_public(&self) -> Result<String, String> {
            self.up()?;
            let id = acct(0xee);
            lock(&self.accounts).push((id.clone(), true, Some(0)));
            Ok(id)
        }
        fn get_balance(&self, id: &str, _public: bool) -> Result<String, String> {
            self.up()?;
            Ok(lock(&self.accounts)
                .iter()
                .find(|(a, _, _)| a == id)
                .and_then(|(_, _, b)| *b)
                .map(|b| b.to_string())
                .unwrap_or_default())
        }
        fn get_account_public(&self, _id: &str) -> Result<String, String> {
            self.up().map(|_| String::new())
        }
        fn send_generic_public_transaction(&self, tx: &GenericTx) -> Result<String, String> {
            self.up()?;
            let _ = tx;
            Ok(r#"{"success":true,"tx_hash":"abc","secrets":[],"error":""}"#.to_owned())
        }
        fn get_sequencer_addr(&self) -> Result<String, String> {
            self.up()?;
            Ok(lock(&self.open_on).clone().unwrap_or_default())
        }
    }

    fn home_with_config(tag: &str, sequencer: Option<&str>) -> PathBuf {
        let home = temp_home(tag);
        if let Some(seq) = sequencer {
            std::fs::write(home.join(CONFIG_FILE), wallet_config_json(seq)).unwrap();
        }
        home
    }

    #[test]
    fn a_fresh_home_is_created_and_an_existing_one_opened() {
        let home = home_with_config("open-fresh", Some("http://ours/"));
        let core = FakeCore::default();
        let (c, s) = (home.join(CONFIG_FILE), home.join(STORAGE_FILE));
        assert_eq!(open_or_adopt(&core, &c, &s), Ok(Opened::Ours), "no storage: create_new");

        std::fs::write(&s, "{}").unwrap();
        let core = FakeCore::default();
        assert_eq!(open_or_adopt(&core, &c, &s), Ok(Opened::Ours), "storage: open");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `lez_core` holds one wallet per host. One already open on this
    /// registry's chain is used as it stands; trailing slash and case do not
    /// make it another chain.
    #[test]
    fn a_wallet_another_consumer_opened_on_our_chain_is_adopted() {
        let home = home_with_config("open-adopt", Some("https://Testnet.lez.logos.co"));
        let core = FakeCore::default();
        *lock(&core.open_on) = Some("https://testnet.lez.logos.co/".to_owned());
        assert_eq!(
            open_or_adopt(&core, &home.join(CONFIG_FILE), &home.join(STORAGE_FILE)),
            Ok(Opened::Adopted("https://testnet.lez.logos.co/".to_owned()))
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_wallet_open_on_another_chain_is_final() {
        let home = home_with_config("open-other", Some("https://testnet.lez.logos.co/"));
        let core = FakeCore::default();
        *lock(&core.open_on) = Some("http://devnet:3140/".to_owned());
        let Err(OpenError::Fatal(reason)) =
            open_or_adopt(&core, &home.join(CONFIG_FILE), &home.join(STORAGE_FILE))
        else {
            panic!("another chain must be refused for good");
        };
        assert!(reason.contains("http://devnet:3140/"), "{reason}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A refusal with no wallet open is a failed open (the sequencer did not
    /// answer the client's calibration, say): worth retrying, not final.
    #[test]
    fn a_failed_open_with_nothing_open_is_retried() {
        let home = home_with_config("open-broken", Some("http://ours/"));
        let core = FakeCore { broken: true, ..FakeCore::default() };
        assert!(matches!(
            open_or_adopt(&core, &home.join(CONFIG_FILE), &home.join(STORAGE_FILE)),
            Err(OpenError::Retry(_))
        ));
        let down = FakeCore { down: true, ..FakeCore::default() };
        assert!(matches!(
            open_or_adopt(&down, &home.join(CONFIG_FILE), &home.join(STORAGE_FILE)),
            Err(OpenError::Retry(_))
        ));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_wallet_dir_answer_becomes_the_home() {
        assert_eq!(home_of_wallet_dir("/var/lib/lez_core"), Ok(PathBuf::from("/var/lib/lez_core")));
        assert!(home_of_wallet_dir("-").is_err(), "LEZ_NO_WALLET_DIR");
        assert!(home_of_wallet_dir("").is_err());
    }

    #[test]
    fn the_best_funded_account_pays() {
        let core = FakeCore::with(&[
            (acct(1), true, Some(5)),
            (acct(2), false, Some(1_000)), // private: never a payer
            (acct(3), true, Some(70)),
            (acct(4), true, None), // unreadable: skipped
        ]);
        assert_eq!(
            pick_payer(&core, "", &acct(1)),
            Ok(PayerPick { account: acct(3), record: false })
        );
    }

    #[test]
    fn with_nothing_funded_the_published_account_stays_put() {
        let core = FakeCore::with(&[(acct(1), true, Some(0)), (acct(2), true, Some(0))]);
        assert_eq!(
            pick_payer(&core, "", &acct(2)),
            Ok(PayerPick { account: acct(2), record: false }),
            "the recorded account keeps being the one to fund"
        );
        assert_eq!(
            pick_payer(&core, "", ""),
            Ok(PayerPick { account: acct(1), record: true }),
            "no record: the first account, written down"
        );
        assert_eq!(
            pick_payer(&core, "", &acct(9)),
            Ok(PayerPick { account: acct(1), record: true }),
            "a record from another wallet is ignored"
        );
    }

    #[test]
    fn an_empty_wallet_gets_an_account_to_fund() {
        let core = FakeCore::default();
        assert_eq!(
            pick_payer(&core, "", ""),
            Ok(PayerPick { account: acct(0xee), record: true })
        );
        assert_eq!(lock(&core.accounts).len(), 1);
    }

    #[test]
    fn a_configured_payer_must_be_in_the_wallet() {
        let core = FakeCore::with(&[(acct(1), true, Some(0)), (acct(3), true, Some(70))]);
        assert_eq!(
            pick_payer(&core, &acct(1), ""),
            Ok(PayerPick { account: acct(1), record: false }),
            "LEZ_RLN_PAYER wins even unfunded"
        );
        assert!(matches!(pick_payer(&core, &acct(7), ""), Err(PayerError::Fatal(_))));
        let down = FakeCore { down: true, ..FakeCore::default() };
        assert!(matches!(pick_payer(&down, "", ""), Err(PayerError::Retry(_))));
    }

    #[test]
    fn a_list_that_crosses_as_text_still_parses() {
        struct TextList;
        impl Core for TextList {
            fn wallet_dir(&self) -> Result<String, String> { unreachable!() }
            fn open(&self, _: &str, _: &str) -> Result<i64, String> { unreachable!() }
            fn create_new(&self, _: &str, _: &str, _: &str) -> Result<String, String> { unreachable!() }
            fn save(&self) -> Result<i64, String> { unreachable!() }
            fn list_accounts(&self) -> Result<serde_json::Value, String> {
                Ok(serde_json::Value::String(format!(
                    r#"[{{"account_id":"{}","is_public":true}}]"#,
                    acct(5).to_uppercase()
                )))
            }
            fn create_account_public(&self) -> Result<String, String> { unreachable!() }
            fn get_balance(&self, _: &str, _: bool) -> Result<String, String> { unreachable!() }
            fn get_account_public(&self, _: &str) -> Result<String, String> { unreachable!() }
            fn send_generic_public_transaction(&self, _: &GenericTx) -> Result<String, String> { unreachable!() }
            fn get_sequencer_addr(&self) -> Result<String, String> { unreachable!() }
        }
        assert_eq!(public_accounts(&TextList), Ok(vec![acct(5)]));
    }

    /// `lez_core` answers `{nonce: <16 LE bytes hex>, shards: [{program,
    /// data}]}`; `fetch_shards` reads `{nonce: <decimal>, shards: {program:
    /// data}}`.
    #[test]
    fn lez_core_account_replies_are_reshaped_for_the_registry_reads() {
        let raw = serde_json::json!({
            "nonce": "05010000000000000000000000000000",
            "shards": [
                { "program": "AB".repeat(32), "data": "0A0B" },
                { "program": "00".repeat(32), "data": "" },
            ],
        })
        .to_string();
        let out: serde_json::Value =
            serde_json::from_str(&account_json_from_core(&raw).unwrap()).unwrap();
        assert_eq!(out["nonce"], "261");
        assert_eq!(out["shards"]["ab".repeat(32)], "0a0b");
        assert_eq!(out["shards"]["00".repeat(32)], "");
        assert_eq!(account_json_from_core(""), None, "lez_core's failure value");
        assert_eq!(account_json_from_core(r#"{"nonce":"05","shards":[]}"#), None);
    }

    #[test]
    fn a_send_becomes_parallel_arrays_and_bytes() {
        let mentions = [
            Mention { account_hex: "AA".repeat(32), signs: true, shard_program_hex: "00".repeat(32) },
            Mention { account_hex: "bb".repeat(32), signs: false, shard_program_hex: "cd".repeat(32) },
        ];
        let tx = generic_tx(&mentions, &[1, 2, 3], &"EF".repeat(32), "").unwrap();
        assert_eq!(
            tx,
            GenericTx {
                account_ids: vec!["aa".repeat(32), "bb".repeat(32)],
                signing_requirements: vec![true, false],
                instruction: vec![1, 2, 3],
                program_id_hex: "ef".repeat(32),
                payer_account_id_hex: String::new(),
                shard_program_account_ids_hex: vec!["00".repeat(32), "cd".repeat(32)],
            }
        );
        assert!(generic_tx(&mentions, &[], &"ef".repeat(32), "nope").is_err(), "bad payer");
    }

    #[test]
    fn a_send_reply_keeps_the_module_shape() {
        let ok: serde_json::Value = serde_json::from_str(&send_reply_from_core(
            r#"{"success":true,"tx_hash":"abc","secrets":[],"error":""}"#,
        ))
        .unwrap();
        assert_eq!(ok, serde_json::json!({ "error": "", "success": true, "tx_hash": "abc" }));
        let refused: serde_json::Value = serde_json::from_str(&send_reply_from_core(
            r#"{"success":false,"tx_hash":"","error":"send_generic_public_transaction: wallet FFI error 18"}"#,
        ))
        .unwrap();
        assert_eq!(refused["success"], false);
        assert!(refused["error"].as_str().unwrap().contains("error 18"));
        assert_eq!(send_reply_from_core(""), "");
    }

    /// The config this module writes leaves the gas limit to the wallet's
    /// default (2M), which covers every call the program has.
    #[test]
    fn the_written_config_declares_no_gas_limit() {
        let config: serde_json::Value =
            serde_json::from_str(&wallet_config_json("http://seq/")).unwrap();
        assert!(config.get("gas_limit").is_none(), "{config}");
    }
}
