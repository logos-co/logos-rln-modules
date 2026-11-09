//! The wallet this module owns.
//!
//! It cannot share `lez_core`'s wallet: that module holds exactly one wallet
//! handle per host, so whichever app opened first owns it, and the gas limit a
//! transaction declares comes from the wallet's config. A registration costs
//! ~9.1M cycles against a stock default of 2,000,000, and `lez_core` exposes no
//! way to read the limit back; a wallet opened with the stock config refuses
//! every registration with a bare "Incorrect fee".
//!
//! So this module links LEZ's `core_ffi` itself and holds a handle of its own.
//! That is the same prebuilt library `lez_core` links, resolved through
//! `externalLibInputs` from the LEZ flake — deliberately not the `wallet`
//! crate compiled here. Compiling it needs a prebuilt rapidsnark, the circuits
//! tree, a pre-fetched risc0 recursion archive and, on macOS, a Metal
//! toolchain stub and an unsandboxed build; the LEZ flake supplies all of that
//! and a module flake cannot.
//!
//! The symbols below resolve at the final plugin link, the way the SDK's `lp_*`
//! calls already do, so `cargo test` links them against the stub at the bottom
//! of this file instead.
//!
//! The storage file is opened with `LEE_WALLET_PASSWORD` (unset or empty: a
//! plaintext storage, which is what every tool in this stack writes). A
//! password that does not open the storage is terminal, not an outage.
//!
//! What the wallet cannot do is pay its own way. A fee is reserved from a
//! *native* balance; the payer must sign, so the wallet has to hold its key;
//! and native balance enters an account only at genesis, over the L1 bridge,
//! or by transfer from something already funded. A wallet created here can
//! sign but never pay, so a funded key has to be handed in —
//! `LEZ_RLN_PAYER_KEY` — and `LEZ_RLN_PAYER` names which account to declare.
//!
//! Which chain a home talks to is decided once, by `plan_home` at
//! `on_context_ready` or, when nothing configured one, by the first
//! `use_network` — the membership module calls it with the reference of its
//! first registry id, looked up in the built-in table (`networks.rs`). The
//! choice is recorded in the home's `network.json`, and a home is never
//! re-pointed afterwards.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::lock;
use crate::networks;
use crate::rln_core::bytes_to_hex;

/// An existing wallet home to adopt instead of provisioning one under the
/// module's persistence dir. This is the variable the LEZ wallet itself reads
/// and the one the e2e harness and Basecamp already export, so a home staged
/// by `tools/deployments/stage.sh` — config, storage and the payer's
/// derivation together — is adopted whole with no extra configuration.
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

/// Which network a home was provisioned for, `{"network":s,"source":s}`,
/// written beside the config whenever the network is known by name. A home
/// without one was configured by its operator and is not checked.
const NETWORK_FILE: &str = "network.json";

/// What `wallet_status` says while nothing has told this module which chain
/// to use.
const AWAIT_DETAIL: &str = "no network selected — no wallet_config.json, LEZ_RLN_SEQUENCER \
     unset; liblogos_rln_module.start selects one from its registry ids";

/// A funded account's private key as 32-byte hex, imported so the wallet can
/// sign as the fee payer. Not needed when the adopted home already holds a
/// funded account — a staged deployment wallet does.
const PAYER_KEY_ENV: &str = "LEZ_RLN_PAYER_KEY";

/// The password the storage file was written with — the variable the LEZ
/// wallet itself reads. Unset or empty opens a plaintext storage.
const PASSWORD_ENV: &str = "LEE_WALLET_PASSWORD";

/// Where a payer this module derived for itself is recorded, inside the wallet
/// home. Derivation is deterministic from the seed, so re-deriving would hand
/// back the same account — but only while nothing else has consumed a slot.
/// Writing the id down makes the payer survive that, and makes it answerable
/// before the first chain read.
const PAYER_FILE: &str = "payer.json";

/// How long a handler waits for bring-up before giving up. Consumers already
/// retry a failed read; blocking a dispatch thread for a whole first sync
/// would wedge the module under `concurrency:"multi"`.
const READY_WAIT: Duration = Duration::from_secs(30);

/// The wallet's execution gas limit, for a home we provision. Gas is cycles and
/// a registration costs ~9.1M, so the wallet's own 2,000,000
/// default refuses one outright. This is the per-transaction ceiling the
/// sequencer allows; unused gas is refunded, so a cheaper call still pays less.
pub(crate) const GAS_LIMIT: u64 = 10_000_000;

#[allow(unsafe_code)]
mod ffi {
    //! Declarations for LEZ's `core_ffi` library, mirrored field
    //! for field from `core_ffi.h`. `#[allow(unsafe_code)]` is scoped to this
    //! module, as it is for the generated scaffold and the lp test transport:
    //! the crate keeps `deny(unsafe_code)` everywhere else.
    use std::ffi::{c_char, c_void};

    pub type WalletHandle = c_void;

    /// The `FfiOperationError` values this module branches on.
    pub const SUCCESS: i32 = 0;
    pub const WALLET_NOT_INITIALIZED: i32 = 5;
    pub const NETWORK_ERROR: i32 = 8;
    pub const ACCOUNT_NOT_FOUND: i32 = 10;
    pub const KEY_NOT_FOUND: i32 = 11;
    pub const INVALID_ACCOUNT_ID: i32 = 13;
    pub const PAYER_CANNOT_FUND: i32 = 21;
    pub const WRONG_PASSWORD: i32 = 25;
    /// The code the test transport answers with.
    #[cfg(test)]
    pub const NO_WALLET: i32 = WALLET_NOT_INITIALIZED;

    /// A code with its `FfiOperationError` name, for a log line.
    pub fn describe(rc: i32) -> String {
        let name = match rc {
            SUCCESS => "success",
            1 => "null pointer",
            2 => "invalid utf-8",
            3 => "invalid argument",
            4 => "sequencer initialization error",
            WALLET_NOT_INITIALIZED => "wallet not initialized",
            6 => "config error",
            7 => "storage error",
            NETWORK_ERROR => "network error",
            9 => "query error",
            ACCOUNT_NOT_FOUND => "account not found",
            KEY_NOT_FOUND => "key not found",
            12 => "insufficient funds",
            INVALID_ACCOUNT_ID => "invalid account id",
            14 => "runtime error",
            15 => "password required",
            16 => "sync error",
            17 => "serialization error",
            PAYER_CANNOT_FUND => "payer cannot fund",
            22 => "not supported",
            23 => "response too big",
            WRONG_PASSWORD => "wrong password",
            99 => "internal error",
            _ => "unlisted",
        };
        format!("code {rc} ({name})")
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Bytes32 {
        pub data: [u8; 32],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct U128 {
        pub data: [u8; 16],
    }

    /// One program's state on an account (`FfiActorState`): an account's data
    /// is kept per program, and the native balance is the native token
    /// program's.
    #[repr(C)]
    pub struct ActorState {
        pub program: Bytes32,
        pub data: *const u8,
        pub data_len: usize,
    }

    #[repr(C)]
    pub struct Account {
        /// This account's actor states, ordered by program address.
        pub actor_states: *const ActorState,
        pub actor_states_len: usize,
        pub nonce: U128,
    }

    impl Default for Account {
        fn default() -> Self {
            Self {
                actor_states: std::ptr::null(),
                actor_states_len: 0,
                nonce: U128::default(),
            }
        }
    }

    /// The `FfiAccountIdentityKind` values this module uses: a public account
    /// that signs, one that does not, and a program-derived one admitted by
    /// its `(program, seed)`. The enum is wider; the private variants never
    /// appear here.
    pub const KIND_PUBLIC: i32 = 0;
    pub const KIND_PUBLIC_NO_SIGN: i32 = 1;
    pub const KIND_PUBLIC_PDA: i32 = 9;

    #[repr(C)]
    pub struct AccountIdentity {
        pub kind: i32,
        pub account_id: Bytes32,
        pub key_path: *mut c_char,
        pub public_key: Bytes32,
        /// For `KIND_PUBLIC_PDA`: the program the account is derived from.
        pub authority: Bytes32,
        /// For `KIND_PUBLIC_PDA`: the seed it is derived with.
        pub seed: Bytes32,
        pub authorization_secret_key: Bytes32,
        pub nullifier_secret_key: Bytes32,
        pub nullifier_public_key: Bytes32,
        pub viewing_public_key: *const u8,
        pub viewing_public_key_len: usize,
    }

    impl AccountIdentity {
        fn blank(kind: i32, account_id: [u8; 32]) -> Self {
            Self {
                kind,
                account_id: Bytes32 { data: account_id },
                key_path: std::ptr::null_mut(),
                public_key: Bytes32::default(),
                authority: Bytes32::default(),
                seed: Bytes32::default(),
                authorization_secret_key: Bytes32::default(),
                nullifier_secret_key: Bytes32::default(),
                nullifier_public_key: Bytes32::default(),
                viewing_public_key: std::ptr::null(),
                viewing_public_key_len: 0,
            }
        }

        /// A keyed public account: `KIND_PUBLIC` or `KIND_PUBLIC_NO_SIGN`.
        pub fn public(account_id: [u8; 32], kind: i32) -> Self {
            Self::blank(kind, account_id)
        }

        /// A program-derived account. `account_id` is the module's own
        /// derivation; the wallet re-derives it from `(program, seed)` and
        /// answers `INVALID_ACCOUNT_ID` if the two disagree.
        pub fn public_pda(program: [u8; 32], seed: [u8; 32], account_id: [u8; 32]) -> Self {
            let mut identity = Self::blank(KIND_PUBLIC_PDA, account_id);
            identity.authority = Bytes32 { data: program };
            identity.seed = Bytes32 { data: seed };
            identity
        }
    }

    /// An account identity with the program actor state a transaction selects
    /// on it, and whether the account authorizes (signs) the transaction.
    #[repr(C)]
    pub struct AccountMention {
        pub identity: AccountIdentity,
        pub program_account_id: Bytes32,
        pub authorizes: bool,
        pub address_openings: *const Bytes32,
        pub address_openings_size: usize,
    }

    #[repr(C)]
    pub struct TransactionResult {
        pub tx_hash: *mut c_char,
        pub success: bool,
        pub secrets_data: *const Bytes32,
        pub secrets_size: usize,
    }

    impl Default for TransactionResult {
        fn default() -> Self {
            Self {
                tx_hash: std::ptr::null_mut(),
                success: false,
                secrets_data: std::ptr::null(),
                secrets_size: 0,
            }
        }
    }

    #[repr(C)]
    pub struct CreateWalletOutput {
        pub wallet: *mut WalletHandle,
        pub mnemonic: *mut c_char,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PublicAccountKey {
        pub public_key: Bytes32,
    }

    extern "C" {
        /// `sequencer` is null: the client is built from the config's
        /// sequencer address.
        pub fn wallet_ffi_open(
            config_path: *const c_char,
            storage_path: *const c_char,
            sequencer: *const c_void,
            password: *const c_char,
            out_handle: *mut *mut WalletHandle,
        ) -> i32;

        pub fn wallet_ffi_create_new(
            config_path: *const c_char,
            storage_path: *const c_char,
            password: *const c_char,
            sequencer: *const c_void,
        ) -> CreateWalletOutput;

        pub fn wallet_ffi_save(handle: *mut WalletHandle) -> i32;

        pub fn wallet_ffi_import_public_account(
            handle: *mut WalletHandle,
            private_key_hex: *const c_char,
        ) -> i32;

        pub fn wallet_ffi_create_account_public(
            handle: *mut WalletHandle,
            out_account_id: *mut Bytes32,
        ) -> i32;

        pub fn wallet_ffi_get_account_public(
            handle: *mut WalletHandle,
            account_id: *const Bytes32,
            out_account: *mut Account,
        ) -> i32;

        pub fn wallet_ffi_free_account_data(account: *mut Account);

        pub fn wallet_ffi_get_balance(
            handle: *mut WalletHandle,
            account_id: *const Bytes32,
            is_public: bool,
            out_balance: *mut [u8; 16],
        ) -> i32;

        pub fn wallet_ffi_get_public_account_key(
            handle: *mut WalletHandle,
            account_id: *const Bytes32,
            out_public_key: *mut PublicAccountKey,
        ) -> i32;

        pub fn wallet_ffi_send_generic_public_transaction(
            handle: *mut WalletHandle,
            account_mentions: *const AccountMention,
            account_mentions_size: usize,
            root_mention: usize,
            message: *const u8,
            message_size: usize,
            payer: *const Bytes32,
            out_result: *mut TransactionResult,
        ) -> i32;

        pub fn wallet_ffi_free_transaction_result(result: *mut TransactionResult);

        pub fn wallet_ffi_sync_to_block(handle: *mut WalletHandle, block_id: u64) -> i32;

        pub fn wallet_ffi_get_current_block_height(
            handle: *mut WalletHandle,
            out_block_height: *mut u64,
        ) -> i32;

        pub fn primitives_ffi_free_cstring(block: *mut c_char);
    }
}

#[allow(unsafe_code)]
mod handle {
    /// The opaque wallet pointer.
    ///
    /// `wallet_ffi` locks the wallet inside every entry point, so the pointer
    /// is safe to share between threads; the `RwLock` around it is about *our*
    /// sequencing (a derivation must not overlap a read), not its.
    pub struct Handle(pub *mut super::ffi::WalletHandle);

    // SAFETY: the pointer is opaque — this crate never dereferences it — and
    // every library entry point takes the wallet's own lock before use.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}
}
use handle::Handle;

pub(crate) enum Readiness {
    /// Bring-up has not finished: still opening, importing or syncing. The
    /// string says what it is waiting on, for a human reading `wallet_status`;
    /// empty until bring-up has something more specific to report.
    Pending(String),
    /// Open and caught up to the head it last observed.
    Ready,
    /// Bring-up gave up; the string is the reason, already logged.
    Failed(String),
}

struct State {
    readiness: Readiness,
    /// The account this module signs and pays with: `LEZ_RLN_PAYER`, the
    /// account `LEZ_RLN_PAYER_KEY` imported, or one derived at bring-up.
    /// Empty until bring-up settles.
    payer_hex: String,
    /// The payer's public key as 64 hex chars, read once at bring-up; "" when
    /// the wallet holds no key for it. Published because genesis funding and
    /// the first transfer into a fresh account go by public key.
    payer_public_key: String,
    /// Shared for reads and sends, exclusive for deriving an account. Callers
    /// clone the `Arc` and drop the state lock before calling: holding it
    /// across a sequencer round trip would serialize every handler.
    wallet: Option<Arc<RwLock<Handle>>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    readiness: Readiness::Pending(String::new()),
    payer_hex: String::new(),
    payer_public_key: String::new(),
    wallet: None,
});

/// Held across a submission and nothing else.
///
/// A transaction's nonce is read from confirmed on-chain state, not from a
/// local counter, and it only advances once the transaction settles. Two
/// submissions from one account that overlap that window therefore build with
/// the same nonce and one is dropped. The signer is the payer, so this is the
/// ordinary case.
///
/// `REG_IN_FLIGHT` does not cover this — it keys on the membership PDA, so
/// two DIFFERENT memberships still race. Reads are deliberately outside: the
/// `single` -> `multi` bump exists to keep them concurrent.
static SEND_LOCK: Mutex<()> = Mutex::new(());

/// Signalled once bring-up settles, either way.
static SETTLED: Condvar = Condvar::new();

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
/// a failure: the consumer's registry id can still name
/// the network.
pub(crate) fn plan_home(home: &Path, env: EnvView) -> Plan {
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
            Binding::Recorded {
                network: env.network,
                source: Source::Env,
            }
        };
        return Plan::Provision {
            sequencer: env.sequencer,
            binding,
        };
    }
    if !env.network.is_empty() {
        return match networks::network(&env.network) {
            Some(n) => Plan::Provision {
                sequencer: n.sequencer.clone(),
                binding: Binding::Recorded {
                    network: n.reference.clone(),
                    source: Source::Table,
                },
            },
            None => Plan::Failed(format!("{NETWORK_ENV}: {}", unknown_network(&env.network))),
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
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let network = doc
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let source = match doc.get("source").and_then(|v| v.as_str()) {
        Some("table") => Source::Table,
        Some("env") => Source::Env,
        other => return Err(format!("{}: unknown source {other:?}", path.display())),
    };
    if network.is_empty() {
        return Err(format!("{} names no network", path.display()));
    }
    Ok(Some(Binding::Recorded {
        network: network.to_owned(),
        source,
    }))
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
        Action::Fail(reason) => fail(reason),
    }
}

/// Record a plan's outcome and say what to do about it.
fn apply_plan(sel: &mut Selector, home: PathBuf, plan: Plan) -> Action {
    match plan {
        Plan::Adopt(binding) => {
            log_binding("adopting", &home, &binding);
            sel.selection = Selection::Bound {
                home: home.clone(),
                binding,
            };
            Action::Start(home)
        }
        Plan::Provision { sequencer, binding } => {
            if let Err(e) = provision_home(&home, &sequencer, &binding) {
                sel.selection = Selection::Failed(e.clone());
                return Action::Fail(e);
            }
            log_binding(&format!("provisioned for {sequencer}"), &home, &binding);
            sel.selection = Selection::Bound {
                home: home.clone(),
                binding,
            };
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
        Binding::Operator => eprintln!(
            "lez-rln wallet: {what} {} (operator-configured)",
            home.display()
        ),
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
        Self {
            accepted: false,
            detail,
            network: network.to_owned(),
            retry: false,
            source: "",
        }
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
            return (
                answer_bound(home, binding, &reference, &mut sel.operator_noted),
                Action::None,
            )
        }
        Selection::Awaiting(home) => home.clone(),
    };

    // Re-checked under the lock: a home someone configured since bring-up
    // looked is adopted as it stands, never overwritten.
    if home.join(CONFIG_FILE).exists() {
        let action = apply_plan(
            sel,
            home.clone(),
            plan_home(
                &home,
                EnvView {
                    sequencer: String::new(),
                    network: String::new(),
                },
            ),
        );
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
        return (
            NetworkReply::refused(unknown_network(&reference), ""),
            Action::None,
        );
    };
    let binding = Binding::Recorded {
        network: network.reference.clone(),
        source: Source::Table,
    };
    let action = apply_plan(
        sel,
        home,
        Plan::Provision {
            sequencer: network.sequencer.clone(),
            binding,
        },
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
        Selection::Bound {
            binding: Binding::Recorded { network, .. },
            ..
        } => Some(network.clone()),
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
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| eprintln!("lez-rln wallet: read {}: {e}", path.display()))
        .ok()?;
    sequencer_of_config(&raw)
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

/// Resolve the wallet home and decide what it needs. Called from
/// `on_context_ready`, which runs on the host's Qt main thread — so the only
/// work done here is a few small file writes; opening a wallet calibrates
/// sequencers and then syncs the chain, and that runs on its own thread.
pub(crate) fn spawn_bring_up(persistence_path: &str) {
    let mut sel = lock(&SELECTION);
    if !matches!(sel.selection, Selection::Unresolved) {
        eprintln!("lez-rln wallet: bring-up already resolved, ignoring the repeat");
        return;
    }
    let home = match std::env::var(HOME_ENV) {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir.trim()),
        _ => {
            if persistence_path.is_empty() {
                let reason = format!(
                    "no instance_persistence_path from the host and no {HOME_ENV} — the wallet \
                     has nowhere to live"
                );
                // OWNERSHIP: two owners — the selection and the readiness each keep the reason.
                sel.selection = Selection::Failed(reason.clone());
                fail(reason);
                return;
            }
            PathBuf::from(persistence_path).join("wallet-home")
        }
    };
    let plan = plan_home(&home, EnvView::from_env());
    let action = apply_plan(&mut sel, home, plan);
    perform(action);
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
            fail(format!("cannot spawn the wallet bring-up thread: {e}"));
        });
}

/// Guards `spawn_bring_up` against a second entry; see there.
static BRINGUP_STARTED: AtomicBool = AtomicBool::new(false);

fn fail(reason: String) {
    eprintln!("lez-rln wallet: {reason}");
    let mut state = lock(&STATE);
    state.readiness = Readiness::Failed(reason);
    SETTLED.notify_all();
}

/// Say what bring-up is waiting on, without settling it.
///
/// Deliberately does not notify `SETTLED`: nothing has settled, and waking
/// every waiting handler to tell it to keep waiting would only spin them
/// against `READY_WAIT`.
fn pending(detail: impl Into<String>) {
    let mut state = lock(&STATE);
    state.readiness = Readiness::Pending(detail.into());
}

fn bring_up(home: &Path) {
    if let Err(e) = std::fs::create_dir_all(home) {
        fail(format!("create {}: {e}", home.display()));
        return;
    }
    // The config is in place by now: `plan_home` adopted it or wrote it.
    let config_path = home.join(CONFIG_FILE);
    let storage_path = home.join("storage.json");

    let handle = match open_with_retry(&config_path, &storage_path) {
        Ok(h) => h,
        Err(e) => {
            fail(e);
            return;
        }
    };

    if let Err(e) = import_payer_key(&handle) {
        fail(e);
        return;
    }

    let payer_hex = match resolve_payer(&handle, home) {
        Ok(p) => p,
        Err(e) => {
            fail(e);
            return;
        }
    };
    let payer_public_key = public_key_of(&handle, &payer_hex);
    if payer_public_key.is_empty() {
        // A wallet that cannot sign for its payer sends nothing that the
        // sequencer accepts; Ready would promise registrations it cannot make.
        fail(format!(
            "the payer {payer_hex} has no signing key in this wallet"
        ));
        return;
    }

    match sync(&handle) {
        Ok(head) => eprintln!("lez-rln wallet: synced to block {head}"),
        // Account reads go to the sequencer rather than to local state, so a
        // wallet that opened but has not caught up still answers them.
        Err(e) => eprintln!("lez-rln wallet: initial sync incomplete: {e}"),
    }

    let mut state = lock(&STATE);
    state.wallet = Some(Arc::new(RwLock::new(handle)));
    state.payer_hex = payer_hex;
    state.payer_public_key = payer_public_key;
    state.readiness = Readiness::Ready;
    SETTLED.notify_all();
    eprintln!("lez-rln wallet: ready ({})", home.display());
}

/// Open the wallet, retrying for as long as it takes.
///
/// Opening a wallet is a chain read: `wallet_ffi_open` builds the sequencer
/// client, which calibrates every configured endpoint and then drops any it has
/// no statistics for — so on a fresh home an unreachable sequencer leaves the
/// leader list empty and the open fails outright. That is the ordinary shape of
/// a node started while the chain is down. A node that gives up stays broken
/// after the outage ends.
///
/// So there is no attempt limit and no deadline, for the same reason
/// `logos-rln-module`'s funding wait has none: nothing this module can do makes
/// the sequencer answer sooner, and a deadline only converts a recoverable
/// outage into a permanent one. The wallet stays `pending` throughout, which is
/// precisely the answer that tells a consumer to come back — `failed` is
/// reserved for the causes where waiting cannot help, and an unreachable
/// sequencer is not one of them.
///
/// The one open failure that waiting cannot fix is a password that does not
/// open the storage: that is `Err`, and bring-up fails on it. Every other code
/// (a corrupt storage file included) is retried like an unreachable chain:
/// the node is equally unusable under either cause, so the only cost is the
/// word `wallet_status` prints, while the benefit is that the common cause
/// heals itself. The detail string carries the real error either way, and
/// `LATCH_AFTER` makes a persistent failure say so in as many words.
fn open_with_retry(config: &Path, storage: &Path) -> Result<Handle, String> {
    /// Past this much continuous failure, keep retrying but stop implying the
    /// wait is routine: something needs looking at.
    const LATCH_AFTER: Duration = Duration::from_secs(600);

    let start = Instant::now();
    let mut attempt = 0_u64;
    loop {
        attempt += 1;
        match open_or_create(config, storage) {
            Ok(h) => {
                if attempt > 1 {
                    eprintln!(
                        "lez-rln wallet: opened on attempt {attempt} after {}s",
                        start.elapsed().as_secs()
                    );
                }
                return Ok(h);
            }
            Err(OpenError::Fatal(e)) => return Err(e),
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
                // once per attempt: at the 5s cadence a long outage would
                // otherwise bury every other line in the node's log.
                if attempt == 1 || waited >= LATCH_AFTER {
                    eprintln!("lez-rln wallet: {detail}");
                }
                pending(detail);
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

/// Why an open produced no handle: the chain-outage shape (keep trying), or
/// one that waiting will not change.
enum OpenError {
    Retry(String),
    Fatal(String),
}

#[allow(unsafe_code)]
fn open_or_create(config: &Path, storage: &Path) -> Result<Handle, OpenError> {
    let c = cstring(config).map_err(OpenError::Fatal)?;
    let s = cstring(storage).map_err(OpenError::Fatal)?;
    let pw = CString::new(std::env::var(PASSWORD_ENV).unwrap_or_default())
        .map_err(|e| OpenError::Fatal(format!("{PASSWORD_ENV}: {e}")))?;

    if storage.exists() {
        let mut raw: *mut ffi::WalletHandle = std::ptr::null_mut();
        // SAFETY: three valid null-terminated strings alive across the call, a
        // null sequencer (the config names it), and an out-pointer we own.
        let rc = unsafe {
            ffi::wallet_ffi_open(
                c.as_ptr(),
                s.as_ptr(),
                std::ptr::null(),
                pw.as_ptr(),
                &raw mut raw,
            )
        };
        if rc == ffi::WRONG_PASSWORD {
            return Err(OpenError::Fatal(format!(
                "{PASSWORD_ENV} does not open {} — set it to the password the storage was \
                 written with (empty for a plaintext storage)",
                storage.display()
            )));
        }
        if rc != ffi::SUCCESS || raw.is_null() {
            return Err(OpenError::Retry(format!(
                "open {}: {}",
                storage.display(),
                ffi::describe(rc)
            )));
        }
        return Ok(Handle(raw));
    }

    // Loud on purpose. A home staged for a deployment carries the payer's
    // derivation in its storage; creating an empty wallet over a home that was
    // meant to have one registers nothing, and says why only much later and
    // only as a fee refusal.
    eprintln!(
        "lez-rln wallet: no storage at {} — creating an empty wallet",
        storage.display()
    );
    // SAFETY: three valid null-terminated strings alive across the call and a
    // null sequencer.
    let out = unsafe {
        ffi::wallet_ffi_create_new(c.as_ptr(), s.as_ptr(), pw.as_ptr(), std::ptr::null())
    };
    if out.wallet.is_null() {
        return Err(OpenError::Retry(format!(
            "create_new at {} returned no handle",
            storage.display()
        )));
    }
    if !out.mnemonic.is_null() {
        // A recovery phrase is of no use to a module that re-derives
        // everything it holds; freed unread.
        // SAFETY: a string the library handed over, freed exactly once.
        unsafe { ffi::primitives_ffi_free_cstring(out.mnemonic) };
    }
    let handle = Handle(out.wallet);
    // The new wallet lives in memory only until it is saved; the next open
    // must find the storage file.
    save(&handle).map_err(OpenError::Fatal)?;
    Ok(handle)
}

/// The public key behind `payer_hex` as 64 hex chars, or "" when the wallet
/// holds no signing key for it. Loud: such a payer cannot sign, so nothing
/// this module sends would be accepted.
#[allow(unsafe_code)]
fn public_key_of(handle: &Handle, payer_hex: &str) -> String {
    let Some(bytes) = crate::hex::hex_to_bytes32(payer_hex) else {
        return String::new();
    };
    let id = ffi::Bytes32 { data: bytes };
    let mut out = ffi::PublicAccountKey::default();
    // SAFETY: a live handle, an id we own alive across the call, and an out
    // struct we own.
    let rc =
        unsafe { ffi::wallet_ffi_get_public_account_key(handle.0, &raw const id, &raw mut out) };
    if rc != ffi::SUCCESS {
        eprintln!(
            "lez-rln wallet: no signing key for the payer {payer_hex} ({}) — it cannot sign a \
             registration; import its key with {PAYER_KEY_ENV} or adopt the home that holds it",
            ffi::describe(rc)
        );
        return String::new();
    }
    bytes_to_hex(&out.public_key.data)
}

#[allow(unsafe_code)]
fn import_payer_key(handle: &Handle) -> Result<(), String> {
    let Ok(raw) = std::env::var(PAYER_KEY_ENV) else {
        return Ok(());
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    if crate::hex::hex_to_bytes32(raw).is_none() {
        return Err(format!("{PAYER_KEY_ENV} is not 32-byte hex"));
    }
    let key = CString::new(raw).map_err(|e| e.to_string())?;
    // SAFETY: a live handle and a valid null-terminated hex string.
    let rc = unsafe { ffi::wallet_ffi_import_public_account(handle.0, key.as_ptr()) };
    if rc != ffi::SUCCESS {
        return Err(format!(
            "{PAYER_KEY_ENV} import failed ({})",
            ffi::describe(rc)
        ));
    }
    save(handle)?;
    eprintln!("lez-rln wallet: imported the fee payer's key");
    Ok(())
}

/// The account that pays a transaction's fee, as 32-byte hex, or empty to let
/// the wallet charge the signing account.
///
/// The fee is reserved from a *native* balance. A signer with none cannot pay
/// it, and the registration is refused before it runs, with only "Incorrect
/// fee" to say why.
///
/// `LEZ_RLN_PAYER` names a funded account the wallet already holds a key for —
/// the same variable the host tools use. It accepts base58 or hex, since the
/// tooling that mints the payer prints base58 and the wallet interface wants
/// hex. Unset means self-pay, which is right wherever the signing account is
/// itself funded.
/// `LEZ_RLN_PAYER` as 64-hex: `Ok(None)` when unset or blank, `Err` when set to
/// something that is no account id. Read at bring-up to decide the module's
/// payer; `fee_payer_hex` is what every send actually uses.
fn fee_payer_env_hex() -> Result<Option<String>, String> {
    let Ok(raw) = std::env::var("LEZ_RLN_PAYER") else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    crate::hex::canonical_account_hex(raw)
        .map(Some)
        .ok_or_else(|| {
            format!("LEZ_RLN_PAYER is neither 32-byte hex nor a base58 account id: {raw}")
        })
}

/// The account this module signs and pays with, decided once at bring-up.
///
/// Order: `LEZ_RLN_PAYER` if it names one; otherwise the account recorded in
/// `payer.json` from a previous run; otherwise derive one and write it down.
///
/// Deriving is not funding. No program can mint native balance, so a fresh
/// account is worth nothing until someone transfers to it — which is exactly
/// why the id is published (`wallet_status`) rather than kept private: an
/// operator, or the e2e harness, has to be able to send to it.
#[allow(unsafe_code)]
fn resolve_payer(handle: &Handle, home: &Path) -> Result<String, String> {
    if let Some(configured) = fee_payer_env_hex()? {
        eprintln!("lez-rln wallet: paying from the configured account {configured}");
        return Ok(configured);
    }

    let recorded = home.join(PAYER_FILE);
    match std::fs::read_to_string(&recorded) {
        Ok(raw) => {
            let id = raw.trim().trim_matches('"').to_ascii_lowercase();
            if crate::hex::hex_to_bytes32(&id).is_some() {
                eprintln!("lez-rln wallet: paying from {id} (recorded)");
                return Ok(id);
            }
            return Err(format!(
                "{} does not contain a 32-byte hex account id",
                recorded.display()
            ));
        }
        // Only an absent record means "no payer yet": deriving over one that
        // could not be read would replace the account that holds the funds.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read {}: {e}", recorded.display())),
    }

    let mut out = ffi::Bytes32::default();
    // SAFETY: a live handle and an out struct we own.
    let rc = unsafe { ffi::wallet_ffi_create_account_public(handle.0, &raw mut out) };
    if rc != ffi::SUCCESS {
        return Err(format!(
            "deriving a payer account failed ({})",
            ffi::describe(rc)
        ));
    }
    // Derivation alone does not persist; without this the account is gone on
    // the next open and nothing can sign for it.
    save(handle)?;
    let id = bytes_to_hex(&out.data);
    std::fs::write(&recorded, &id).map_err(|e| format!("write {}: {e}", recorded.display()))?;
    eprintln!(
        "lez-rln wallet: derived the payer {id} — it holds nothing until something transfers to it"
    );
    Ok(id)
}

#[allow(unsafe_code)]
fn save(handle: &Handle) -> Result<(), String> {
    // SAFETY: a live handle.
    let rc = unsafe { ffi::wallet_ffi_save(handle.0) };
    if rc != ffi::SUCCESS {
        return Err(format!("saving the wallet failed ({})", ffi::describe(rc)));
    }
    Ok(())
}

/// Catch the wallet up to the head.
///
/// The wallet serves no reads while a sync runs, but during bring-up nothing
/// is being served yet — handlers wait on `SETTLED` — so this takes the whole
/// range in one call.
#[allow(unsafe_code)]
fn sync(handle: &Handle) -> Result<u64, String> {
    let mut head: u64 = 0;
    // SAFETY: a live handle and a valid out-pointer.
    let rc = unsafe { ffi::wallet_ffi_get_current_block_height(handle.0, &raw mut head) };
    if rc != ffi::SUCCESS {
        return Err(format!("chain head unavailable ({})", ffi::describe(rc)));
    }
    // SAFETY: a live handle.
    let rc = unsafe { ffi::wallet_ffi_sync_to_block(handle.0, head) };
    if rc != ffi::SUCCESS {
        return Err(format!("sync to {head} failed ({})", ffi::describe(rc)));
    }
    Ok(head)
}

fn cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.to_string_lossy().as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// The config this module writes for a home it provisions itself. The shape
/// mirrors what `tools/deployments/stage.sh` emits and what the membership
/// module's `provision_wallet_home` writes, so a home staged by either is
/// readable here and vice versa.
fn wallet_config_json(sequencer: &str) -> String {
    serde_json::json!({
        // Every sequencer field shape a wallet version may require (each version
        // requires a different one; none denies unknown fields).
        "sequencer": { "sequencer_addr": sequencer },
        "sequencer_addr": sequencer,
        "sequencers": [{ "sequencer_addr": sequencer }],
        "seq_poll_timeout": "30s",
        "seq_tx_poll_max_blocks": 15,
        "seq_poll_max_retries": 10,
        "seq_block_poll_max_amount": 100,
        "gas_limit": GAS_LIMIT,
        // The default is 100 sequential probes per sequencer, which blocks the
        // open for minutes against a slow chain. One sequencer, 3 probes.
        "multi_sequencer_client_config": { "distribution_limit": 1, "calibration_limit": 3 },
    })
    .to_string()
}

/// The wallet, once bring-up has settled. `None` means unusable, and the
/// caller reports an empty string.
fn wallet(who: &str) -> Option<Arc<RwLock<Handle>>> {
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
    state.wallet.clone()
    // The state lock is released here, before the caller's call runs.
}

/// What a public account read answered.
pub(crate) enum AccountRead {
    /// Every actor state on the account as `(program, bytes)`; the native
    /// balance is the native token program's (`[0; 32]`), a 16-byte LE u128.
    Present(Vec<([u8; 32], Vec<u8>)>),
    /// No such account on the chain. Quiet: a membership before it registers
    /// and a treasury nobody seeded both read this way, and both are answers.
    Absent,
    /// The question could not be answered (no wallet, or the sequencer did
    /// not reply); logged.
    Error,
}

#[allow(unsafe_code)]
pub(crate) fn read_account(account_id: &[u8; 32]) -> AccountRead {
    let Some(wallet) = wallet("read_account") else {
        return AccountRead::Error;
    };
    let guard = wallet.read().unwrap_or_else(|p| p.into_inner());
    let id = ffi::Bytes32 { data: *account_id };
    let mut account = ffi::Account::default();
    // SAFETY: a live handle, a stack id alive across the call, and an out
    // struct we own.
    let rc =
        unsafe { ffi::wallet_ffi_get_account_public(guard.0, &raw const id, &raw mut account) };
    if rc == ffi::ACCOUNT_NOT_FOUND {
        return AccountRead::Absent;
    }
    if rc != ffi::SUCCESS {
        eprintln!(
            "read_account({}): {}",
            bytes_to_hex(account_id),
            ffi::describe(rc)
        );
        return AccountRead::Error;
    }
    // SAFETY: on success the library hands back an actor-state array it owns,
    // valid for `actor_states_len` entries, each pointing at `data_len` bytes,
    // until `wallet_ffi_free_account_data`.
    let states: &[ffi::ActorState] =
        if account.actor_states.is_null() || account.actor_states_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(account.actor_states, account.actor_states_len) }
        };
    let mut out = Vec::with_capacity(states.len());
    for state in states {
        let data: &[u8] = if state.data.is_null() || state.data_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(state.data, state.data_len) }
        };
        out.push((state.program.data, data.to_vec()));
    }
    // SAFETY: the struct the call just filled, freed exactly once.
    unsafe { ffi::wallet_ffi_free_account_data(&raw mut account) };
    AccountRead::Present(out)
}

/// How a mentioned account is admitted, and whether it signs.
pub(crate) enum MentionKind {
    /// Signs the transaction; the wallet must hold its key.
    Signer,
    /// Declared only: it must already exist on the chain.
    NoSign,
    /// A program-derived account written for the first time, admitted by the
    /// `(program, seed)` the wallet re-derives it from.
    Pda { program: [u8; 32], seed: [u8; 32] },
}

/// One account a transaction declares: the account, the program whose actor
/// state on it the transaction touches (`[0; 32]` for the native balance), and
/// how it is admitted.
pub(crate) struct Mention {
    pub(crate) account: [u8; 32],
    pub(crate) program: [u8; 32],
    pub(crate) kind: MentionKind,
}

impl Mention {
    fn to_ffi(&self) -> ffi::AccountMention {
        let identity = match &self.kind {
            MentionKind::Signer => ffi::AccountIdentity::public(self.account, ffi::KIND_PUBLIC),
            MentionKind::NoSign => {
                ffi::AccountIdentity::public(self.account, ffi::KIND_PUBLIC_NO_SIGN)
            }
            MentionKind::Pda { program, seed } => {
                ffi::AccountIdentity::public_pda(*program, *seed, self.account)
            }
        };
        ffi::AccountMention {
            identity,
            program_account_id: ffi::Bytes32 { data: self.program },
            authorizes: matches!(self.kind, MentionKind::Signer),
            address_openings: std::ptr::null(),
            address_openings_size: 0,
        }
    }
}

/// A send failure as the `<kind>: <reason>` string callers match on.
fn send_error(rc: i32) -> String {
    match rc {
        ffi::PAYER_CANNOT_FUND => {
            "insufficient_balance: the payer cannot cover the fee reserve (\"Incorrect fee\")"
                .to_owned()
        }
        ffi::KEY_NOT_FOUND => {
            "no_signing_key: the wallet holds no key for a signing account".to_owned()
        }
        ffi::INVALID_ACCOUNT_ID => {
            "pda_mismatch: a PDA mention's account id is not derived from its program and seed"
                .to_owned()
        }
        ffi::NETWORK_ERROR => "sequencer: the transaction was not accepted".to_owned(),
        other => format!("wallet: {}", ffi::describe(other)),
    }
}

/// What the wallet reports for one send. It answers `success:false` for a
/// send it could not make (no key for the payer, no network, a payer that
/// cannot fund), and nothing was submitted then.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct SendResult {
    error: String,
    success: bool,
    tx_hash: String,
}

impl SendResult {
    /// The result itself when the sequencer accepted the transaction
    /// (`success` and a tx hash); `Err(why)` otherwise.
    pub(crate) fn accepted(self) -> Result<Self, String> {
        if self.success && !self.tx_hash.is_empty() {
            return Ok(self);
        }
        if !self.error.is_empty() {
            return Err(self.error);
        }
        Err(if self.success {
            "no tx_hash in the send reply"
        } else {
            "send failed"
        }
        .to_string())
    }

    pub(crate) fn into_tx_hash(self) -> String {
        self.tx_hash
    }

    /// `{"error","success","tx_hash"}`, keys in that order: `register_member`
    /// hands this text back as its `tx_result`.
    pub(crate) fn to_json(&self) -> String {
        serde_json::to_value(self)
            .map(|v| v.to_string())
            .unwrap_or_default()
    }
}

/// Submit a public transaction: `message` is delivered to the actor
/// `mentions[root]` selects, and every mention is declared, in order. `None`
/// when the arguments are unusable or the wallet is not up (logged).
#[allow(unsafe_code)]
pub(crate) fn send_generic_public_transaction(
    mentions: &[Mention],
    root: usize,
    message: &[u8],
    payer_account_id_hex: &str,
) -> Option<SendResult> {
    if root >= mentions.len() {
        eprintln!(
            "send_generic_public_transaction: root mention {root} is past the {} mentions",
            mentions.len()
        );
        return None;
    }
    let ffi_mentions: Vec<ffi::AccountMention> = mentions.iter().map(Mention::to_ffi).collect();

    // Empty means self-pay.
    let payer = if payer_account_id_hex.trim().is_empty() {
        None
    } else {
        match crate::hex::hex_to_bytes32(payer_account_id_hex) {
            Some(bytes) => Some(ffi::Bytes32 { data: bytes }),
            None => {
                eprintln!(
                    "send_generic_public_transaction: payer {payer_account_id_hex} is not \
                     32-byte hex"
                );
                return None;
            }
        }
    };
    let payer_ptr = payer.as_ref().map_or(std::ptr::null(), std::ptr::from_ref);

    let wallet = wallet("send_generic_public_transaction")?;
    let guard = wallet.read().unwrap_or_else(|p| p.into_inner());
    let mut result = ffi::TransactionResult::default();
    // SAFETY: a live handle; mentions, message and payer all outlive the call;
    // the out struct is ours.
    let rc = unsafe {
        // One submission at a time; see SEND_LOCK.
        let _serialized = lock(&SEND_LOCK);
        ffi::wallet_ffi_send_generic_public_transaction(
            guard.0,
            ffi_mentions.as_ptr(),
            ffi_mentions.len(),
            root,
            message.as_ptr(),
            message.len(),
            payer_ptr,
            &raw mut result,
        )
    };
    if rc != ffi::SUCCESS {
        let error = send_error(rc);
        eprintln!("send_generic_public_transaction failed: {error}");
        // SAFETY: freeing the out struct is the library's contract whether or
        // not the call filled it.
        unsafe { ffi::wallet_ffi_free_transaction_result(&raw mut result) };
        return Some(SendResult {
            error,
            success: false,
            tx_hash: String::new(),
        });
    }
    // SAFETY: on success tx_hash is null or a null-terminated string the
    // library owns until the free below.
    let tx_hash = if result.tx_hash.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(result.tx_hash) }
            .to_string_lossy()
            .into_owned()
    };
    let success = result.success;
    // SAFETY: the struct the call just filled, freed exactly once.
    unsafe { ffi::wallet_ffi_free_transaction_result(&raw mut result) };

    Some(SendResult {
        error: String::new(),
        success,
        tx_hash,
    })
}

/// Derive a fresh public account in this module's own wallet and persist it,
/// returning it as 64 hex chars. Empty string on failure.
///
/// Derivation is deterministic from the wallet's seed, so this hands back the
/// next slot rather than a random one; a caller that needs an account nothing
/// has claimed on-chain yet checks the balance and asks again. It lives here
/// The account this module signs and pays with, or "" before bring-up settles.
pub(crate) fn payer_hex() -> String {
    lock(&STATE).payer_hex.clone()
}

/// Live NATIVE balance of `account_hex`, or of this module's payer when empty.
///
/// `None` means the question could not be answered — the wallet is not up, the
/// id is malformed, or the sequencer did not reply. That is deliberately not
/// zero: a caller deciding whether it can afford to register would read an
/// unreachable chain as "broke" and give up permanently.
#[allow(unsafe_code)]
pub(crate) fn native_balance(account_hex: &str) -> Option<(String, u128)> {
    let id_hex = if account_hex.trim().is_empty() {
        payer_hex()
    } else {
        crate::hex::canonical_account_hex(account_hex)?
    };
    if id_hex.is_empty() {
        eprintln!("native_balance: no account given and no payer resolved yet");
        return None;
    }
    let bytes = crate::hex::hex_to_bytes32(&id_hex)?;
    let wallet = wallet("native_balance")?;
    let guard = wallet.read().unwrap_or_else(|p| p.into_inner());
    let id = ffi::Bytes32 { data: bytes };
    let mut out = [0u8; 16];
    // SAFETY: a live handle, an id we own, and a 16-byte out buffer. is_public
    // is true because a balance a program can charge is a public one.
    let rc = unsafe { ffi::wallet_ffi_get_balance(guard.0, &raw const id, true, &raw mut out) };
    if rc != ffi::SUCCESS {
        eprintln!(
            "native_balance: {id_hex} read failed ({})",
            ffi::describe(rc)
        );
        return None;
    }
    Some((id_hex, u128::from_le_bytes(out)))
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
    // `payer` is local configuration, never a chain read: this method is what
    // a consumer polls to tell "coming up" from "broken", so it must not be
    // able to block or fail on a sequencer round trip. What that account can
    // afford is get_native_balance's question.
    // `network` is the recorded binding, "" while unbound or when the home was
    // configured by its operator (whose network this module cannot name).
    serde_json::json!({
        "detail": detail,
        "network": network,
        "payer": state.payer_hex,
        "payer_public_key": state.payer_public_key,
        "ready": name == "ready",
        "state": name,
    })
    .to_string()
}

/// The unit-test binary links no `core_ffi`, yet the code above names its
/// symbols. Define them as a "no wallet" transport — every entry point answers
/// `WALLET_NOT_INITIALIZED` and the constructors hand back null — so a test
/// exercises the argument handling above and never reaches a real wallet. The
/// real symbols come from the library at the final plugin link.
#[cfg(test)]
#[allow(unsafe_code)]
mod wallet_ffi_test_transport {
    use super::ffi;
    use std::ffi::{c_char, c_void};

    #[no_mangle]
    pub extern "C" fn wallet_ffi_open(
        _c: *const c_char,
        _s: *const c_char,
        _seq: *const c_void,
        _p: *const c_char,
        _o: *mut *mut ffi::WalletHandle,
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_create_new(
        _c: *const c_char,
        _s: *const c_char,
        _p: *const c_char,
        _seq: *const c_void,
    ) -> ffi::CreateWalletOutput {
        ffi::CreateWalletOutput {
            wallet: std::ptr::null_mut(),
            mnemonic: std::ptr::null_mut(),
        }
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_get_public_account_key(
        _h: *mut ffi::WalletHandle,
        _a: *const ffi::Bytes32,
        _o: *mut ffi::PublicAccountKey,
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn primitives_ffi_free_cstring(_s: *mut c_char) {}

    #[no_mangle]
    pub extern "C" fn wallet_ffi_save(_h: *mut ffi::WalletHandle) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_import_public_account(
        _h: *mut ffi::WalletHandle,
        _k: *const c_char,
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_create_account_public(
        _h: *mut ffi::WalletHandle,
        o: *mut ffi::Bytes32,
    ) -> i32 {
        // Derivation succeeds so a test reaches the save after it, which fails.
        // SAFETY: the caller passes an out struct it owns.
        unsafe { (*o).data = [7; 32] };
        ffi::SUCCESS
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_get_balance(
        _h: *mut ffi::WalletHandle,
        _a: *const ffi::Bytes32,
        _is_public: bool,
        _o: *mut [u8; 16],
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_get_account_public(
        _h: *mut ffi::WalletHandle,
        _a: *const ffi::Bytes32,
        _o: *mut ffi::Account,
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_free_account_data(_a: *mut ffi::Account) {}

    #[no_mangle]
    #[allow(clippy::too_many_arguments)]
    pub extern "C" fn wallet_ffi_send_generic_public_transaction(
        _h: *mut ffi::WalletHandle,
        _am: *const ffi::AccountMention,
        _ams: usize,
        _root: usize,
        _m: *const u8,
        _ms: usize,
        _payer: *const ffi::Bytes32,
        _o: *mut ffi::TransactionResult,
    ) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_free_transaction_result(_r: *mut ffi::TransactionResult) {}

    #[no_mangle]
    pub extern "C" fn wallet_ffi_sync_to_block(_h: *mut ffi::WalletHandle, _b: u64) -> i32 {
        ffi::NO_WALLET
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_get_current_block_height(
        _h: *mut ffi::WalletHandle,
        _o: *mut u64,
    ) -> i32 {
        ffi::NO_WALLET
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base58_payer_resolves_without_a_wallet() {
        // The conversion is local, so it answers before bring-up — which
        // matters, because the fee payer is resolved on the register path.
        assert_eq!(
            crate::hex::canonical_account_hex("FqNyaKjaeUxjMxJszC88Z6SUUL8pxBgN6qRHC4ZsJjgn")
                .as_deref(),
            Some("dc6857ef4236ef416fb6357c1f9988a7c7558b07492d7284c411b3864a1fccf3")
        );
        assert_eq!(crate::hex::canonical_account_hex("not an account"), None);
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

    fn signer(account: [u8; 32]) -> Mention {
        Mention {
            account,
            program: [0; 32],
            kind: MentionKind::Signer,
        }
    }

    #[test]
    fn a_root_index_past_the_mentions_is_refused_before_any_call() {
        // Returns before touching the wallet, so it holds with none open.
        assert_eq!(
            send_generic_public_transaction(&[signer([0xAB; 32])], 1, &[1, 2, 3], ""),
            None
        );
        assert_eq!(send_generic_public_transaction(&[], 0, &[1], ""), None);
    }

    // The wallet's own failure reply is not a submission: success:false (no
    // key for the payer, no network) and a success without a hash both mean
    // nothing reached the sequencer.
    #[test]
    fn a_failed_send_is_not_a_submission() {
        let sent = |error: &str, success: bool, tx_hash: &str| SendResult {
            error: error.into(),
            success,
            tx_hash: tx_hash.into(),
        };
        assert!(sent("", true, "ab12").accepted().is_ok());
        assert_eq!(
            sent("key not found", false, "").accepted().unwrap_err(),
            "key not found"
        );
        assert_eq!(sent("", false, "").accepted().unwrap_err(), "send failed");
        assert_eq!(
            sent("", true, "").accepted().unwrap_err(),
            "no tx_hash in the send reply"
        );
        assert_eq!(
            sent("", true, "ab12").to_json(),
            r#"{"error":"","success":true,"tx_hash":"ab12"}"#
        );
        assert_eq!(
            sent("key not found", false, "").to_json(),
            r#"{"error":"key not found","success":false,"tx_hash":""}"#
        );
    }

    #[test]
    fn a_pda_mention_is_authority_seed_and_derived_id() {
        let pda = Mention {
            account: [0xAA; 32],
            program: [0xBB; 32],
            kind: MentionKind::Pda {
                program: [0xCC; 32],
                seed: [0xDD; 32],
            },
        }
        .to_ffi();
        assert_eq!(pda.identity.kind, ffi::KIND_PUBLIC_PDA);
        assert_eq!(pda.identity.account_id.data, [0xAA; 32]);
        assert_eq!(pda.identity.authority.data, [0xCC; 32]);
        assert_eq!(pda.identity.seed.data, [0xDD; 32]);
        assert_eq!(pda.program_account_id.data, [0xBB; 32]);
        assert!(!pda.authorizes);

        let signs = signer([0xAB; 32]).to_ffi();
        assert_eq!(signs.identity.kind, ffi::KIND_PUBLIC);
        assert_eq!(signs.identity.authority.data, [0; 32]);
        assert!(signs.authorizes);

        let declared = Mention {
            account: [1; 32],
            program: [0; 32],
            kind: MentionKind::NoSign,
        }
        .to_ffi();
        assert_eq!(declared.identity.kind, ffi::KIND_PUBLIC_NO_SIGN);
        assert!(!declared.authorizes);
    }

    #[test]
    fn send_errors_name_their_kind() {
        assert!(send_error(ffi::PAYER_CANNOT_FUND).starts_with("insufficient_balance: "));
        assert!(send_error(ffi::KEY_NOT_FOUND).starts_with("no_signing_key: "));
        assert!(send_error(ffi::INVALID_ACCOUNT_ID).starts_with("pda_mismatch: "));
        assert_eq!(send_error(99), "wallet: code 99 (internal error)");
    }

    // ---------------------------------------------------- payer resolution

    /// `LEZ_RLN_PAYER` is process-global; the tests that set it or need it
    /// unset hold this lock.
    static PAYER_ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn an_invalid_env_payer_fails_resolution() {
        let _env = lock(&PAYER_ENV);
        let home = temp_home("payer-env");
        std::env::set_var("LEZ_RLN_PAYER", "not an account");
        let got = resolve_payer(&Handle(std::ptr::null_mut()), &home);
        std::env::remove_var("LEZ_RLN_PAYER");
        let err = got.unwrap_err();
        assert!(err.contains("LEZ_RLN_PAYER"), "got {err}");
        assert!(!home.join(PAYER_FILE).exists());
    }

    #[test]
    fn an_unreadable_payer_record_is_an_error_not_a_new_payer() {
        let _env = lock(&PAYER_ENV);
        let home = temp_home("payer-unreadable");
        // A directory where the record belongs: present, but not readable as one.
        std::fs::create_dir(home.join(PAYER_FILE)).unwrap();
        let err = resolve_payer(&Handle(std::ptr::null_mut()), &home).unwrap_err();
        assert!(err.starts_with("read "), "got {err}");
        assert!(err.contains(PAYER_FILE), "got {err}");
    }

    #[test]
    fn a_failed_save_records_no_payer() {
        let _env = lock(&PAYER_ENV);
        let home = temp_home("payer-save");
        let err = resolve_payer(&Handle(std::ptr::null_mut()), &home).unwrap_err();
        assert!(err.contains("saving the wallet failed"), "got {err}");
        assert!(!home.join(PAYER_FILE).exists());
    }

    // ---------------------------------------------------- network selection

    /// A fresh, empty directory per test; removed first so a rerun starts clean.
    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lez-rln-wallet-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env(sequencer: &str, network: &str) -> EnvView {
        EnvView {
            sequencer: sequencer.to_owned(),
            network: network.to_owned(),
        }
    }

    fn selector(selection: Selection) -> Selector {
        Selector {
            selection,
            operator_noted: false,
        }
    }

    fn devnet_sequencer() -> String {
        networks::network("devnet").unwrap().sequencer.clone()
    }

    #[test]
    fn plan_adopts_an_existing_config_whatever_the_env_says() {
        let home = temp_home("plan-adopt");
        std::fs::write(home.join(CONFIG_FILE), "{}").unwrap();
        assert_eq!(
            plan_home(&home, env("http://elsewhere/", "devnet")),
            Plan::Adopt(Binding::Operator)
        );
        std::fs::write(
            home.join(NETWORK_FILE),
            r#"{"network":"devnet","source":"table"}"#,
        )
        .unwrap();
        assert_eq!(
            plan_home(&home, env("", "")),
            Plan::Adopt(Binding::Recorded {
                network: "devnet".into(),
                source: Source::Table
            })
        );
        // A marker that does not parse must not read as "operator": that
        // would switch the network check off without a word.
        std::fs::write(home.join(NETWORK_FILE), "garbage").unwrap();
        assert!(matches!(plan_home(&home, env("", "")), Plan::Failed(_)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn plan_provisions_from_the_sequencer_labelled_or_not() {
        let home = temp_home("plan-seq");
        assert_eq!(
            plan_home(&home, env("http://seq/", "")),
            Plan::Provision {
                sequencer: "http://seq/".into(),
                binding: Binding::Operator
            }
        );
        assert_eq!(
            plan_home(&home, env("http://seq/", "testnet")),
            Plan::Provision {
                sequencer: "http://seq/".into(),
                binding: Binding::Recorded {
                    network: "testnet".into(),
                    source: Source::Env
                },
            }
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn plan_looks_a_bare_network_up_in_the_table() {
        let home = temp_home("plan-net");
        assert_eq!(
            plan_home(&home, env("", "devnet")),
            Plan::Provision {
                sequencer: devnet_sequencer(),
                binding: Binding::Recorded {
                    network: "devnet".into(),
                    source: Source::Table
                },
            }
        );
        let Plan::Failed(reason) = plan_home(&home, env("", "nosuch")) else {
            panic!("an unknown network must fail");
        };
        assert!(reason.contains("unknown network 'nosuch'"), "{reason}");
        assert!(
            reason.contains("devnet"),
            "the refusal lists what is known: {reason}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Nothing configured is a wait, not a failure: the membership module's
    /// provisioning abandons a registry for good on `failed`, and the registry
    /// id it is about to send can still name the network.
    #[test]
    fn plan_with_nothing_configured_awaits_selection() {
        let home = temp_home("plan-await");
        assert_eq!(plan_home(&home, env("", "")), Plan::AwaitSelection);
        let mut sel = selector(Selection::Unresolved);
        assert_eq!(
            apply_plan(&mut sel, home.clone(), Plan::AwaitSelection),
            Action::Await
        );
        assert!(matches!(sel.selection, Selection::Awaiting(_)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_sequencer_labelled_with_a_network_writes_the_marker() {
        let home = temp_home("env-marker");
        let mut sel = selector(Selection::Unresolved);
        let plan = plan_home(&home, env("http://seq/", "devnet"));
        assert_eq!(
            apply_plan(&mut sel, home.clone(), plan),
            Action::Start(home.clone())
        );
        assert_eq!(
            std::fs::read_to_string(home.join(CONFIG_FILE)).unwrap(),
            wallet_config_json("http://seq/")
        );
        assert_eq!(
            read_marker(&home).unwrap(),
            Some(Binding::Recorded {
                network: "devnet".into(),
                source: Source::Env
            })
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
            Some(Binding::Recorded {
                network: "devnet".into(),
                source: Source::Table
            })
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
        assert!(
            reply
                .detail
                .contains("unknown network 'nosuch' (known: devnet"),
            "{}",
            reply.detail
        );
        assert!(reply
            .detail
            .contains("LEZ_RLN_SEQUENCER or LEE_WALLET_HOME_DIR"));
        assert_eq!(action, Action::None);
        assert!(!home.join(CONFIG_FILE).exists());
        assert!(!home.join(NETWORK_FILE).exists());
        assert!(
            matches!(sel.selection, Selection::Awaiting(_)),
            "still selectable"
        );
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
            reply
                .detail
                .contains("is bound to network devnet; refusing to re-point it to testnet"),
            "{}",
            reply.detail
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_operator_home_accepts_any_network() {
        let home = temp_home("select-operator");
        let mut sel = selector(Selection::Bound {
            home: home.clone(),
            binding: Binding::Operator,
        });
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
        assert_eq!(
            std::fs::read_to_string(home.join(CONFIG_FILE)).unwrap(),
            staged
        );
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
        assert_eq!(
            sequencer_of_config(&wallet_config_json(&seq)),
            Some(seq.clone())
        );
        // A flat-only config still names it.
        let flat = serde_json::json!({ "sequencer_addr": seq }).to_string();
        assert_eq!(sequencer_of_config(&flat), Some(seq));
        assert_eq!(sequencer_of_config(r#"{"sequencers":[]}"#), None);
        assert_eq!(sequencer_of_config(r#"{"sequencer_addr":" "}"#), None);
        assert_eq!(sequencer_of_config("not json"), None);
    }

    #[test]
    fn status_carries_the_network_and_payer_key_fields() {
        let s = status_json();
        assert!(s.contains(r#""network":"#), "got {s}");
        assert!(s.contains(r#""payer_public_key":"#), "got {s}");
    }

    #[test]
    fn a_malformed_payer_is_refused_before_any_call() {
        let out = send_generic_public_transaction(&[signer([0xAB; 32])], 0, &[1, 2, 3], "not-hex");
        assert_eq!(out, None);
    }
}
