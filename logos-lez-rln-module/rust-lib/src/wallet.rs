//! The wallet this module owns.
//!
//! Every registry read and every transaction used to go out over lp to the
//! `lez_core` module. That module holds exactly one wallet handle per host,
//! `open` and `create_new` both refuse while one is open, and there is no
//! close — so whichever app opened first owned the only wallet, and the others
//! inherited whatever config it was opened with. For this module that is not
//! untidy but fatal: the gas limit a transaction declares comes from the
//! wallet's config, a registration costs ~9.1M cycles against a stock default
//! of 2,000,000, and `lez_core` exposes no way to read the limit back. Losing
//! that race meant every registration refused with a bare "Incorrect fee".
//!
//! So this module links `wallet_ffi` itself and holds a handle of its own.
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
//! What the wallet cannot do is pay its own way. A fee is reserved from a
//! *native* balance; the payer must sign, so the wallet has to hold its key;
//! and native balance enters an account only at genesis, over the L1 bridge,
//! or by transfer from something already funded. A wallet created here can
//! sign but never pay, so a funded key has to be handed in —
//! `LEZ_RLN_PAYER_KEY` — and `LEZ_RLN_PAYER` names which account to declare.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use crate::base58;
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

/// A funded account's private key as 32-byte hex, imported so the wallet can
/// sign as the fee payer. Not needed when the adopted home already holds a
/// funded account — a staged deployment wallet does.
const PAYER_KEY_ENV: &str = "LEZ_RLN_PAYER_KEY";

/// How long a handler waits for bring-up before giving up. Consumers already
/// retry a failed read; blocking a dispatch thread for a whole first sync
/// would wedge the module under `concurrency:"multi"`.
const READY_WAIT: Duration = Duration::from_secs(30);

/// The wallet's execution gas limit, for a home we provision. Gas is cycles in
/// v0.2.5 and a registration costs ~9.1M, so the wallet's own 2,000,000
/// default refuses one outright. This is the per-transaction ceiling the
/// sequencer allows; unused gas is refunded, so a cheaper call still pays less.
const GAS_LIMIT: u64 = 10_000_000;

#[allow(unsafe_code)]
mod ffi {
    //! Declarations for the `wallet_ffi` library. `#[allow(unsafe_code)]` is
    //! scoped to this module, as it is for the generated scaffold and the lp
    //! test transport: the crate keeps `deny(unsafe_code)` everywhere else.
    use std::ffi::{c_char, c_void};

    pub type WalletHandle = c_void;

    pub const SUCCESS: i32 = 0;
    /// `WALLET_NOT_INITIALIZED`, the code the test transport answers with.
    pub const NO_WALLET: i32 = 3;

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

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ProgramId {
        pub data: [u32; 8],
    }

    #[repr(C)]
    pub struct Account {
        pub program_owner: Bytes32,
        pub balance: U128,
        pub data: *const u8,
        pub data_len: usize,
        pub nonce: U128,
    }

    impl Default for Account {
        fn default() -> Self {
            Self {
                program_owner: Bytes32::default(),
                balance: U128::default(),
                data: std::ptr::null(),
                data_len: 0,
                nonce: U128::default(),
            }
        }
    }

    /// The two kinds this module uses: a public account either signs or does
    /// not. The enum is wider; the private variants never appear here.
    pub const KIND_PUBLIC: i32 = 0;
    pub const KIND_PUBLIC_NO_SIGN: i32 = 1;

    #[repr(C)]
    pub struct AccountIdentity {
        pub kind: i32,
        pub account_id: Bytes32,
        pub key_path: *mut c_char,
        pub authorization_secret_key: Bytes32,
        pub nullifier_secret_key: Bytes32,
        pub nullifier_public_key: Bytes32,
        pub viewing_public_key: *const u8,
        pub viewing_public_key_len: usize,
        pub identifier: U128,
    }

    impl AccountIdentity {
        pub fn public(account_id: [u8; 32], signs: bool) -> Self {
            Self {
                kind: if signs { KIND_PUBLIC } else { KIND_PUBLIC_NO_SIGN },
                account_id: Bytes32 { data: account_id },
                key_path: std::ptr::null_mut(),
                authorization_secret_key: Bytes32::default(),
                nullifier_secret_key: Bytes32::default(),
                nullifier_public_key: Bytes32::default(),
                viewing_public_key: std::ptr::null(),
                viewing_public_key_len: 0,
                identifier: U128::default(),
            }
        }
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

    extern "C" {
        pub fn wallet_ffi_open(
            config_path: *const c_char,
            storage_path: *const c_char,
            statistics_path: *const c_char,
        ) -> *mut WalletHandle;

        pub fn wallet_ffi_create_new(
            config_path: *const c_char,
            storage_path: *const c_char,
            statistics_path: *const c_char,
            password: *const c_char,
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

        pub fn wallet_ffi_send_generic_public_transaction(
            handle: *mut WalletHandle,
            account_identities: *const AccountIdentity,
            account_identities_size: usize,
            instruction_data: *const u8,
            instruction_data_size: usize,
            program_id: ProgramId,
            payer: *const Bytes32,
            out_result: *mut TransactionResult,
        ) -> i32;

        pub fn wallet_ffi_free_transaction_result(result: *mut TransactionResult);

        pub fn wallet_ffi_sync_to_block(handle: *mut WalletHandle, block_id: u64) -> i32;

        pub fn wallet_ffi_get_current_block_height(
            handle: *mut WalletHandle,
            out_block_height: *mut u64,
        ) -> i32;
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
    /// Bring-up has not finished: still opening, importing or syncing.
    Pending,
    /// Open and caught up to the head it last observed.
    Ready,
    /// Bring-up gave up; the string is the reason, already logged.
    Failed(String),
}

struct State {
    readiness: Readiness,
    /// Shared for reads and sends, exclusive for deriving an account. Callers
    /// clone the `Arc` and drop the state lock before calling: holding it
    /// across a sequencer round trip would serialize every handler, the wedge
    /// the `single` -> `multi` concurrency bump was made to escape.
    wallet: Option<Arc<RwLock<Handle>>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    readiness: Readiness::Pending,
    wallet: None,
});

/// Signalled once bring-up settles, either way.
static SETTLED: Condvar = Condvar::new();

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Kick bring-up on its own thread. Called from `on_context_ready`, which runs
/// on the host's Qt main thread — opening a wallet calibrates sequencers and
/// then syncs the chain, work the loop must not be holding.
pub(crate) fn spawn_bring_up(persistence_path: &str) {
    let home = match std::env::var(HOME_ENV) {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir.trim()),
        _ => {
            if persistence_path.is_empty() {
                fail(&format!(
                    "no instance_persistence_path from the host and no {HOME_ENV} — the wallet \
                     has nowhere to live"
                ));
                return;
            }
            PathBuf::from(persistence_path).join("wallet-home")
        }
    };
    std::thread::Builder::new()
        .name("lez-rln-wallet".to_owned())
        .spawn(move || bring_up(&home))
        .map(|_| ())
        .unwrap_or_else(|e| fail(&format!("cannot spawn the wallet bring-up thread: {e}")));
}

fn fail(reason: &str) {
    eprintln!("lez-rln wallet: {reason}");
    let mut state = lock(&STATE);
    state.readiness = Readiness::Failed(reason.to_owned());
    SETTLED.notify_all();
}

fn bring_up(home: &Path) {
    if let Err(e) = std::fs::create_dir_all(home) {
        fail(&format!("create {}: {e}", home.display()));
        return;
    }
    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let statistics_path = home.join("statistics.json");

    // An existing config is authoritative and is never rewritten: adopting a
    // home means adopting the chain it already points at, and re-pointing a
    // wallet that holds registered memberships would strand them. Only a home
    // we provision ourselves needs to be told a sequencer.
    if !config_path.exists() {
        let sequencer = std::env::var(SEQUENCER_ENV).unwrap_or_default();
        let sequencer = sequencer.trim();
        if sequencer.is_empty() {
            fail(&format!(
                "{} has no wallet_config.json and {SEQUENCER_ENV} is unset — this module owns \
                 its own wallet and needs to be told which sequencer it talks to",
                home.display()
            ));
            return;
        }
        if let Err(e) = std::fs::write(&config_path, wallet_config_json(sequencer)) {
            fail(&format!("write {}: {e}", config_path.display()));
            return;
        }
    }

    let handle = match open_or_create(&config_path, &storage_path, &statistics_path) {
        Ok(h) => h,
        Err(e) => {
            fail(&e);
            return;
        }
    };

    if let Err(e) = import_payer_key(&handle) {
        fail(&e);
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
    state.readiness = Readiness::Ready;
    SETTLED.notify_all();
    eprintln!("lez-rln wallet: ready ({})", home.display());
}

#[allow(unsafe_code)]
fn open_or_create(config: &Path, storage: &Path, statistics: &Path) -> Result<Handle, String> {
    let c = cstring(config)?;
    let s = cstring(storage)?;
    let t = cstring(statistics)?;

    if storage.exists() {
        // SAFETY: three valid null-terminated paths, alive across the call.
        let raw = unsafe { ffi::wallet_ffi_open(c.as_ptr(), s.as_ptr(), t.as_ptr()) };
        if raw.is_null() {
            return Err(format!("open {} returned no handle", storage.display()));
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
    // This wallet build does not use the password for storage encryption
    // (storage.json is plaintext either way), so there is nothing to remember
    // and nothing gained by inventing a secret here.
    let pw = CString::new("").map_err(|e| e.to_string())?;
    // SAFETY: four valid null-terminated strings, alive across the call.
    let out = unsafe { ffi::wallet_ffi_create_new(c.as_ptr(), s.as_ptr(), t.as_ptr(), pw.as_ptr()) };
    if out.wallet.is_null() {
        return Err(format!(
            "create_new at {} returned no handle",
            storage.display()
        ));
    }
    Ok(Handle(out.wallet))
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
    if crate::hex_to_bytes32(raw).is_none() {
        return Err(format!("{PAYER_KEY_ENV} is not 32-byte hex"));
    }
    let key = CString::new(raw).map_err(|e| e.to_string())?;
    // SAFETY: a live handle and a valid null-terminated hex string.
    let rc = unsafe { ffi::wallet_ffi_import_public_account(handle.0, key.as_ptr()) };
    if rc != ffi::SUCCESS {
        return Err(format!("{PAYER_KEY_ENV} import failed (code {rc})"));
    }
    save(handle);
    eprintln!("lez-rln wallet: imported the fee payer's key");
    Ok(())
}

#[allow(unsafe_code)]
fn save(handle: &Handle) {
    // SAFETY: a live handle.
    let rc = unsafe { ffi::wallet_ffi_save(handle.0) };
    if rc != ffi::SUCCESS {
        eprintln!("lez-rln wallet: save failed (code {rc})");
    }
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
        return Err(format!("chain head unavailable (code {rc})"));
    }
    // SAFETY: a live handle.
    let rc = unsafe { ffi::wallet_ffi_sync_to_block(handle.0, head) };
    if rc != ffi::SUCCESS {
        return Err(format!("sync to {head} failed (code {rc})"));
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
        // v0.2.5 reads `sequencers`; the flat field is what the rc6-era wallet
        // read. Neither denies unknown fields, so both can ride along.
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
/// caller reports the same empty string `lez_core` used to return.
fn wallet(who: &str) -> Option<Arc<RwLock<Handle>>> {
    let mut state = lock(&STATE);
    loop {
        match &state.readiness {
            Readiness::Ready => break,
            Readiness::Failed(reason) => {
                eprintln!("{who}: wallet unavailable: {reason}");
                return None;
            }
            Readiness::Pending => {
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

/// Public account state as the JSON `{program_owner, balance, nonce, data}`
/// (all hex) that `lez_core` returned, so the parsing above is unchanged.
/// Empty string on failure.
#[allow(unsafe_code)]
pub(crate) fn get_account_public(account_id_hex: &str) -> String {
    let Some(bytes) = crate::hex_to_bytes32(account_id_hex) else {
        eprintln!("get_account_public: {account_id_hex} is not 32-byte hex");
        return String::new();
    };
    let Some(wallet) = wallet("get_account_public") else {
        return String::new();
    };
    let guard = wallet.read().unwrap_or_else(|p| p.into_inner());
    let id = ffi::Bytes32 { data: bytes };
    let mut account = ffi::Account::default();
    // SAFETY: a live handle, a stack id alive across the call, and an out
    // struct we own.
    let rc =
        unsafe { ffi::wallet_ffi_get_account_public(guard.0, &raw const id, &raw mut account) };
    if rc != ffi::SUCCESS {
        eprintln!("get_account_public({account_id_hex}): code {rc}");
        return String::new();
    }
    // SAFETY: on success the library hands back a pointer it owns, valid for
    // `data_len` bytes until `wallet_ffi_free_account_data`.
    let data = if account.data.is_null() || account.data_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(account.data, account.data_len) }.to_vec()
    };
    let out = serde_json::json!({
        "program_owner": bytes_to_hex(&account.program_owner.data),
        "balance": u128::from_le_bytes(account.balance.data).to_string(),
        "nonce": u128::from_le_bytes(account.nonce.data).to_string(),
        "data": bytes_to_hex(&data),
    })
    .to_string();
    // SAFETY: the struct the call just filled, freed exactly once.
    unsafe { ffi::wallet_ffi_free_account_data(&raw mut account) };
    out
}

/// Submit a generic public transaction, answering the JSON
/// `{success, tx_hash, error}` shape the module already parses.
#[allow(unsafe_code)]
pub(crate) fn send_generic_public_transaction(
    account_ids: &[String],
    signing_requirements: &[bool],
    instruction: &[u8],
    program_id_hex: &str,
    payer_account_id_hex: &str,
) -> String {
    if account_ids.len() != signing_requirements.len() {
        eprintln!("send_generic_public_transaction: account/signing arrays differ in length");
        return String::new();
    }
    let mut identities = Vec::with_capacity(account_ids.len());
    for (id_hex, signs) in account_ids.iter().zip(signing_requirements) {
        let Some(bytes) = crate::hex_to_bytes32(id_hex) else {
            eprintln!("send_generic_public_transaction: {id_hex} is not 32-byte hex");
            return String::new();
        };
        identities.push(ffi::AccountIdentity::public(bytes, *signs));
    }
    let Some(program) = crate::hex_to_bytes32(program_id_hex) else {
        eprintln!(
            "send_generic_public_transaction: program id {program_id_hex} is not 32-byte hex"
        );
        return String::new();
    };
    // A ProgramId is eight u32 words, each little-endian, and an AccountId is
    // their concatenation (lee program/mod.rs) — so this is the inverse.
    let mut program_id = ffi::ProgramId::default();
    for (word, chunk) in program_id.data.iter_mut().zip(program.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
    }

    // Empty means self-pay, matching the lez_core contract.
    let payer = if payer_account_id_hex.trim().is_empty() {
        None
    } else {
        match crate::hex_to_bytes32(payer_account_id_hex) {
            Some(bytes) => Some(ffi::Bytes32 { data: bytes }),
            None => {
                eprintln!(
                    "send_generic_public_transaction: payer {payer_account_id_hex} is not \
                     32-byte hex"
                );
                return String::new();
            }
        }
    };
    let payer_ptr = payer.as_ref().map_or(std::ptr::null(), std::ptr::from_ref);

    let Some(wallet) = wallet("send_generic_public_transaction") else {
        return String::new();
    };
    let guard = wallet.read().unwrap_or_else(|p| p.into_inner());
    let mut result = ffi::TransactionResult::default();
    // SAFETY: a live handle; identities, instruction and payer all outlive the
    // call; the out struct is ours.
    let rc = unsafe {
        ffi::wallet_ffi_send_generic_public_transaction(
            guard.0,
            identities.as_ptr(),
            identities.len(),
            instruction.as_ptr(),
            instruction.len(),
            program_id,
            payer_ptr,
            &raw mut result,
        )
    };
    if rc != ffi::SUCCESS {
        eprintln!("send_generic_public_transaction failed: code {rc}");
        // SAFETY: freeing the out struct is the library's contract whether or
        // not the call filled it.
        unsafe { ffi::wallet_ffi_free_transaction_result(&raw mut result) };
        return serde_json::json!({
            "success": false,
            "tx_hash": "",
            "error": format!("wallet_ffi error {rc}"),
        })
        .to_string();
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

    serde_json::json!({ "error": "", "success": success, "tx_hash": tx_hash }).to_string()
}

/// Derive a fresh public account in this module's own wallet and persist it,
/// returning it as 64 hex chars. Empty string on failure.
///
/// Derivation is deterministic from the wallet's seed, so this hands back the
/// next slot rather than a random one; a caller that needs an account nothing
/// has claimed on-chain yet checks the balance and asks again. It lives here
/// because the wallet does: the accounts this module signs with have to be
/// ones its own storage knows.
#[allow(unsafe_code)]
pub(crate) fn create_holding_account() -> String {
    let Some(wallet) = wallet("create_holding_account") else {
        return String::new();
    };
    // Exclusive: deriving mutates the key chain, and a read mid-derivation
    // would see a wallet halfway through it.
    let guard = wallet.write().unwrap_or_else(|p| p.into_inner());
    let mut out = ffi::Bytes32::default();
    // SAFETY: a live handle and an out struct we own.
    let rc = unsafe { ffi::wallet_ffi_create_account_public(guard.0, &raw mut out) };
    if rc != ffi::SUCCESS {
        eprintln!("create_holding_account: code {rc}");
        return String::new();
    }
    // Derivation alone does not persist; without this the account is gone on
    // the next open and nothing can sign for it.
    save(&guard);
    bytes_to_hex(&out.data)
}

/// What the module can say about its wallet without one being open — the read
/// a consumer uses to tell "still coming up" from "broken".
pub(crate) fn status_json() -> String {
    let state = lock(&STATE);
    // `state` is the field a consumer branches on, because the distinction
    // that matters is not ready-or-not but retry-or-give-up: "pending" means
    // wait, "failed" means waiting longer will not help. `detail` is for a
    // human reading a log.
    let (name, detail) = match &state.readiness {
        Readiness::Ready => ("ready", String::new()),
        Readiness::Pending => ("pending", "opening the wallet".to_owned()),
        Readiness::Failed(reason) => ("failed", reason.clone()),
    };
    serde_json::json!({
        "detail": detail,
        "ready": name == "ready",
        "state": name,
    })
    .to_string()
}

/// The unit-test binary links no `wallet_ffi`, yet the code above names its
/// symbols. Define them as a "no wallet" transport — every entry point answers
/// `WALLET_NOT_INITIALIZED` and the constructors hand back null — so a test
/// exercises the argument handling above and never reaches a real wallet. The
/// real symbols come from the library at the final plugin link.
#[cfg(test)]
#[allow(unsafe_code)]
mod wallet_ffi_test_transport {
    use super::ffi;
    use std::ffi::c_char;

    #[no_mangle]
    pub extern "C" fn wallet_ffi_open(
        _c: *const c_char,
        _s: *const c_char,
        _t: *const c_char,
    ) -> *mut ffi::WalletHandle {
        std::ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn wallet_ffi_create_new(
        _c: *const c_char,
        _s: *const c_char,
        _t: *const c_char,
        _p: *const c_char,
    ) -> ffi::CreateWalletOutput {
        ffi::CreateWalletOutput {
            wallet: std::ptr::null_mut(),
            mnemonic: std::ptr::null_mut(),
        }
    }

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
        _o: *mut ffi::Bytes32,
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
        _ai: *const ffi::AccountIdentity,
        _ais: usize,
        _i: *const u8,
        _is: usize,
        _p: ffi::ProgramId,
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

    #[test]
    fn mismatched_account_and_signing_arrays_are_refused_before_any_call() {
        // Returns before touching the wallet, so it holds with none open.
        let out = send_generic_public_transaction(
            &["ab".repeat(32)],
            &[true, false],
            &[1, 2, 3],
            &"cd".repeat(32),
            "",
        );
        assert_eq!(out, "");
    }

    #[test]
    fn a_malformed_program_id_is_refused_before_any_call() {
        let out = send_generic_public_transaction(
            &["ab".repeat(32)],
            &[true],
            &[1, 2, 3],
            "not-hex",
            "",
        );
        assert_eq!(out, "");
    }
}
