//! The wallet this module owns, in-process.
//!
//! Every registry read and every transaction used to go out over lp to the
//! `lez_core` module. That module holds exactly one wallet handle per host,
//! `open` and `create_new` both refuse while one is open, and there is no
//! close — so whichever app opened first owned the only wallet, and the
//! others inherited whatever config it was opened with. For this module that
//! is not survivable: a registration costs ~9.1M cycles, the gas limit a
//! transaction declares comes from the wallet's config, the stock default is
//! 2,000,000, and `lez_core` exposes no way to read the limit back. Losing
//! the race meant every registration refused with a bare "Incorrect fee".
//!
//! So this module links the wallet crate and keeps a `WalletCore` of its own,
//! under its own host-stamped persistence dir. Nothing else can take it, the
//! gas limit is ours to set, and the lp round trip disappears from the read
//! path.
//!
//! What it cannot do is pay its own way. A fee is reserved from a *native*
//! balance; the payer must sign, so the wallet has to hold its key; and
//! native balance only enters an account at genesis, over the L1 bridge, or
//! by transfer from something already funded. A wallet created here can sign
//! but never pay, so a funded payer's key has to be handed in —
//! `LEZ_RLN_PAYER_KEY` — and `LEZ_RLN_PAYER` names which account to declare.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use wallet::account::{AccountIdWithPrivacy, Label};
use wallet::storage::Storage;
use wallet::{AccountIdentity, WalletCore};

use lee::AccountId;

/// The account the payer is labelled under in our own storage, matching the
/// label `mint_payer` uses so an adopted deployment wallet reads the same.
const PAYER_LABEL: &str = "rln-fee-payer";

/// The sequencer this module's wallet talks to. There is no default on
/// purpose: `WalletConfig::from_path_or_initialize_default` would otherwise
/// write a config pointing at the public testnet, and a module silently
/// talking to the wrong chain is worse than one that refuses to start.
const SEQUENCER_ENV: &str = "LEZ_RLN_SEQUENCER";

/// A funded account's private key (32-byte hex), imported so the wallet can
/// sign as the fee payer. See the module header for why this cannot be
/// bootstrapped. Not needed when the adopted wallet home already holds a
/// funded account — a staged deployment wallet does.
const PAYER_KEY_ENV: &str = "LEZ_RLN_PAYER_KEY";

/// An existing wallet home to adopt instead of provisioning one under the
/// module's persistence dir. This is the variable the wallet crate itself
/// reads (`wallet::HOME_DIR_ENV_VAR`) and the one the e2e harness and
/// Basecamp already export, so a home staged by `tools/deployments/stage.sh`
/// — config, storage and the payer's derivation together — is adopted whole
/// with no extra configuration.
const HOME_ENV: &str = wallet::HOME_DIR_ENV_VAR;

/// How long a handler waits for bring-up before giving up. Consumers already
/// retry a failed read; blocking a dispatch thread for the whole first sync
/// would wedge the module under `concurrency:"multi"`.
const READY_WAIT: Duration = Duration::from_secs(30);

/// The wallet's execution gas limit. Gas is cycles in v0.2.5 and a
/// registration costs ~9.1M, so the wallet's own 2,000,000 default refuses
/// one outright. This is the per-transaction ceiling the sequencer allows,
/// and unused gas is refunded, so a cheaper call still pays less.
const GAS_LIMIT: u64 = 10_000_000;

pub(crate) enum Readiness {
    /// Bring-up has not run, or is still opening/syncing.
    Pending,
    /// Open and caught up to the head it last observed.
    Ready,
    /// Bring-up failed; the string is the reason, already logged.
    Failed(String),
}

struct State {
    readiness: Readiness,
    /// Behind an `Arc` so a handler can take a reference and release the
    /// state lock before it calls: this module is `concurrency:"multi"` and
    /// holding the lock across a sequencer round trip would serialize every
    /// handler behind one call — the exact wedge the single -> multi bump
    /// was made to escape. Every method a handler uses takes `&self`; only
    /// bring-up needs `&mut`, and it runs before the `Arc` is published.
    wallet: Option<Arc<WalletCore>>,
}

static STATE: Mutex<State> = Mutex::new(State {
    readiness: Readiness::Pending,
    wallet: None,
});

/// Signalled once bring-up settles, either way.
static SETTLED: Condvar = Condvar::new();

static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("wallet runtime")
});

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Kick bring-up on its own thread. Called from `on_context_ready`, which
/// runs on the host's Qt main thread — opening a wallet there would block the
/// loop for the whole calibration-and-sync, so nothing here may be done
/// inline.
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
    // wallet that already holds registered memberships would strand them.
    // Only a home we are provisioning ourselves needs to be told a sequencer.
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

    if let Err(e) = prepare_storage(&storage_path) {
        fail(&format!("wallet storage: {e}"));
        return;
    }

    let opened = RUNTIME.block_on(WalletCore::new_update_chain(
        config_path,
        storage_path,
        statistics_path,
        None,
    ));
    let mut core = match opened {
        Ok(core) => core,
        Err(e) => {
            fail(&format!("open: {e}"));
            return;
        }
    };

    match sync(&mut core) {
        Ok(head) => eprintln!("lez-rln wallet: synced to block {head}"),
        // Reads go to the sequencer, not to local state, so a wallet that
        // opened but has not caught up is still useful; a send tops it up.
        Err(e) => eprintln!("lez-rln wallet: initial sync incomplete: {e}"),
    }

    let mut state = lock(&STATE);
    state.wallet = Some(Arc::new(core));
    state.readiness = Readiness::Ready;
    SETTLED.notify_all();
    eprintln!("lez-rln wallet: ready ({})", home.display());
}

/// Load or create the storage, and import the fee payer's key when one is
/// configured. Done on `Storage` directly, before `WalletCore` opens, the way
/// `mint_payer` does it — `WalletCore` reaches for a sequencer as it opens,
/// and the import must be persisted before that.
fn prepare_storage(storage_path: &Path) -> anyhow::Result<()> {
    let mut storage = if storage_path.exists() {
        Storage::from_path(storage_path)?
    } else {
        Storage::new("")?.0
    };

    let mut dirty = !storage_path.exists();

    if let Ok(raw) = std::env::var(PAYER_KEY_ENV) {
        let raw = raw.trim();
        if !raw.is_empty() {
            let label = Label::new(PAYER_LABEL);
            if storage.resolve_label(&label).is_none() {
                let key = parse_private_key(raw)?;
                storage.key_chain_mut().add_imported_public_account(key);
                let account = imported_account_id(raw)?;
                storage
                    .add_label(label, AccountIdWithPrivacy::Public(account))
                    .ok();
                dirty = true;
                eprintln!("lez-rln wallet: imported the fee payer {account}");
            }
        }
    }

    if dirty {
        storage.save_to_path(storage_path)?;
    }
    Ok(())
}

fn parse_private_key(hex: &str) -> anyhow::Result<lee::PrivateKey> {
    let bytes = crate::hex_to_bytes32(hex)
        .ok_or_else(|| anyhow::anyhow!("{PAYER_KEY_ENV} is not 32-byte hex"))?;
    lee::PrivateKey::try_new(bytes)
        .map_err(|e| anyhow::anyhow!("{PAYER_KEY_ENV} is not a valid private key: {e:?}"))
}

fn imported_account_id(hex: &str) -> anyhow::Result<AccountId> {
    let key = parse_private_key(hex)?;
    Ok(AccountId::from(&lee::PublicKey::new_from_private_key(&key)))
}

/// The config this module writes for itself. The shape mirrors what
/// `tools/deployments/stage.sh` emits and what the membership module's
/// `provision_wallet_home` writes, so a home staged by either is readable
/// here and vice versa.
fn wallet_config_json(sequencer: &str) -> String {
    serde_json::json!({
        // v0.2.5 reads `sequencers`; the flat field is what the rc6-era
        // wallet read. Neither denies unknown fields, so both can ride along.
        "sequencer_addr": sequencer,
        "sequencers": [{ "sequencer_addr": sequencer }],
        "seq_poll_timeout": "30s",
        "seq_tx_poll_max_blocks": 15,
        "seq_poll_max_retries": 10,
        "seq_block_poll_max_amount": 100,
        "gas_limit": GAS_LIMIT,
        // The default is 100 sequential probes per sequencer, which blocks
        // the open for minutes against a slow chain. One sequencer, 3 probes.
        "multi_sequencer_client_config": { "distribution_limit": 1, "calibration_limit": 3 },
    })
    .to_string()
}

/// Catch the wallet up to the head.
///
/// The wallet serves no reads while a sync runs, but during bring-up nothing
/// is being served yet — handlers wait on `SETTLED` — so this can take the
/// whole range in one call. `sync_to_block` is a no-op when the cursor is
/// already past the target, which makes the top-up before a send free.
fn sync(core: &mut WalletCore) -> anyhow::Result<u64> {
    RUNTIME.block_on(async {
        let head = core.get_last_block_id().await?;
        core.sync_to_block(head).await?;
        Ok(head)
    })
}

/// Run `f` against the open wallet, waiting out bring-up if it is still in
/// flight. `None` means the wallet is unusable — the caller reports the same
/// empty string lez_core used to return.
fn with_wallet<R>(who: &str, f: impl FnOnce(&WalletCore) -> R) -> Option<R> {
    let core = {
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
        Arc::clone(state.wallet.as_ref()?)
        // The state lock is released here, before the call runs.
    };
    Some(f(&core))
}

// --- the three operations the module used to make over lp ------------------

/// Decode a base58 account id to 64 hex chars; empty string on failure.
/// Needs no wallet — kept here so every account-id conversion lives together.
pub(crate) fn account_id_from_base58(base58: &str) -> String {
    match base58.trim().parse::<AccountId>() {
        Ok(id) => crate::rln_core::bytes_to_hex(id.value()),
        Err(e) => {
            eprintln!("account_id_from_base58({base58}): {e}");
            String::new()
        }
    }
}

/// Public account state as the JSON `{program_owner, balance, nonce, data}`
/// (all hex) that `lez_core` returned, so the parsing above is unchanged.
/// Empty string on failure.
pub(crate) fn get_account_public(account_id_hex: &str) -> String {
    let Some(bytes) = crate::hex_to_bytes32(account_id_hex) else {
        eprintln!("get_account_public: {account_id_hex} is not 32-byte hex");
        return String::new();
    };
    let id = AccountId::new(bytes);
    let fetched = with_wallet("get_account_public", |core| {
        RUNTIME.block_on(core.get_account_public(id))
    });
    match fetched {
        Some(Ok(account)) => serde_json::json!({
            "program_owner": crate::rln_core::bytes_to_hex(account.program_owner.value()),
            "balance": account.balance.to_string(),
            "nonce": account.nonce.0.to_string(),
            "data": crate::rln_core::bytes_to_hex(&account.data),
        })
        .to_string(),
        Some(Err(e)) => {
            eprintln!("get_account_public({account_id_hex}): {e}");
            String::new()
        }
        None => String::new(),
    }
}

/// Submit a generic public transaction, answering the JSON
/// `{success, tx_hash, error}` shape the module already parses.
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
    let mut accounts = Vec::with_capacity(account_ids.len());
    for (id_hex, signs) in account_ids.iter().zip(signing_requirements) {
        let Some(bytes) = crate::hex_to_bytes32(id_hex) else {
            eprintln!("send_generic_public_transaction: {id_hex} is not 32-byte hex");
            return String::new();
        };
        let id = AccountId::new(bytes);
        accounts.push(if *signs {
            AccountIdentity::Public(id)
        } else {
            AccountIdentity::PublicNoSign(id)
        });
    }
    let Some(program_bytes) = crate::hex_to_bytes32(program_id_hex) else {
        eprintln!("send_generic_public_transaction: program id {program_id_hex} is not 32-byte hex");
        return String::new();
    };
    let program = AccountId::new(program_bytes);

    // Empty means self-pay, matching the lez_core contract.
    let payer = if payer_account_id_hex.trim().is_empty() {
        None
    } else {
        match crate::hex_to_bytes32(payer_account_id_hex) {
            Some(bytes) => Some(AccountId::new(bytes)),
            None => {
                eprintln!("send_generic_public_transaction: payer {payer_account_id_hex} is not 32-byte hex");
                return String::new();
            }
        }
    };

    let sent = with_wallet("send_generic_public_transaction", |core| {
        RUNTIME.block_on(core.send_pub_tx_paid_by(accounts, instruction.to_vec(), program, payer))
    });
    match sent {
        Some(Ok(hash)) => serde_json::json!({
            "success": true,
            "tx_hash": crate::rln_core::bytes_to_hex(hash.as_ref()),
            "error": "",
        })
        .to_string(),
        Some(Err(e)) => {
            eprintln!("send_generic_public_transaction failed: {e}");
            serde_json::json!({ "success": false, "tx_hash": "", "error": e.to_string() })
                .to_string()
        }
        None => String::new(),
    }
}

/// What the module can say about its wallet without one being open — the read
/// a consumer uses to tell "still coming up" from "broken".
pub(crate) fn status_json() -> String {
    let state = lock(&STATE);
    let (ready, detail) = match &state.readiness {
        Readiness::Ready => (true, String::new()),
        Readiness::Pending => (false, "coming up".to_owned()),
        Readiness::Failed(reason) => (false, reason.clone()),
    };
    serde_json::json!({ "detail": detail, "ready": ready }).to_string()
}
