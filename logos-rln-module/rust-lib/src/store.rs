//! Membership store: runtime state over the keystore file — unlock state,
//! record CRUD, the module-local lifecycle state machine, and the merged
//! (module ∪ registry) state view of RLN-MEMBERSHIP-MANAGEMENT.
//!
//! ## Lifecycle (module-local overlay)
//!
//! ```text
//! (register) → pending ──confirmed──→ active ──chain time──→ grace_period → expired
//!                │
//!                └─window elapsed──→ failed ──(re-register)──→ pending
//!
//! active-history + registry-absent → erased   (inferred: lez-rln wipes the
//!                                              PDA, so the registry itself
//!                                              can only report "unknown")
//! ```
//!
//! `pending`/`failed` exist only here; `active`/`grace_period`/`expired`
//! mirror the registry's chain-clock view; `failed`, `expired` and `erased`
//! records are retained and visible in `get_memberships` (spec: a Failed
//! membership SHOULD remain visible until re-registration replaces it) but
//! never selected.
//!
//! ## Unlock model
//!
//! The sidecar metadata is plaintext-safe, so reads and lifecycle polling
//! never need the password; `unlock` is required only to WRITE credentials
//! (register) and to RELEASE them (select). With zero stored credentials
//! any password unlocks and becomes the encryption password at first write —
//! inherent to the keystore format (no keystore-level verifier); a later
//! unlock is verified against the first stored envelope's MAC.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::keystore::{self, KeystoreEntry, KeystoreFile};
use crate::registry_id;
use crate::{ApiError, ErrorKind};

/// Persisted schema types owned by `keystore.rs` (the on-disk format);
/// re-exported so the crate addresses them as `store::` paths.
/// `store → keystore` is the only dependency edge between the two modules.
pub(crate) use crate::keystore::{
    AllocationState, CacheState, MembershipMeta, MembershipState, StateChange,
};

/// Pending→Failed bound (spec MUST). Testnet confirmation runs 60–90s;
/// 300s leaves margin.
pub(crate) const CONFIRMATION_WINDOW_SECS: u64 = 300;
const STATE_HISTORY_CAP: usize = 20;

// ------------------------------------------------------------------- records

impl CacheState {
    /// Records a failed submission: state → Failed, the "submit_failed: "
    /// failure-reason prefix consumers key on, and the spec's retryable flag.
    pub(crate) fn mark_submit_failed(&mut self, message: &str, retryable: bool) {
        self.state = MembershipState::Failed;
        self.failed_reason = Some(format!("submit_failed: {message}"));
        self.retryable = Some(retryable);
    }

    /// Record a late/async submission error without clobbering a state already
    /// advanced past `Pending` (the registry may have confirmed the submission).
    /// Only a non-retryable error fails a still-`Pending` record; retryable
    /// ones stay `Pending` for `merge_state` to confirm or time out.
    pub(crate) fn record_async_submit_error(&mut self, message: &str, retryable: bool) {
        if self.state != MembershipState::Pending || retryable {
            return;
        }
        self.mark_submit_failed(message, retryable);
    }
}

/// One registry's local record as consumers see it: the membership_hash, its
/// sidecar metadata, and whether the load-time tamper scan quarantined it.
/// In-memory only — never persisted (the on-disk shape is `KeystoreEntry`).
#[derive(Clone)]
pub(crate) struct MembershipRecord {
    pub(crate) hash: String,
    pub(crate) meta: MembershipMeta,
    pub(crate) quarantined: bool,
}

/// The decrypted credential plaintext (see keystore.rs module docs).
/// Alphabetical field order = the encrypted JSON's key order.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct StoredCredential {
    pub(crate) identity_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity_nullifier: Option<String>,
    pub(crate) identity_secret_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identity_trapdoor: Option<String>,
    /// Authoritative copy for post-decrypt cross-checks against the sidecar.
    pub(crate) registry_id: String,
}

// --------------------------------------------------------------------- store

pub(crate) struct Store {
    dir: PathBuf,
    file: KeystoreFile,
    session_password: Option<Zeroizing<String>>,
    /// membership_hash keys whose sidecar failed the load-time recomputation
    /// or the unlock-time allocation-state MAC — surfaced with failed_reason
    /// "metadata_tamper", never decrypted, never selected.
    quarantined: BTreeSet<String>,
    /// Sidecar-MAC key, derived once per unlock (see keystore.rs "Sidecar
    /// authentication"); cleared on lock alongside the password.
    meta_mac_key: Option<Zeroizing<[u8; 32]>>,
    /// Exclusive OS lock on the persistence dir's sentinel file, held for the
    /// store's lifetime (released on drop). Guards the whole-file-rewrite
    /// persistence against a second process on the same path.
    _dir_lock: std::fs::File,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

/// Tests swap the process-global STORE — they serialize on this and reset it.
#[cfg(test)]
pub(crate) static TEST_STORE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    *crate::lock(&STORE) = None;
}

/// Load (or create) the store. Called from `on_context_ready`; takes the
/// exclusive persistence-dir lock, then runs the tamper scan binding each
/// entry's sidecar to its membership_hash key.
pub(crate) fn init(dir: PathBuf) {
    let mut guard = crate::lock(&STORE);
    // Drop any prior store FIRST: its directory lock releases on drop, so an
    // in-process re-init (tests; a fresh on_context_ready) can reacquire —
    // OS file locks conflict between file descriptions even within one
    // process.
    *guard = None;
    let dir_lock = match acquire_dir_lock(&dir) {
        Ok(f) => f,
        Err(e) => {
            // Fail closed: two stores on one path would last-writer-wins
            // clobber each other's credentials and allocation counters.
            eprintln!(
                "store: could not take the exclusive keystore lock in {} ({e}); another \
                 process may be using this persistence path; leaving store uninitialized \
                 so every keystore op fails rather than corrupting shared state",
                dir.display()
            );
            return;
        }
    };
    let file = match keystore::load(&dir) {
        Ok(file) => file,
        Err(e) => {
            // Fail closed: leave the store UNINITIALIZED so every op errors,
            // rather than treating an unreadable file as an empty store —
            // which would invent a new secret over, then clobber, existing
            // credentials. The next launch retries the read.
            eprintln!(
                "store: keystore read failed ({e}); leaving store uninitialized to avoid \
                 clobbering existing credentials — resolve the fault and restart"
            );
            return;
        }
    };
    let mut quarantined = BTreeSet::new();
    for (hash, entry) in &file.credentials {
        let meta = &entry.membership;
        let recomputed = registry_id::hex_to_bytes32(&meta.identity_commitment)
            .map(|c| registry_id::membership_hash(&meta.registry_id, &c));
        if recomputed.as_deref() != Some(hash.as_str()) {
            eprintln!("store: entry {hash} fails membership_hash recomputation — quarantined");
            quarantined.insert(hash.clone());
        }
    }
    *guard = Some(Store {
        dir,
        file,
        session_password: None,
        quarantined,
        meta_mac_key: None,
        _dir_lock: dir_lock,
    });
}

/// Exclusive advisory lock on the persistence dir, via its sentinel file
/// (`keystore::LOCK_FILE`). Advisory: it stops a second WELL-BEHAVED module
/// instance, not an arbitrary writer, and network/shared-volume filesystems
/// may not honor it (see README).
fn acquire_dir_lock(dir: &std::path::Path) -> std::io::Result<std::fs::File> {
    logos_keystore_core::acquire_dir_lock(dir, keystore::LOCK_FILE)
}

/// Run `f` against the store; `internal` error when `init` never succeeded —
/// no persistence path from the host (no silent cwd fallback — see README),
/// an unreadable keystore, or another process holding the keystore lock.
pub(crate) fn with_store<R>(f: impl FnOnce(&mut Store) -> Result<R, ApiError>) -> Result<R, ApiError> {
    let mut guard = crate::lock(&STORE);
    match guard.as_mut() {
        Some(store) => f(store),
        None => Err(ApiError::internal(
            "store not initialized (no instance persistence path from the host, unreadable \
             keystore, or another process holds the keystore lock)",
        )),
    }
}

impl Store {
    /// Verify the password, then derive the sidecar-MAC key and authenticate
    /// every entry's reservation-critical state (quarantining a missing or
    /// mismatched MAC). Two 1M-round PBKDF2 runs — treat unlock as a
    /// ~seconds operation. The session fields are set only after every
    /// fallible step, so a failed unlock never leaves the store half
    /// unlocked.
    pub(crate) fn unlock(&mut self, password: &str) -> Result<usize, ApiError> {
        match self
            .file
            .credentials
            .iter()
            .find(|(hash, _)| !self.quarantined.contains(*hash))
        {
            Some((_, entry)) => match keystore::decrypt(password, &entry.crypto) {
                Ok(_) => {}
                Err(keystore::KeystoreError::BadPassword) => {
                    return Err(ApiError::new(
                        ErrorKind::BadPassword,
                        "password does not open the existing keystore",
                    ))
                }
                Err(e) => return Err(ApiError::internal(&format!("keystore decrypt: {e}"))),
            },
            // Refuse an all-quarantined store: with nothing to verify
            // against, ANY password would "unlock" vacuously and become the
            // session/MAC key.
            None if !self.file.credentials.is_empty() => {
                return Err(ApiError::internal(
                    "every keystore entry is quarantined (metadata tamper); restore \
                     rln_keystore.json from a backup",
                ))
            }
            // Empty keystore: any password unlocks and becomes the
            // encryption password at first write (see module docs).
            None => {}
        }

        // Sidecar authentication (see keystore.rs module docs). Every
        // non-empty keystore carries `metaMacSalt` and every entry is MAC'd
        // from birth (insert stamps it); there is no MAC-less shape to
        // adopt, so a missing salt over credentials is tamper or a foreign
        // writer, never a migration.
        let mut dirty = false;
        let salt = match &self.file.meta_mac_salt {
            Some(s) => s.clone(),
            None if !self.file.credentials.is_empty() => {
                return Err(ApiError::internal(
                    "metaMacSalt is missing from a non-empty keystore — the file was \
                     tampered with, partially restored, or written by a foreign tool; \
                     restore rln_keystore.json from a consistent backup",
                ))
            }
            // Empty keystore: initialize the salt at first unlock.
            None => {
                let mut raw = [0u8; 16];
                getrandom::getrandom(&mut raw)
                    .map_err(|_| ApiError::internal("no CSPRNG for the meta MAC salt"))?;
                let s = registry_id::bytes_to_hex(&raw);
                self.file.meta_mac_salt = Some(s.clone());
                dirty = true;
                s
            }
        };
        // A present-but-malformed salt fails closed (never regenerate — a
        // fresh salt would mass-quarantine every MAC'd entry).
        let key = keystore::derive_meta_mac_key(password, &salt).map_err(|e| {
            ApiError::internal(&format!(
                "meta MAC key: {e}; if metaMacSalt is corrupt, restore rln_keystore.json \
                 from a backup"
            ))
        })?;
        for (hash, entry) in &self.file.credentials {
            if self.quarantined.contains(hash) {
                continue;
            }
            // meta_mac_ok is false for an ABSENT MAC too: entries are MAC'd
            // from birth, so a missing tag is as much tamper as a mismatch.
            if !keystore::meta_mac_ok(&key, hash, &entry.membership) {
                eprintln!(
                    "store: entry {hash} sidecar allocation state is missing its MAC or \
                     fails verification — quarantined"
                );
                self.quarantined.insert(hash.clone());
            }
        }
        if dirty {
            self.persist()?;
        }
        self.session_password = Some(Zeroizing::new(password.to_string()));
        self.meta_mac_key = Some(key);
        Ok(self.file.credentials.len())
    }

    pub(crate) fn lock(&mut self) {
        self.session_password = None;
        self.meta_mac_key = None;
    }

    /// The active session password, if unlocked — a Zeroizing clone for
    /// keychain persistence (remember_keystore_password in keychain.rs).
    pub(crate) fn session_password(&self) -> Option<Zeroizing<String>> {
        self.session_password.clone()
    }

    /// True when unlock() would actually VERIFY a password (a non-quarantined
    /// envelope exists). Auto-unlock uses this to distinguish a fresh keystore
    /// from existing credentials that require the manual password.
    pub(crate) fn has_credentials(&self) -> bool {
        self.file
            .credentials
            .keys()
            .any(|hash| !self.quarantined.contains(hash))
    }

    /// Encrypt + insert a new (or re-registered) membership and persist —
    /// which stamps the sidecar MAC, so the entry is authenticated from
    /// birth. Unlock-gated: a locked insert would persist an unstamped
    /// entry that the next unlock quarantines.
    pub(crate) fn insert(
        &mut self,
        hash: &str,
        meta: MembershipMeta,
        credential: &StoredCredential,
    ) -> Result<(), ApiError> {
        let password = self.session_password.as_ref().ok_or_else(|| {
            ApiError::new(ErrorKind::Locked, "unlock_keystore before registering")
        })?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(credential)
                .map_err(|e| ApiError::internal(&format!("credential serialize: {e}")))?,
        );
        let crypto = keystore::encrypt(password, &plaintext)
            .map_err(|e| ApiError::internal(&format!("keystore encrypt: {e}")))?;
        if self.meta_mac_key.is_none() {
            return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before registering"));
        }
        self.file
            .credentials
            .insert(hash.to_string(), KeystoreEntry { crypto, membership: meta });
        self.quarantined.remove(hash);
        self.persist()
    }

    /// Decrypt one credential — the module's single plaintext release path.
    /// Cross-checks the plaintext's authoritative registry_id/commitment
    /// against the sidecar before releasing.
    pub(crate) fn decrypt_credential(&self, hash: &str) -> Result<StoredCredential, ApiError> {
        if self.quarantined.contains(hash) {
            return Err(ApiError::internal("entry quarantined (metadata tamper)"));
        }
        let password = self.session_password.as_ref().ok_or_else(|| {
            ApiError::new(ErrorKind::Locked, "unlock_keystore before selecting")
        })?;
        let entry = self.file.credentials.get(hash).ok_or_else(|| {
            ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash")
        })?;
        let plaintext = keystore::decrypt(password, &entry.crypto).map_err(|e| match e {
            keystore::KeystoreError::BadPassword => {
                ApiError::new(ErrorKind::BadPassword, "session password no longer opens this entry")
            }
            other => ApiError::internal(&format!("keystore decrypt: {other}")),
        })?;
        let credential: StoredCredential = serde_json::from_slice(&plaintext)
            .map_err(|e| ApiError::internal(&format!("credential parse: {e}")))?;
        if credential.registry_id != entry.membership.registry_id
            || credential.identity_commitment != entry.membership.identity_commitment
        {
            return Err(ApiError::internal(
                "credential/sidecar mismatch (metadata tamper)",
            ));
        }
        Ok(credential)
    }

    pub(crate) fn get(&self, hash: &str) -> Option<&MembershipMeta> {
        self.file.credentials.get(hash).map(|e| &e.membership)
    }

    /// The host-stamped persistence dir this store lives in — the anchor
    /// for sibling provisioning (wallet_home.rs).
    pub(crate) fn base_dir(&self) -> &std::path::Path {
        &self.dir
    }

    #[cfg(test)]
    pub(crate) fn is_quarantined(&self, hash: &str) -> bool {
        self.quarantined.contains(hash)
    }

    /// All records for one canonical registry_id, as [`MembershipRecord`]s.
    pub(crate) fn records_for(&self, canonical_registry: &str) -> Vec<MembershipRecord> {
        self.file
            .credentials
            .iter()
            .filter(|(_, e)| e.membership.registry_id == canonical_registry)
            .map(|(h, e)| MembershipRecord {
                hash: h.clone(),
                meta: e.membership.clone(),
                quarantined: self.quarantined.contains(h),
            })
            .collect()
    }

    /// The poller's confirmation work list: every non-quarantined record in
    /// state `pending`, with its metadata snapshot.
    pub(crate) fn pending_records(&self) -> Vec<(String, MembershipMeta)> {
        self.file
            .credentials
            .iter()
            .filter(|(h, e)| {
                e.membership.cache.state == MembershipState::Pending
                    && !self.quarantined.contains(*h)
            })
            .map(|(h, e)| (h.clone(), e.membership.clone()))
            .collect()
    }

    /// The state-refresh work list: records a registry transition can still
    /// move (active → grace_period → expired, or vanish → erased).
    pub(crate) fn refreshable_records(&self) -> Vec<(String, MembershipMeta)> {
        self.file
            .credentials
            .iter()
            .filter(|(h, e)| {
                !self.quarantined.contains(*h)
                    && matches!(
                        e.membership.cache.state,
                        MembershipState::Active | MembershipState::GracePeriod | MembershipState::Expired
                    )
            })
            .map(|(h, e)| (h.clone(), e.membership.clone()))
            .collect()
    }

    /// Run a cache-only mutation against an entry and persist. The closure
    /// receives `CacheState` ONLY — MAC-covered allocation state is not
    /// reachable here by construction; the sole covered-mutation path is
    /// `reserve_message_id`.
    pub(crate) fn update_cache(
        &mut self,
        hash: &str,
        f: impl FnOnce(&mut CacheState),
    ) -> Result<(), ApiError> {
        let entry = self.file.credentials.get_mut(hash).ok_or_else(|| {
            ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash")
        })?;
        let cache = &mut entry.membership.cache;
        let before = cache.state;
        f(cache);
        if cache.state != before {
            cache.state_history.push(StateChange {
                at: crate::now_unix(),
                state: cache.state,
            });
            if cache.state_history.len() > STATE_HISTORY_CAP {
                let drop_n = cache.state_history.len() - STATE_HISTORY_CAP;
                cache.state_history.drain(..drop_n);
            }
        }
        self.persist()
    }

    /// Reserve the next `message_id` for `(membership, rln_identifier, epoch)`
    /// and durably persist it before returning — the caller uses the slot only
    /// after this call succeeds, so a crash can waste a slot but never reissue
    /// one. Requires an unlocked keystore (the sidecar MAC key derives from
    /// the session password).
    ///
    /// `BudgetExhausted` when the epoch's `rate_limit` is spent. `Permanent`
    /// when `epoch` is below the persisted allocation floor, or when
    /// `epoch_size_sec` differs from the size this membership's allocations
    /// are bound to (an epoch-size change is not migratable — see
    /// `AllocationState::epoch_size_sec`); recovery is a fresh membership.
    pub(crate) fn reserve_message_id(
        &mut self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        retain_floor: u64,
        rate_limit: u64,
        epoch_size_sec: u64,
    ) -> Result<u64, ApiError> {
        // Guards FIRST — a refused call must leave the counters untouched,
        // and a quarantined entry's counters are untrusted: refuse before
        // any mutation (persist would also skip its restamp).
        if self.quarantined.contains(hash) {
            return Err(ApiError::internal("entry quarantined (metadata tamper)"));
        }
        if self.meta_mac_key.is_none() {
            return Err(ApiError::new(
                ErrorKind::Locked,
                "unlock_keystore before generate_proof",
            ));
        }
        let entry = self.file.credentials.get_mut(hash).ok_or_else(|| {
            ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash")
        })?;
        let meta = &mut entry.membership;
        if meta.alloc.epoch_size_sec != 0 && meta.alloc.epoch_size_sec != epoch_size_sec {
            return Err(ApiError::new(
                ErrorKind::Permanent,
                &format!(
                    "configured epoch_size_sec {epoch_size_sec} differs from {} — the size this \
                     membership's allocations are bound to; a rebased epoch numbering could \
                     reissue spent slots. Register a fresh membership under the new size",
                    meta.alloc.epoch_size_sec
                ),
            ));
        }
        let slot = crate::rate_limit::reserve_slot(
            &mut meta.alloc,
            rln_identifier_hex,
            epoch,
            retain_floor,
            rate_limit,
        )
        .map_err(|e| match e {
            crate::rate_limit::AllocError::BudgetExhausted => ApiError::new(
                ErrorKind::BudgetExhausted,
                "epoch rate-limit budget exhausted; retry next epoch",
            ),
            crate::rate_limit::AllocError::EpochBelowFloor => ApiError::new(
                ErrorKind::Permanent,
                "epoch is below the persisted allocation floor (backwards clock step or a \
                 widened max_epoch_gap re-admitted a pruned epoch); refusing to reissue a \
                 possibly spent slot",
            ),
        })?;
        meta.alloc.epoch_size_sec = epoch_size_sec; // adopt-on-first-success
        // On persist failure the counter/floor deliberately stay advanced:
        // no proof is issued, so the slot can only be WASTED, never reissued.
        self.persist()?;
        Ok(slot)
    }

    /// Every entry's persisted epoch-size binding (0 = not yet bound) — the
    /// input to `start()`'s configure-time mismatch warning.
    pub(crate) fn epoch_size_bindings(&self) -> Vec<(String, u64)> {
        self.file
            .credentials
            .iter()
            .map(|(h, e)| (h.clone(), e.membership.alloc.epoch_size_sec))
            .collect()
    }

    /// Remaining slots for `(membership, rln_identifier, epoch)` — the quota
    /// read's current-epoch budget. Read-only. Mirrors the reserve path's
    /// permanent refusals: an epoch below the persisted floor, or a
    /// configured epoch size the membership isn't bound to, reports 0 — the
    /// wire contract's fallback cue — instead of advertising slots
    /// `reserve_message_id` will refuse.
    pub(crate) fn remaining_budget(
        &self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        rate_limit: u64,
        epoch_size_sec: u64,
    ) -> u64 {
        self.file
            .credentials
            .get(hash)
            .map(|e| {
                let alloc = &e.membership.alloc;
                if alloc.epoch_size_sec != 0 && alloc.epoch_size_sec != epoch_size_sec {
                    return 0;
                }
                if epoch < alloc.prune_floor {
                    return 0;
                }
                crate::rate_limit::remaining(&alloc.allocations, rln_identifier_hex, epoch, rate_limit)
            })
            .unwrap_or(0)
    }

    /// Serialize + durably persist the keystore — the SINGLE MAC-stamping
    /// site. When unlocked, every non-quarantined entry's `allocations_mac`
    /// is recomputed here (quarantined entries are never restamped: a fresh
    /// MAC over tampered state would launder it). While locked, entries are
    /// written with their stored MACs unchanged — covered state cannot
    /// change while locked, since `update_cache` is cache-only by type and
    /// `reserve_message_id` is unlock-gated.
    fn persist(&mut self) -> Result<(), ApiError> {
        if let Some(key) = self.meta_mac_key.as_ref() {
            for (hash, entry) in &mut self.file.credentials {
                if self.quarantined.contains(hash) {
                    continue;
                }
                entry.membership.allocations_mac =
                    Some(keystore::meta_mac(key, hash, &entry.membership.alloc));
            }
        }
        keystore::save_atomic(&self.dir, &self.file)
            .map_err(|e| ApiError::internal(&format!("keystore save: {e}")))
    }
}

// -------------------------------------------------------------- merged state

/// True once a record has ever been observed on the registry — the spec's
/// "state becomes Unknown after having been Active" removal signal.
fn has_been_active(meta: &MembershipMeta) -> bool {
    meta.cache.state.is_active_like()
        || meta.cache.state_history.iter().any(|c| c.state.is_active_like())
}

/// The spec's merged view, as a pure function: the registry's report
/// (`Some(state)` / `None` = not present) overlaid on the local record.
/// Callers persist any transition this implies (pending→failed, →erased).
pub(crate) fn merge_state(
    local: Option<&MembershipMeta>,
    registry_state: Option<MembershipState>,
    now: u64,
) -> MembershipState {
    match (local, registry_state) {
        (None, None) => MembershipState::Unknown,
        // The registry has it: its chain-clock view wins outright.
        (_, Some(state)) => state,
        (Some(meta), None) => {
            if meta.cache.state == MembershipState::Pending {
                if now.saturating_sub(meta.cache.submitted_at) > CONFIRMATION_WINDOW_SECS {
                    MembershipState::Failed
                } else {
                    MembershipState::Pending
                }
            } else if has_been_active(meta) {
                MembershipState::Erased
            } else {
                // failed stays failed (visible until re-registered).
                meta.cache.state
            }
        }
    }
}

/// The `membership_state_changed` event's args, or `None` when `new_state`
/// equals the current state (re-observations — every poller tick and read —
/// must NOT emit). `meta` is the PRE-transition record, so `previous` is the
/// state held just before the change; an empty (legacy) `rln_identifier`
/// carries through verbatim.
pub(crate) fn transition_event(
    hash: &str,
    meta: &MembershipMeta,
    new_state: MembershipState,
) -> Option<(String, String, String, String, String)> {
    if new_state == meta.cache.state {
        return None;
    }
    // Enum→wire string: serde's `rename_all = "snake_case"` on
    // MembershipState is the single source of truth for the wire strings.
    let wire = |s: MembershipState| {
        serde_json::to_value(s)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    };
    Some((
        meta.registry_id.clone(),
        meta.rln_identifier.clone(),
        hash.to_string(),
        wire(new_state),
        wire(meta.cache.state),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(state: MembershipState, submitted_at: u64) -> MembershipMeta {
        MembershipMeta {
            alloc: AllocationState::default(),
            allocations_mac: None,
            cache: CacheState {
                failed_reason: None,
                leaf_index: 7,
                rate_limit: 300,
                retryable: None,
                state,
                state_history: vec![],
                submitted_at,
                tx_result: None,
            },
            identity_commitment: "11".repeat(32),
            registry_id: format!("logos:local:{}", "ab".repeat(32)),
            rln_identifier: String::new(),
        }
    }

    #[test]
    fn merge_state_matrix() {
        use MembershipState::*;
        let now = 10_000;
        // No local record.
        assert_eq!(merge_state(None, None, now), Unknown);
        assert_eq!(merge_state(None, Some(Active), now), Active);
        // Pending inside/outside the confirmation window.
        let fresh = meta(Pending, now - 10);
        assert_eq!(merge_state(Some(&fresh), None, now), Pending);
        let stale = meta(Pending, now - CONFIRMATION_WINDOW_SECS - 1);
        assert_eq!(merge_state(Some(&stale), None, now), Failed);
        // Registry view wins when present.
        assert_eq!(merge_state(Some(&stale), Some(GracePeriod), now), GracePeriod);
        // Failed stays failed while absent.
        let failed = meta(Failed, now - 1_000);
        assert_eq!(merge_state(Some(&failed), None, now), Failed);
        // Was active, now gone from the registry → inferred erased.
        let was_active = meta(Active, now - 1_000);
        assert_eq!(merge_state(Some(&was_active), None, now), Erased);
        let mut expired_history = meta(Failed, now - 1_000);
        expired_history.cache.state_history.push(StateChange {
            at: now - 500,
            state: Expired,
        });
        assert_eq!(merge_state(Some(&expired_history), None, now), Erased);
    }

    #[test]
    fn transition_event_gates_on_actual_state_change() {
        use MembershipState::*;
        // A mere re-observation of the same state must not emit.
        let active = meta(Active, 0);
        assert!(transition_event("h", &active, Active).is_none());

        // pending -> active: previous carries the pre-transition state.
        let pending = meta(Pending, 0);
        let (registry_id, rln_identifier, hash, state, previous) =
            transition_event("h1", &pending, Active).expect("real transition");
        assert_eq!(registry_id, pending.registry_id);
        assert_eq!(rln_identifier, "");
        assert_eq!(hash, "h1");
        assert_eq!(state, "active");
        assert_eq!(previous, "pending");

        // A scoped record's rln_identifier is carried through verbatim.
        let mut scoped = meta(Pending, 0);
        scoped.rln_identifier = "ab".repeat(32);
        let (_, rln_identifier, ..) =
            transition_event("h2", &scoped, Failed).expect("real transition");
        assert_eq!(rln_identifier, scoped.rln_identifier);
    }

    fn test_store(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rln-ms-store-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn init_quarantines_metadata_tamper_and_unlock_verifies() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("quarantine");
        init(dir.clone());

        // Insert one good record through the store.
        let registry = format!("logos:local:{}", "cd".repeat(32));
        let commitment = [0x22u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        let credential = StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(&commitment),
            identity_nullifier: None,
            identity_secret_hash: "33".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.clone(),
        };
        with_store(|s| {
            s.unlock("pw")?;
            let mut m = meta(MembershipState::Pending, crate::now_unix());
            m.registry_id = registry.clone();
            m.identity_commitment = credential.identity_commitment.clone();
            s.insert(&hash, m, &credential)
        })
        .unwrap();

        // Tamper the sidecar registry_id on disk, then re-init: quarantined.
        // With every entry quarantined, unlock refuses outright — a vacuous
        // password match would otherwise adopt ANY password as the session
        // key.
        let path = dir.join(keystore::KEYSTORE_FILE);
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("logos:local:", "logos:evil0:");
        std::fs::write(&path, tampered).unwrap();
        init(dir.clone());
        with_store(|s| {
            assert!(s.is_quarantined(&hash), "tampered entry must be quarantined");
            let denied = s.unlock("pw");
            assert!(
                matches!(denied, Err(ref e) if e.message.contains("quarantined")),
                "an all-quarantined store must refuse every password: {denied:?}"
            );
            assert!(s.decrypt_credential(&hash).is_err());
            Ok(())
        })
        .unwrap();

        // Wrong password against a real envelope is rejected. Restore the
        // honest file first (quarantined entries can't verify anything).
        let honest = std::fs::read_to_string(&path)
            .unwrap()
            .replace("logos:evil0:", "logos:local:");
        std::fs::write(&path, honest).unwrap();
        init(dir.clone());
        let bad = with_store(|s| s.unlock("not-pw"));
        assert!(matches!(bad, Err(e) if e.kind == ErrorKind::BadPassword));
        // Right password decrypts and cross-checks.
        with_store(|s| {
            s.unlock("pw")?;
            let released = s.decrypt_credential(&hash)?;
            assert_eq!(released.identity_secret_hash, "33".repeat(32));
            Ok(())
        })
        .unwrap();

        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_locker_fails_closed_until_released() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("lock");
        std::fs::create_dir_all(&dir).unwrap();
        // Simulate a second process: hold the sentinel lock on a separate
        // file description (OS file locks conflict between descriptions even
        // within one process — the same conflict a real second process hits).
        let foreign = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(keystore::LOCK_FILE))
            .unwrap();
        foreign.try_lock().unwrap();

        init(dir.clone());
        let denied = with_store(|_| Ok(()));
        assert!(
            matches!(denied, Err(ref e) if e.message.contains("keystore lock")),
            "init under a foreign lock must fail closed: {denied:?}"
        );

        // Release the foreign lock: init succeeds and the store operates.
        foreign.unlock().unwrap();
        drop(foreign);
        init(dir.clone());
        with_store(|_| Ok(())).unwrap();

        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reservation_floor_and_epoch_size_survive_restart() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("floor");
        init(dir.clone());
        let registry = format!("logos:local:{}", "aa".repeat(32));
        let commitment = [0x66u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        let credential = StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(&commitment),
            identity_nullifier: None,
            identity_secret_hash: "77".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.clone(),
        };
        with_store(|s| {
            s.unlock("pw")?;
            let mut m = meta(MembershipState::Active, crate::now_unix());
            m.registry_id = registry.clone();
            m.identity_commitment = credential.identity_commitment.clone();
            s.insert(&hash, m, &credential)
        })
        .unwrap();

        // Reserve in epoch 10, then in epoch 12 with the window floor at 11 —
        // the second reservation prunes epoch 10's spent row and records
        // floor 11, all under epoch_size 600.
        assert_eq!(
            with_store(|s| s.reserve_message_id(&hash, "aa", 10, 9, 5, 600)).unwrap(),
            0
        );
        assert_eq!(
            with_store(|s| s.reserve_message_id(&hash, "aa", 12, 11, 5, 600)).unwrap(),
            0
        );

        // Restart: reload everything from disk (and unlock — reservation
        // needs the sidecar-MAC key).
        init(dir.clone());
        with_store(|s| s.unlock("pw").map(|_| ())).unwrap();

        // Audit cause B/D: a rewound (or gap-widened) window re-admits pruned
        // epoch 10, but the persisted floor must refuse it instead of
        // reissuing slot 0.
        let rewound = with_store(|s| s.reserve_message_id(&hash, "aa", 10, 9, 5, 600));
        assert!(matches!(rewound, Err(e) if e.kind == ErrorKind::Permanent));
        // Epoch 12 continues its persisted counter — slot 1, never a fresh 0.
        assert_eq!(
            with_store(|s| s.reserve_message_id(&hash, "aa", 12, 11, 5, 600)).unwrap(),
            1
        );
        // A different epoch_size_sec rebases the epoch numbering: permanently refused.
        let rebased = with_store(|s| s.reserve_message_id(&hash, "aa", 12, 11, 5, 1200));
        assert!(matches!(rebased, Err(e) if e.kind == ErrorKind::Permanent));

        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// persist() is the single MAC-stamping site, and while LOCKED it must
    /// write entries with their stored MACs unchanged: a locked-mode cache
    /// persist (the poller's path) must never invalidate an honest entry.
    #[test]
    fn locked_cache_updates_do_not_disturb_the_mac() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("locked-cache-mac");
        init(dir.clone());
        let registry = format!("logos:local:{}", "cc".repeat(32));
        let commitment = [0x61u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        let credential = StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(&commitment),
            identity_nullifier: None,
            identity_secret_hash: "77".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.clone(),
        };
        with_store(|s| {
            s.unlock("pw")?;
            let mut m = meta(MembershipState::Active, crate::now_unix());
            m.registry_id = registry.clone();
            m.identity_commitment = registry_id::bytes_to_hex(&commitment);
            s.insert(&hash, m, &credential)?;
            // Cover live allocation state so the MAC is not over defaults.
            s.reserve_message_id(&hash, "aa", 10, 9, 5, 600).map(|_| ())?;
            s.lock();
            // Locked-mode cache mutation persists without touching the MAC.
            s.update_cache(&hash, |c| c.leaf_index = 7)
        })
        .unwrap();
        // Reload from disk: the entry must still verify (not quarantined)
        // and carry the cache change.
        init(dir.clone());
        with_store(|s| {
            s.unlock("pw")?;
            assert!(!s.is_quarantined(&hash), "locked persist must not disturb the MAC");
            Ok(())
        })
        .unwrap();
        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_sidecar_allocations_are_quarantined() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("meta-mac");
        init(dir.clone());
        let registry = format!("logos:local:{}", "bb".repeat(32));
        let commitment_a = [0x51u8; 32];
        let commitment_b = [0x52u8; 32];
        let hash_a = registry_id::membership_hash(&registry, &commitment_a);
        let hash_b = registry_id::membership_hash(&registry, &commitment_b);
        let cred = |c: &[u8; 32]| StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(c),
            identity_nullifier: None,
            identity_secret_hash: "66".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.clone(),
        };
        with_store(|s| {
            s.unlock("pw")?;
            for (h, c) in [(&hash_a, &commitment_a), (&hash_b, &commitment_b)] {
                let mut m = meta(MembershipState::Active, crate::now_unix());
                m.registry_id = registry.clone();
                m.identity_commitment = registry_id::bytes_to_hex(c);
                s.insert(h, m, &cred(c))?;
            }
            // Spend a slot on A so its MAC covers live allocation state.
            s.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).map(|_| ())
        })
        .unwrap();

        // The audit's cause-C attack: rewind A's spent counter on disk
        // (file-write access, no password). The next unlock must quarantine
        // A; untampered B stays usable.
        let path = dir.join(keystore::KEYSTORE_FILE);
        let honest = std::fs::read_to_string(&path).unwrap();
        let tampered = honest.replace("\"used\": 1", "\"used\": 0");
        assert_ne!(honest, tampered, "the tamper must hit a spent counter");
        std::fs::write(&path, tampered).unwrap();
        init(dir.clone());
        with_store(|s| {
            s.unlock("pw")?;
            assert!(s.is_quarantined(&hash_a), "rewound counter must quarantine");
            assert!(!s.is_quarantined(&hash_b), "untampered sibling stays usable");
            assert!(s.decrypt_credential(&hash_a).is_err());
            assert!(s.decrypt_credential(&hash_b).is_ok());
            Ok(())
        })
        .unwrap();

        // Deleting just one entry's MAC (keeping the rewound state and the
        // file's salt) must be DETECTED: entries are MAC'd from birth, so a
        // missing tag is tamper.
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v["credentials"][hash_a.as_str()]["membership"]
            .as_object_mut()
            .unwrap()
            .remove("allocations_mac");
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        init(dir.clone());
        with_store(|s| {
            s.unlock("pw")?;
            assert!(s.is_quarantined(&hash_a), "a stripped MAC must quarantine");
            assert!(!s.is_quarantined(&hash_b));
            Ok(())
        })
        .unwrap();

        // Stripping the salt from a non-empty keystore must refuse unlock
        // loudly (restore-from-backup guidance) — with or without entry MACs
        // remaining: there is no MAC-less legacy shape to fall back to.
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("metaMacSalt");
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        init(dir.clone());
        with_store(|s| {
            let denied = s.unlock("pw");
            assert!(
                matches!(denied, Err(ref e) if e.message.contains("metaMacSalt")),
                "salt strip with MACs present must fail unlock: {denied:?}"
            );
            Ok(())
        })
        .unwrap();

        // Stripping the salt together with EVERY entry's MAC used to reach
        // an adoptable legacy shape (the old accepted residual 3); with
        // legacy adoption gone it must refuse unlock exactly like the
        // partial strip above.
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("metaMacSalt");
        for (_, entry) in v["credentials"].as_object_mut().unwrap() {
            entry["membership"].as_object_mut().unwrap().remove("allocations_mac");
        }
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        init(dir.clone());
        with_store(|s| {
            let denied = s.unlock("pw");
            assert!(
                matches!(denied, Err(ref e) if e.message.contains("metaMacSalt")),
                "full salt+MAC strip must refuse unlock, never re-adopt: {denied:?}"
            );
            Ok(())
        })
        .unwrap();

        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_tracks_history_with_cap() {
        let _serial = crate::lock(&TEST_STORE_LOCK);
        let dir = test_store("history");
        init(dir.clone());
        let registry = format!("logos:local:{}", "ef".repeat(32));
        let commitment = [0x44u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        let credential = StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(&commitment),
            identity_nullifier: None,
            identity_secret_hash: "55".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.clone(),
        };
        with_store(|s| {
            s.unlock("pw")?;
            let mut m = meta(MembershipState::Pending, crate::now_unix());
            m.registry_id = registry.clone();
            m.identity_commitment = credential.identity_commitment.clone();
            s.insert(&hash, m, &credential)?;
            for i in 0..(STATE_HISTORY_CAP + 5) {
                let next = if i % 2 == 0 { MembershipState::Active } else { MembershipState::GracePeriod };
                s.update_cache(&hash, |m| m.state = next)?;
            }
            let meta = s.get(&hash).unwrap();
            assert_eq!(meta.cache.state_history.len(), STATE_HISTORY_CAP);
            // Unchanged state must NOT append history.
            let len_before = meta.cache.state_history.len();
            s.update_cache(&hash, |m| m.leaf_index = 42)?;
            assert_eq!(s.get(&hash).unwrap().cache.state_history.len(), len_before);
            assert_eq!(s.get(&hash).unwrap().cache.leaf_index, 42);
            Ok(())
        })
        .unwrap();
        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
