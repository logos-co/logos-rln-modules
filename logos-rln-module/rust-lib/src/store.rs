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
pub(crate) use crate::keystore::{MembershipMeta, MembershipState, StateChange};

/// Pending→Failed bound (spec MUST). Testnet confirmation runs 60–90s;
/// 300s leaves margin.
pub(crate) const CONFIRMATION_WINDOW_SECS: u64 = 300;
const STATE_HISTORY_CAP: usize = 20;

// ------------------------------------------------------------------- records

impl MembershipMeta {
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
    /// — surfaced with failed_reason "metadata_tamper", never decrypted,
    /// never selected.
    quarantined: BTreeSet<String>,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

/// Tests swap the process-global STORE — they serialize on this and reset it.
#[cfg(test)]
pub(crate) static TEST_STORE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    *crate::lock(&STORE) = None;
}

/// Load (or create) the store. Called from `on_context_ready`; runs the
/// tamper scan binding each entry's sidecar to its membership_hash key.
pub(crate) fn init(dir: PathBuf) {
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
            *crate::lock(&STORE) = None;
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
    *crate::lock(&STORE) = Some(Store {
        dir,
        file,
        session_password: None,
        quarantined,
    });
}

/// Run `f` against the store; `internal` error when no persistence path was
/// provided at context time (no silent cwd fallback — see README).
pub(crate) fn with_store<R>(f: impl FnOnce(&mut Store) -> Result<R, ApiError>) -> Result<R, ApiError> {
    let mut guard = crate::lock(&STORE);
    match guard.as_mut() {
        Some(store) => f(store),
        None => Err(ApiError::internal(
            "store not initialized (host provided no instance persistence path)",
        )),
    }
}

impl Store {
    pub(crate) fn unlock(&mut self, password: &str) -> Result<usize, ApiError> {
        if let Some(entry) = self
            .file
            .credentials
            .iter()
            .find(|(hash, _)| !self.quarantined.contains(*hash))
            .map(|(_, e)| e)
        {
            match keystore::decrypt(password, &entry.crypto) {
                Ok(_) => {}
                Err(keystore::KeystoreError::BadPassword) => {
                    return Err(ApiError::new(
                        ErrorKind::BadPassword,
                        "password does not open the existing keystore",
                    ))
                }
                Err(e) => return Err(ApiError::internal(&format!("keystore decrypt: {e}"))),
            }
        }
        self.session_password = Some(Zeroizing::new(password.to_string()));
        Ok(self.file.credentials.len())
    }

    pub(crate) fn lock(&mut self) {
        self.session_password = None;
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

    /// Encrypt + insert a new (or re-registered) membership and persist.
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
            .filter(|(h, e)| e.membership.state == MembershipState::Pending && !self.quarantined.contains(*h))
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
                        e.membership.state,
                        MembershipState::Active | MembershipState::GracePeriod | MembershipState::Expired
                    )
            })
            .map(|(h, e)| (h.clone(), e.membership.clone()))
            .collect()
    }

    /// Mutate one record's metadata and persist. State changes go through
    /// here so history stays consistent: pass the new state via
    /// `MembershipMeta::state`; history appends automatically on change.
    pub(crate) fn update(
        &mut self,
        hash: &str,
        f: impl FnOnce(&mut MembershipMeta),
    ) -> Result<(), ApiError> {
        let entry = self.file.credentials.get_mut(hash).ok_or_else(|| {
            ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash")
        })?;
        let before = entry.membership.state;
        f(&mut entry.membership);
        if entry.membership.state != before {
            entry.membership.state_history.push(StateChange {
                at: crate::now_unix(),
                state: entry.membership.state,
            });
            if entry.membership.state_history.len() > STATE_HISTORY_CAP {
                let drop_n = entry.membership.state_history.len() - STATE_HISTORY_CAP;
                entry.membership.state_history.drain(..drop_n);
            }
        }
        self.persist()
    }

    /// Reserve the next `message_id` for `(membership, rln_identifier, epoch)`
    /// and DURABLY PERSIST it before returning — the caller uses the slot only
    /// after this call succeeds, so a crash can waste a slot but never reissue
    /// one. No unlock needed: allocations live in the plaintext
    /// sidecar. `BudgetExhausted` when the epoch's `rate_limit` is spent.
    pub(crate) fn reserve_message_id(
        &mut self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        retain_floor: u64,
        rate_limit: u64,
    ) -> Result<u64, ApiError> {
        let entry = self.file.credentials.get_mut(hash).ok_or_else(|| {
            ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash")
        })?;
        let slot = crate::rate_limit::reserve_slot(
            &mut entry.membership.allocations,
            rln_identifier_hex,
            epoch,
            retain_floor,
            rate_limit,
        )
        .map_err(|_| {
            ApiError::new(
                ErrorKind::BudgetExhausted,
                "epoch rate-limit budget exhausted; retry next epoch",
            )
        })?;
        self.persist()?;
        Ok(slot)
    }

    /// Remaining slots for `(membership, rln_identifier, epoch)` — the quota
    /// read's current-epoch budget. Read-only.
    pub(crate) fn remaining_budget(
        &self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        rate_limit: u64,
    ) -> u64 {
        self.file
            .credentials
            .get(hash)
            .map(|e| {
                crate::rate_limit::remaining(
                    &e.membership.allocations,
                    rln_identifier_hex,
                    epoch,
                    rate_limit,
                )
            })
            .unwrap_or(0)
    }

    fn persist(&self) -> Result<(), ApiError> {
        keystore::save_atomic(&self.dir, &self.file)
            .map_err(|e| ApiError::internal(&format!("keystore save: {e}")))
    }
}

// -------------------------------------------------------------- merged state

/// True once a record has ever been observed on the registry — the spec's
/// "state becomes Unknown after having been Active" removal signal.
fn has_been_active(meta: &MembershipMeta) -> bool {
    meta.state.is_active_like() || meta.state_history.iter().any(|c| c.state.is_active_like())
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
            if meta.state == MembershipState::Pending {
                if now.saturating_sub(meta.submitted_at) > CONFIRMATION_WINDOW_SECS {
                    MembershipState::Failed
                } else {
                    MembershipState::Pending
                }
            } else if has_been_active(meta) {
                MembershipState::Erased
            } else {
                // failed stays failed (visible until re-registered).
                meta.state
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
    if new_state == meta.state {
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
        wire(meta.state),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(state: MembershipState, submitted_at: u64) -> MembershipMeta {
        MembershipMeta {
            allocations: Vec::new(),
            failed_reason: None,
            identity_commitment: "11".repeat(32),
            leaf_index: 7,
            rate_limit: 300,
            registry_id: format!("logos:local:{}", "ab".repeat(32)),
            retryable: None,
            rln_identifier: String::new(),
            state,
            state_history: vec![],
            submitted_at,
            tx_result: None,
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
        expired_history.state_history.push(StateChange {
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
        let path = dir.join(keystore::KEYSTORE_FILE);
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("logos:local:", "logos:evil0:");
        std::fs::write(&path, tampered).unwrap();
        init(dir.clone());
        with_store(|s| {
            assert!(s.is_quarantined(&hash), "tampered entry must be quarantined");
            s.unlock("pw")?; // verification skips quarantined entries
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
                s.update(&hash, |m| m.state = next)?;
            }
            let meta = s.get(&hash).unwrap();
            assert_eq!(meta.state_history.len(), STATE_HISTORY_CAP);
            // Unchanged state must NOT append history.
            let len_before = meta.state_history.len();
            s.update(&hash, |m| m.leaf_index = 42)?;
            assert_eq!(s.get(&hash).unwrap().state_history.len(), len_before);
            assert_eq!(s.get(&hash).unwrap().leaf_index, 42);
            Ok(())
        })
        .unwrap();
        reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
