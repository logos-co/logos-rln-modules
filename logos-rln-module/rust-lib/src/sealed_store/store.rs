//! The sealed-store runtime: session state over the format/crypto/fs layers —
//! open-time census, unlock-time keyed verification, credential sealing, the
//! MAC-covered allocation ledger, the plaintext cache sidecar, and the
//! persist-before-issue `message_id` reservation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use zeroize::Zeroizing;

use crate::lifecycle::{
    CacheFile, CacheState, MembershipRecord, MembershipState, StoredCredential, FORMAT_CACHE,
};
use crate::rate_limit::{remaining, reserve_slot, AllocError, AllocationState, EpochAllocation};
use crate::registry_id;
use crate::sealed_store::crypto::{self, KdfParams, MasterKey, SubKeys};
use crate::sealed_store::format::{
    self, AllocRow, AllocationsFile, IdentityBlock, SealedEntry, SealedFile, Section,
};
use crate::sealed_store::fs;
use crate::sealed_store::hex::{bytes_to_hex, hex_to_vec};
use crate::{ApiError, ErrorKind};

// ------------------------------------------------------------------- opening

/// Why `open` refused. Each message later travels inside a kind=internal
/// `ApiError`, so the text carries the whole diagnosis on its own.
#[derive(Debug)]
pub enum OpenError {
    /// The host stamped no instance persistence path (constructed by the
    /// caller — `open` itself always receives a dir).
    NoPersistencePath(String),
    DirLockHeld(String),
    OldFormatPresent(String),
    Unreadable(String),
}

impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OpenError::NoPersistencePath(m)
            | OpenError::DirLockHeld(m)
            | OpenError::OldFormatPresent(m)
            | OpenError::Unreadable(m) => f.write_str(m),
        }
    }
}

// ------------------------------------------------------------ published slot

/// The published store for worker loops (poller, keychain auto-unlock): a
/// Weak so a published-but-closed store can actually drop.
static CURRENT: Mutex<Weak<Store>> = Mutex::new(Weak::new());

pub(crate) fn publish(store: Option<&Arc<Store>>) {
    *crate::lock(&CURRENT) = store.map_or_else(Weak::new, Arc::downgrade);
}

pub(crate) fn current() -> Option<Arc<Store>> {
    crate::lock(&CURRENT).upgrade()
}

/// The refusal every keystore op surfaces when no store was ever opened —
/// no persistence path from the host (no silent cwd fallback — see README),
/// an unreadable keystore, or another process holding the keystore lock.
pub(crate) const UNINIT_MSG: &str =
    "store not initialized (no instance persistence path from the host, unreadable \
     keystore, or another process holds the keystore lock)";

/// The published store, or the uninitialized `internal` error.
pub(crate) fn current_or_uninit() -> Result<Arc<Store>, ApiError> {
    current().ok_or_else(|| ApiError::internal(UNINIT_MSG))
}

// -------------------------------------------------------------------- state

/// The unlocked session: the password (re-releasable for keychain
/// persistence) and the sub-keys derived from it. Dropped whole on `lock`.
struct Session {
    password: Zeroizing<String>,
    keys: SubKeys,
}

struct Inner {
    /// `None` until the first unlock provisions the sealed file.
    sealed: Option<SealedFile>,
    store_uuid: Option<[u8; 16]>,
    /// The live allocation ledger, one entry per credentialed membership.
    sections: BTreeMap<String, AllocationState>,
    cache: BTreeMap<String, CacheState>,
    /// Failed the unkeyed open-time census (membership_hash recomputation,
    /// missing/foreign allocations) — never unsealed, never verified.
    census_quarantined: BTreeSet<String>,
    /// Failed unlock-time keyed verification (credential AEAD, section MAC,
    /// root splice) — rebuilt from scratch on every unlock.
    keyed_quarantined: BTreeSet<String>,
    session: Option<Session>,
    /// Sections and root exactly as loaded (or last written): the unlock-time
    /// MAC-verification input. Orphan sections stay here — a crash-orphaned
    /// section is still covered by the root it was written under.
    raw_sections: BTreeMap<String, Section>,
    root_mac_raw: Option<[u8; 32]>,
    /// Exclusive OS lock on the persistence dir's sentinel; taken out by
    /// `close` for deterministic release ahead of a re-open.
    lock: Option<std::fs::File>,
}

/// The read-only publication: identity + cache + alloc + quarantine clones.
struct Snapshot {
    records: BTreeMap<String, MembershipRecord>,
    has_credentials: bool,
}

pub struct Store {
    dir: PathBuf,
    // CONCURRENCY RULE: every mutation runs under this ONE mutex across its
    // full mutate → persist → snapshot-swap; reserve mutates the
    // authoritative Inner state, never snapshot-derived values; the snapshot
    // is a read-only publication (readers clone the Arc, never wait on
    // fsync).
    write: Mutex<Inner>,
    snapshot: Mutex<Arc<Snapshot>>,
}

impl Store {
    /// Open (never create-then-write: the first unlock provisions) the store
    /// in `dir`: refuse an old-format dir, take the exclusive dir lock, load
    /// the three files with pre-unlock caps, and run the unkeyed census.
    pub fn open(dir: PathBuf) -> Result<Arc<Store>, OpenError> {
        match format::detect(&dir) {
            format::FormatPresence::OldOnly => {
                return Err(OpenError::OldFormatPresent(
                    "an old-format RLN keystore (rln_keystore.json) was found; this version \
                     uses a new incompatible format with no migration — back up \
                     rln_keystore.json and move it out of the persistence dir to start fresh \
                     (memberships must be re-registered), or run a previous module version"
                        .to_string(),
                ));
            }
            format::FormatPresence::Both => {
                eprintln!(
                    "sealed store: an old-format {} sits next to the sealed store; it is \
                     ignored (never read, renamed, or deleted)",
                    format::OLD_FORMAT_FILE
                );
            }
            format::FormatPresence::Neither | format::FormatPresence::NewOnly => {}
        }
        let lock = match fs::acquire_dir_lock(&dir, format::LOCK_FILE) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(OpenError::DirLockHeld(format!(
                    "could not take the exclusive keystore lock in {} ({e}); another \
                     process may be using this persistence path",
                    dir.display()
                )));
            }
            Err(e) => {
                return Err(OpenError::Unreadable(format!(
                    "keystore lock file in {}: {e}",
                    dir.display()
                )));
            }
        };

        let sealed = load_sealed(&dir)?;
        let store_uuid = match &sealed {
            Some(f) => match hex_to_vec(&f.store_uuid).and_then(|v| <[u8; 16]>::try_from(v).ok())
            {
                Some(u) => Some(u),
                None => {
                    return Err(OpenError::Unreadable(format!(
                        "{} carries a store_uuid that is not 16-byte hex — refusing to \
                         guess; restore the file from a backup",
                        format::SEALED_FILE
                    )));
                }
            },
            None => None,
        };

        // Unkeyed census: every credential's map key must recompute from its
        // plaintext identity block.
        let mut census = BTreeSet::new();
        if let Some(f) = &sealed {
            for (hash, entry) in &f.credentials {
                let recomputed = registry_id::hex_to_bytes32(&entry.identity.identity_commitment)
                    .map(|c| registry_id::membership_hash(&entry.identity.registry_id, &c));
                if recomputed.as_deref() != Some(hash.as_str()) {
                    eprintln!(
                        "sealed store: entry {hash} fails membership_hash recomputation — \
                         quarantined"
                    );
                    census.insert(hash.clone());
                }
            }
        }

        let loaded = load_allocations(&dir, sealed.as_ref(), &mut census);
        let cache = load_cache(&dir, sealed.as_ref());

        let inner = Inner {
            sealed,
            store_uuid,
            sections: loaded.sections,
            cache,
            census_quarantined: census,
            keyed_quarantined: BTreeSet::new(),
            session: None,
            raw_sections: loaded.raw_sections,
            root_mac_raw: loaded.root_mac_raw,
            lock: Some(lock),
        };
        let snapshot = build_snapshot(&inner);
        Ok(Arc::new(Store {
            dir,
            write: Mutex::new(inner),
            snapshot: Mutex::new(Arc::new(snapshot)),
        }))
    }

    /// Release the directory lock deterministically (drop order is otherwise
    /// tied to the last Arc), so a re-open can reacquire it.
    pub fn close(&self) {
        crate::lock(&self.write).lock.take();
    }

    /// Verify the password and authenticate every entry. The ordering is
    /// wire-frozen:
    /// 1. an all-census-quarantined store refuses BEFORE any KDF (nothing
    ///    could verify the password; a vacuous match would adopt it),
    /// 2. exactly ONE KDF run — an empty store (re-)provisions and returns,
    /// 3. a non-empty store checks the verifier (constant-time),
    /// 4. keyed pass: credential AEAD per entry, then every non-quarantined
    ///    section's MAC, then the root over the stored section MACs,
    /// 5. all-or-nothing commit of quarantine sets + session.
    pub fn unlock(&self, password: &str) -> Result<usize, ApiError> {
        let mut guard = crate::lock(&self.write);
        let inner = &mut *guard;

        let cred_count = inner.sealed.as_ref().map_or(0, |f| f.credentials.len());
        if cred_count > 0
            && inner.sealed.as_ref().is_some_and(|f| {
                f.credentials.keys().all(|h| inner.census_quarantined.contains(h))
            })
        {
            return Err(ApiError::internal(
                "every keystore entry is quarantined (metadata tamper); restore \
                 rln_sealed.json from a backup",
            ));
        }

        if cred_count == 0 {
            // (Re-)provision: any password unlocks an empty store and becomes
            // the store password at first write; the uuid survives so sibling
            // files stay bound across a password change while empty.
            let params = provision_params()
                .map_err(|e| ApiError::internal(&format!("kdf params: {e}")))?;
            let keys = derive_keys(password, &params)?;
            let uuid = match inner.store_uuid {
                Some(u) => u,
                None => {
                    let mut u = [0u8; 16];
                    getrandom::getrandom(&mut u)
                        .map_err(|_| ApiError::internal("no CSPRNG for the store uuid"))?;
                    u
                }
            };
            let file = SealedFile::provision(
                params,
                bytes_to_hex(&keys.verify[..]),
                bytes_to_hex(&uuid),
            );
            fs::write_durable_json(&self.dir, format::SEALED_FILE, &file)
                .map_err(|e| ApiError::internal(&format!("sealed store save: {e}")))?;
            inner.sealed = Some(file);
            inner.store_uuid = Some(uuid);
            inner.session = Some(Session {
                password: Zeroizing::new(password.to_string()),
                keys,
            });
            self.swap_snapshot(inner);
            return Ok(0);
        }

        let Some(sealed) = inner.sealed.as_ref() else {
            return Err(ApiError::internal("sealed store state desynchronized"));
        };
        let Some(uuid) = inner.store_uuid else {
            return Err(ApiError::internal("sealed store is not provisioned"));
        };
        let keys = derive_keys(password, &sealed.kdf)?;
        let stored_verifier = hex_to_vec(&sealed.verifier).unwrap_or_default();
        if !crypto::ct_eq(&keys.verify[..], &stored_verifier) {
            return Err(ApiError::new(
                ErrorKind::BadPassword,
                "password does not open the existing keystore",
            ));
        }

        // Keyed pass, only after the verifier passed. Credential AEAD first…
        let mut keyed = BTreeSet::new();
        for (hash, entry) in &sealed.credentials {
            if inner.census_quarantined.contains(hash) {
                continue;
            }
            let aad = format::credential_aad(hash, &entry.identity, &uuid);
            if !credential_opens(&keys, &aad, entry) {
                eprintln!(
                    "sealed store: entry {hash} fails credential authentication — quarantined"
                );
                keyed.insert(hash.clone());
            }
        }
        // …then every non-quarantined membership's section MAC…
        for hash in sealed.credentials.keys() {
            if inner.census_quarantined.contains(hash) || keyed.contains(hash) {
                continue;
            }
            let ok = inner
                .raw_sections
                .get(hash)
                .is_some_and(|s| section_mac_ok(&keys, hash, s, &uuid));
            if !ok {
                eprintln!(
                    "sealed store: entry {hash} allocation section MAC is missing or fails \
                     verification — quarantined"
                );
                keyed.insert(hash.clone());
            }
        }
        // …then the root, recomputed over the section MACs AS STORED. A clean
        // write always restamps every section MAC and the root together, and a
        // content-only edit leaves the stored MAC (and thus the root) valid and
        // attributable — so a root mismatch can only mean an unforgeable-MAC or
        // structural change: a section spliced in from an older file, a MAC
        // stripped or edited, a section added or removed, or the root itself
        // rolled back. None of those is attributable to a single section (a
        // decoy tamper elsewhere would otherwise mask a splice), so the whole
        // store fails closed: every not-yet-attributed entry quarantines.
        if !inner.raw_sections.is_empty() {
            let mut stored_macs = BTreeMap::new();
            for (hash, s) in &inner.raw_sections {
                if let Some(m) = hex_to_vec(&s.mac).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                    stored_macs.insert(hash.clone(), m);
                }
            }
            let root_ok = stored_macs.len() == inner.raw_sections.len()
                && inner.root_mac_raw.is_some_and(|stored| {
                    let recomputed =
                        format::mac(&keys.ledger, &format::root_mac_payload(&stored_macs, &uuid));
                    crypto::ct_eq(&recomputed, &stored)
                });
            if !root_ok {
                eprintln!(
                    "sealed store: allocations root MAC mismatch — splice, rollback, or \
                     structural tamper; quarantining every membership not already attributed"
                );
                for hash in sealed.credentials.keys() {
                    if !inner.census_quarantined.contains(hash) {
                        keyed.insert(hash.clone());
                    }
                }
            }
        }

        // All-or-nothing commit: nothing above touched Inner.
        let unlocked = sealed
            .credentials
            .keys()
            .filter(|h| !inner.census_quarantined.contains(*h) && !keyed.contains(*h))
            .count();
        inner.keyed_quarantined = keyed;
        inner.session = Some(Session {
            password: Zeroizing::new(password.to_string()),
            keys,
        });
        self.swap_snapshot(inner);
        Ok(unlocked)
    }

    pub fn lock(&self) {
        crate::lock(&self.write).session = None;
    }

    /// The active session password, if unlocked — a Zeroizing clone for
    /// keychain persistence.
    pub fn session_password(&self) -> Option<Zeroizing<String>> {
        crate::lock(&self.write).session.as_ref().map(|s| s.password.clone())
    }

    /// True when unlock() would actually VERIFY a password (a non-quarantined
    /// credential exists).
    pub fn has_credentials(&self) -> bool {
        self.snapshot_arc().has_credentials
    }

    /// The host-stamped persistence dir this store lives in.
    pub fn base_dir(&self) -> &Path {
        &self.dir
    }

    #[allow(dead_code)] // consumer surface: views read the record's flag; the tests read this
    pub fn is_quarantined(&self, hash: &str) -> bool {
        self.snapshot_arc().records.get(hash).map(|r| r.quarantined).unwrap_or(false)
    }

    /// Seal + insert a new (or re-registered) membership. Unlock-gated.
    ///
    /// WRITE ORDERING: (a) allocations — an existing honest section KEEPS its
    /// counters (a quarantined one is reset: its counters are untrusted),
    /// restamped and durably written; (b) the cache row (loose write); then
    /// (c) the sealed credential, durably — the COMMIT POINT. A crash after
    /// (a)/(b) leaves an orphan section/cache row the next open treats as
    /// inert; the membership exists only once (c) lands.
    pub fn insert(
        &self,
        hash: &str,
        identity: IdentityBlock,
        credential: &StoredCredential,
    ) -> Result<(), ApiError> {
        let mut guard = crate::lock(&self.write);
        let inner = &mut *guard;
        if inner.session.is_none() {
            return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before registering"));
        }
        let was_quarantined =
            inner.census_quarantined.remove(hash) | inner.keyed_quarantined.remove(hash);
        if was_quarantined {
            inner.sections.insert(hash.to_string(), AllocationState::default());
        } else {
            inner.sections.entry(hash.to_string()).or_default();
        }
        write_allocations(&self.dir, inner)?;

        inner.cache.insert(
            hash.to_string(),
            CacheState { state: MembershipState::Pending, ..CacheState::default() },
        );
        write_cache(&self.dir, inner)?;

        let Some(session) = inner.session.as_ref() else {
            return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before registering"));
        };
        let Some(uuid) = inner.store_uuid else {
            return Err(ApiError::internal("sealed store is not provisioned"));
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(credential)
                .map_err(|e| ApiError::internal(&format!("credential serialize: {e}")))?,
        );
        let aad = format::credential_aad(hash, &identity, &uuid);
        let (nonce, ct) = crypto::seal(&session.keys.seal, &aad, &plaintext)
            .map_err(|e| ApiError::internal(&format!("credential seal: {e}")))?;
        let Some(sealed) = inner.sealed.as_mut() else {
            return Err(ApiError::internal("sealed store is not provisioned"));
        };
        sealed.credentials.insert(
            hash.to_string(),
            SealedEntry { identity, nonce: bytes_to_hex(&nonce), ct: bytes_to_hex(&ct) },
        );
        fs::write_durable_json(&self.dir, format::SEALED_FILE, sealed)
            .map_err(|e| ApiError::internal(&format!("sealed store save: {e}")))?;
        self.swap_snapshot(inner);
        Ok(())
    }

    /// Unseal one credential — the module's single plaintext release path.
    /// The AAD is recomputed from the CURRENT identity block, so a swapped
    /// identity header fails the AEAD (the old sidecar cross-check, now
    /// enforced by construction).
    pub fn unseal_credential(&self, hash: &str) -> Result<StoredCredential, ApiError> {
        let guard = crate::lock(&self.write);
        let inner = &*guard;
        if inner.census_quarantined.contains(hash) || inner.keyed_quarantined.contains(hash) {
            return Err(ApiError::internal("entry quarantined (metadata tamper)"));
        }
        let Some(session) = inner.session.as_ref() else {
            return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before selecting"));
        };
        let entry = inner.sealed.as_ref().and_then(|f| f.credentials.get(hash)).ok_or_else(
            || ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash"),
        )?;
        let Some(uuid) = inner.store_uuid else {
            return Err(ApiError::internal("sealed store is not provisioned"));
        };
        let aad = format::credential_aad(hash, &entry.identity, &uuid);
        let nonce = hex_to_vec(&entry.nonce)
            .ok_or_else(|| ApiError::internal("malformed credential nonce"))?;
        let ct = hex_to_vec(&entry.ct)
            .ok_or_else(|| ApiError::internal("malformed credential ciphertext"))?;
        let plaintext =
            crypto::unseal(&session.keys.seal, &nonce, &aad, &ct).map_err(|e| match e {
                crypto::CryptoError::BadPassword => ApiError::new(
                    ErrorKind::BadPassword,
                    "session password no longer opens this entry",
                ),
                other => ApiError::internal(&format!("credential unseal: {other}")),
            })?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| ApiError::internal(&format!("credential parse: {e}")))
    }

    // ---------------------------------------------------- snapshot reads

    pub fn membership(&self, hash: &str) -> Option<MembershipRecord> {
        self.snapshot_arc().records.get(hash).cloned()
    }

    /// All records for one canonical registry_id.
    pub fn records_for(&self, canonical_registry: &str) -> Vec<MembershipRecord> {
        self.snapshot_arc()
            .records
            .values()
            .filter(|r| r.identity.registry_id == canonical_registry)
            .cloned()
            .collect()
    }

    /// The poller's confirmation work list: non-quarantined `pending`.
    pub fn pending_records(&self) -> Vec<MembershipRecord> {
        self.snapshot_arc()
            .records
            .values()
            .filter(|r| !r.quarantined && r.cache.state == MembershipState::Pending)
            .cloned()
            .collect()
    }

    /// The state-refresh work list: the old set (Active/GracePeriod/Expired)
    /// PLUS Unknown — a heal-only widening so a lost cache file's defaulted
    /// rows are re-read from the registry instead of staying dark.
    pub fn refreshable_records(&self) -> Vec<MembershipRecord> {
        self.snapshot_arc()
            .records
            .values()
            .filter(|r| {
                !r.quarantined
                    && matches!(
                        r.cache.state,
                        MembershipState::Active
                            | MembershipState::GracePeriod
                            | MembershipState::Expired
                            | MembershipState::Unknown
                    )
            })
            .cloned()
            .collect()
    }

    /// Every membership's persisted epoch-size binding (0 = not yet bound).
    pub fn epoch_size_bindings(&self) -> Vec<(String, u64)> {
        self.snapshot_arc()
            .records
            .values()
            .map(|r| (r.hash.clone(), r.alloc.epoch_size_sec))
            .collect()
    }

    // --------------------------------------------------------- mutations

    /// Run a cache-only mutation and persist the sidecar. Works LOCKED (the
    /// poller's path); by construction it can never touch the sealed or
    /// allocations files. Stamps the monotone `first_active_at` on the first
    /// active-like observation.
    pub fn update_cache(
        &self,
        hash: &str,
        f: impl FnOnce(&mut CacheState),
    ) -> Result<(), ApiError> {
        let mut guard = crate::lock(&self.write);
        let inner = &mut *guard;
        if !inner.sealed.as_ref().is_some_and(|s| s.credentials.contains_key(hash)) {
            return Err(ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash"));
        }
        let row = inner.cache.entry(hash.to_string()).or_default();
        f(row);
        if row.first_active_at.is_none() && row.state.is_active_like() {
            row.first_active_at = Some(crate::now_unix());
        }
        write_cache(&self.dir, inner)?;
        self.swap_snapshot(inner);
        Ok(())
    }

    /// Reserve the next `message_id` for `(membership, rln_identifier,
    /// epoch)` and durably persist it before returning — the caller uses the
    /// slot only after this call succeeds, so a crash can waste a slot but
    /// never reissue one. Guards run FIRST: a refused call must leave the
    /// counters untouched, and a quarantined entry's counters are untrusted.
    pub fn reserve_message_id(
        &self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        retain_floor: u64,
        rate_limit: u64,
        epoch_size_sec: u64,
    ) -> Result<u64, ApiError> {
        let mut guard = crate::lock(&self.write);
        let inner = &mut *guard;
        let quarantined =
            inner.census_quarantined.contains(hash) || inner.keyed_quarantined.contains(hash);
        reservation_guards(quarantined, inner.sections.get(hash), epoch_size_sec)?;
        if inner.session.is_none() {
            return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before generate_proof"));
        }
        let Some(alloc) = inner.sections.get_mut(hash) else {
            return Err(ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash"));
        };
        let slot = reserve_slot(alloc, rln_identifier_hex, epoch, retain_floor, rate_limit)
            .map_err(|e| match e {
                AllocError::BudgetExhausted => ApiError::new(
                    ErrorKind::BudgetExhausted,
                    "epoch rate-limit budget exhausted; retry next epoch",
                ),
                AllocError::EpochBelowFloor => floor_refusal(),
            })?;
        alloc.epoch_size_sec = epoch_size_sec; // adopt-on-first-success
        let written = write_allocations(&self.dir, inner);
        // On a failed persist the counter/floor deliberately stay advanced
        // and the snapshot still publishes them: no proof is issued for the
        // slot, so it can only be WASTED, never reissued (the
        // waste-not-reissue tie-break).
        self.swap_snapshot(inner);
        written?;
        Ok(slot)
    }

    /// Remaining slots for `(membership, rln_identifier, epoch)`. Read-only
    /// and works LOCKED, but it mirrors the reserve path's PERMANENT
    /// refusals with the same errors — never shown as an "exhausted" budget
    /// the consumer would retry forever. A missing membership reads as 0.
    pub fn remaining_budget(
        &self,
        hash: &str,
        rln_identifier_hex: &str,
        epoch: u64,
        rate_limit: u64,
        epoch_size_sec: u64,
    ) -> Result<u64, ApiError> {
        let guard = crate::lock(&self.write);
        let inner = &*guard;
        if !inner.sealed.as_ref().is_some_and(|f| f.credentials.contains_key(hash)) {
            return Ok(0);
        }
        let quarantined =
            inner.census_quarantined.contains(hash) || inner.keyed_quarantined.contains(hash);
        let alloc = inner.sections.get(hash).cloned().unwrap_or_default();
        reservation_guards(quarantined, Some(&alloc), epoch_size_sec)?;
        if epoch < alloc.prune_floor {
            return Err(floor_refusal());
        }
        Ok(remaining(&alloc.allocations, rln_identifier_hex, epoch, rate_limit))
    }

    // ----------------------------------------------------------- helpers

    fn snapshot_arc(&self) -> Arc<Snapshot> {
        crate::lock(&self.snapshot).clone()
    }

    fn swap_snapshot(&self, inner: &Inner) {
        *crate::lock(&self.snapshot) = Arc::new(build_snapshot(inner));
    }
}

// ------------------------------------------------------------ free helpers

fn provision_params() -> Result<KdfParams, crypto::CryptoError> {
    #[cfg(test)]
    {
        Ok(KdfParams::fast_for_tests())
    }
    #[cfg(not(test))]
    {
        KdfParams::generate()
    }
}

fn derive_keys(password: &str, params: &KdfParams) -> Result<SubKeys, ApiError> {
    let mk = MasterKey::derive(password, params)
        .map_err(|e| ApiError::internal(&format!("kdf: {e}")))?;
    SubKeys::derive(&mk).map_err(|e| ApiError::internal(&format!("kdf: {e}")))
}

/// True when the entry's AEAD opens under this session AND the plaintext
/// parses as a credential. The Zeroizing plaintext (and the parsed
/// credential's ZeroizeOnDrop fields) drop before returning.
fn credential_opens(keys: &SubKeys, aad: &[u8], entry: &SealedEntry) -> bool {
    let Some(nonce) = hex_to_vec(&entry.nonce) else { return false };
    let Some(ct) = hex_to_vec(&entry.ct) else { return false };
    match crypto::unseal(&keys.seal, &nonce, aad, &ct) {
        Ok(pt) => serde_json::from_slice::<StoredCredential>(&pt).is_ok(),
        Err(_) => false,
    }
}

fn section_mac_ok(keys: &SubKeys, hash: &str, section: &Section, uuid: &[u8; 16]) -> bool {
    let expected = format::mac(
        &keys.ledger,
        &format::section_mac_payload(
            hash,
            section.epoch_size_sec,
            section.prune_floor,
            &section.allocations,
            uuid,
        ),
    );
    match hex_to_vec(&section.mac) {
        Some(stored) => crypto::ct_eq(&expected, &stored),
        None => false,
    }
}

/// The shared reserve/quota guards: quarantined counters are untrusted, a
/// missing membership is unknown, and an epoch-size mismatch is permanently
/// refused (a rebased epoch numbering could reissue spent slots).
fn reservation_guards(
    quarantined: bool,
    alloc: Option<&AllocationState>,
    epoch_size_sec: u64,
) -> Result<(), ApiError> {
    if quarantined {
        return Err(ApiError::internal("entry quarantined (metadata tamper)"));
    }
    let Some(alloc) = alloc else {
        return Err(ApiError::new(ErrorKind::UnknownMembership, "no such membership_hash"));
    };
    if alloc.epoch_size_sec != 0 && alloc.epoch_size_sec != epoch_size_sec {
        return Err(ApiError::new(
            ErrorKind::Permanent,
            &format!(
                "configured epoch_size_sec {epoch_size_sec} differs from {} — the size this \
                 membership's allocations are bound to; a rebased epoch numbering could \
                 reissue spent slots. Register a fresh membership under the new size",
                alloc.epoch_size_sec
            ),
        ));
    }
    Ok(())
}

fn floor_refusal() -> ApiError {
    ApiError::new(
        ErrorKind::Permanent,
        "epoch is below the persisted allocation floor (backwards clock step or a \
         widened max_epoch_gap re-admitted a pruned epoch); refusing to reissue a \
         possibly spent slot",
    )
}

/// Move a corrupt file aside as `.bad.<unix-ts>` evidence (left in place if
/// the rename fails).
fn quarantine_file(dir: &Path, file_name: &str, why: &str) {
    let bad = dir.join(format!("{file_name}.bad.{}", crate::now_unix()));
    eprintln!(
        "sealed store: {file_name} corrupt ({why}); attempting to move aside to {}",
        bad.display()
    );
    if let Err(re) = std::fs::rename(dir.join(file_name), &bad) {
        eprintln!("sealed store: quarantine rename failed ({re}); bad file left in place");
    }
}

fn quarantine_all(sealed: Option<&SealedFile>, census: &mut BTreeSet<String>, why: &str) {
    let Some(f) = sealed else { return };
    if f.credentials.is_empty() {
        return;
    }
    eprintln!("sealed store: {why}; quarantining every membership");
    for hash in f.credentials.keys() {
        census.insert(hash.clone());
    }
}

/// Load the sealed file. `None` = unprovisioned. A parse-corrupt file is
/// moved aside as evidence and treated as unprovisioned; a foreign format or
/// version is refused outright (never adopted, never renamed).
fn load_sealed(dir: &Path) -> Result<Option<SealedFile>, OpenError> {
    let path = dir.join(format::SEALED_FILE);
    match format::file_within_cap(&path) {
        Ok(true) => {}
        Ok(false) => {
            return Err(OpenError::Unreadable(format!(
                "{} exceeds the {}-byte size cap; refusing to parse it — restore the file \
                 from a backup",
                format::SEALED_FILE,
                format::MAX_FILE_BYTES
            )));
        }
        Err(e) => {
            return Err(OpenError::Unreadable(format!("{}: {e}", format::SEALED_FILE)));
        }
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(OpenError::Unreadable(format!("{}: {e}", format::SEALED_FILE)));
        }
    };
    let parsed = serde_json::from_str::<SealedFile>(&raw)
        .map_err(|e| e.to_string())
        .and_then(|f| format::check_sealed_caps(&f).map(|()| f).map_err(String::from));
    let file = match parsed {
        Ok(f) => f,
        Err(e) => {
            quarantine_file(dir, format::SEALED_FILE, &e);
            return Ok(None);
        }
    };
    if file.format != format::FORMAT_SEALED || file.version != format::FORMAT_VERSION {
        return Err(OpenError::Unreadable(format!(
            "{} declares format \"{}\" version {} but this build speaks {} version {}; \
             refusing to adopt it — run a module version matching the file, or restore \
             the file from a backup",
            format::SEALED_FILE,
            file.format,
            file.version,
            format::FORMAT_SEALED,
            format::FORMAT_VERSION
        )));
    }
    Ok(Some(file))
}

struct LoadedAllocations {
    sections: BTreeMap<String, AllocationState>,
    raw_sections: BTreeMap<String, Section>,
    root_mac_raw: Option<[u8; 32]>,
}

impl LoadedAllocations {
    fn empty() -> LoadedAllocations {
        LoadedAllocations {
            sections: BTreeMap::new(),
            raw_sections: BTreeMap::new(),
            root_mac_raw: None,
        }
    }
}

/// Load the allocations ledger. Deletion-is-tamper: an absent (or corrupt,
/// or foreign) ledger while credentials exist quarantines every membership —
/// counters and floors are local security state with no source to re-read.
fn load_allocations(
    dir: &Path,
    sealed: Option<&SealedFile>,
    census: &mut BTreeSet<String>,
) -> LoadedAllocations {
    let path = dir.join(format::ALLOCATIONS_FILE);
    match format::file_within_cap(&path) {
        Ok(true) => {}
        Ok(false) => {
            quarantine_file(dir, format::ALLOCATIONS_FILE, "over the size cap");
            quarantine_all(sealed, census, "the allocations file exceeded the size cap");
            return LoadedAllocations::empty();
        }
        Err(e) => {
            quarantine_all(
                sealed,
                census,
                &format!("the allocations file metadata is unreadable ({e})"),
            );
            return LoadedAllocations::empty();
        }
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            quarantine_all(
                sealed,
                census,
                "the allocations file is missing while credentials exist (deleting the \
                 ledger is tamper)",
            );
            return LoadedAllocations::empty();
        }
        Err(e) => {
            quarantine_all(sealed, census, &format!("the allocations file is unreadable ({e})"));
            return LoadedAllocations::empty();
        }
    };
    let parsed = serde_json::from_str::<AllocationsFile>(&raw)
        .map_err(|e| e.to_string())
        .and_then(|f| format::check_allocations_caps(&f).map(|()| f).map_err(String::from))
        .and_then(|f| {
            if f.format == format::FORMAT_ALLOCATIONS && f.version == format::FORMAT_VERSION {
                Ok(f)
            } else {
                Err(format!("foreign format \"{}\" version {}", f.format, f.version))
            }
        });
    let file = match parsed {
        Ok(f) => f,
        Err(e) => {
            quarantine_file(dir, format::ALLOCATIONS_FILE, &e);
            quarantine_all(sealed, census, &format!("the allocations file is corrupt ({e})"));
            return LoadedAllocations::empty();
        }
    };
    if sealed.is_none_or(|s| s.store_uuid != file.store_uuid) {
        quarantine_all(
            sealed,
            census,
            "the allocations file's store_uuid does not match the sealed header (a foreign \
             or partially restored file)",
        );
        let root = hex_to_vec(&file.root_mac).and_then(|v| <[u8; 32]>::try_from(v).ok());
        return LoadedAllocations {
            sections: BTreeMap::new(),
            raw_sections: file.sections,
            root_mac_raw: root,
        };
    }
    let mut sections = BTreeMap::new();
    if let Some(f) = sealed {
        for (hash, section) in &file.sections {
            if !f.credentials.contains_key(hash) {
                eprintln!(
                    "sealed store: allocations section {hash} has no credential — inert (a \
                     crash-orphaned write; pruned at the next allocations write)"
                );
                continue;
            }
            sections.insert(
                hash.clone(),
                AllocationState {
                    allocations: section
                        .allocations
                        .iter()
                        .map(|r| EpochAllocation {
                            rln_identifier: r.rln_identifier.clone(),
                            epoch: r.epoch,
                            used: r.used,
                        })
                        .collect(),
                    epoch_size_sec: section.epoch_size_sec,
                    prune_floor: section.prune_floor,
                },
            );
        }
        for hash in f.credentials.keys() {
            if !file.sections.contains_key(hash) {
                eprintln!(
                    "sealed store: credential {hash} has no allocations section — quarantined"
                );
                census.insert(hash.clone());
            }
        }
    }
    let root = hex_to_vec(&file.root_mac).and_then(|v| <[u8; 32]>::try_from(v).ok());
    LoadedAllocations { sections, raw_sections: file.sections, root_mac_raw: root }
}

/// Load the cache sidecar. Unauthenticated and registry-healed, so every
/// failure degrades to defaults: rows for unknown hashes are pruned and a
/// credential without a row gets a default (state Unknown).
fn load_cache(dir: &Path, sealed: Option<&SealedFile>) -> BTreeMap<String, CacheState> {
    let path = dir.join(format::CACHE_FILE);
    let mut entries = match format::file_within_cap(&path) {
        Ok(true) => match fs::load_json::<CacheFile>(dir, format::CACHE_FILE) {
            Ok(f) => f.entries,
            Err(e) => {
                eprintln!(
                    "sealed store: {} unreadable ({e}); starting from an empty cache (the \
                     poller heals it)",
                    format::CACHE_FILE
                );
                BTreeMap::new()
            }
        },
        Ok(false) => {
            quarantine_file(dir, format::CACHE_FILE, "over the size cap");
            BTreeMap::new()
        }
        Err(e) => {
            eprintln!(
                "sealed store: {} metadata unreadable ({e}); starting from an empty cache",
                format::CACHE_FILE
            );
            BTreeMap::new()
        }
    };
    match sealed {
        Some(f) => {
            entries.retain(|hash, _| f.credentials.contains_key(hash));
            for hash in f.credentials.keys() {
                entries.entry(hash.clone()).or_default();
            }
        }
        None => entries.clear(),
    }
    entries
}

/// Serialize + durably write the allocations ledger: every non-quarantined
/// section restamped under the session ledger key, a quarantined section
/// written exactly as loaded (a fresh MAC over tampered state would launder
/// it), the root over exactly the MACs written. Orphan sections are not
/// carried — this write prunes them. `raw_sections`/`root_mac_raw` track the
/// written state so a later in-process unlock verifies against it.
fn write_allocations(dir: &Path, inner: &mut Inner) -> Result<(), ApiError> {
    let Some(session) = inner.session.as_ref() else {
        return Err(ApiError::new(ErrorKind::Locked, "unlock_keystore before registering"));
    };
    let Some(uuid) = inner.store_uuid else {
        return Err(ApiError::internal("sealed store is not provisioned"));
    };
    let mut sections = BTreeMap::new();
    let mut macs = BTreeMap::new();
    for (hash, alloc) in &inner.sections {
        let quarantined =
            inner.census_quarantined.contains(hash) || inner.keyed_quarantined.contains(hash);
        let section = if quarantined {
            match inner.raw_sections.get(hash) {
                Some(s) => s.clone(),
                None => continue,
            }
        } else {
            let rows: Vec<AllocRow> = alloc
                .allocations
                .iter()
                .map(|a| AllocRow {
                    rln_identifier: a.rln_identifier.clone(),
                    epoch: a.epoch,
                    used: a.used,
                })
                .collect();
            let mac = format::mac(
                &session.keys.ledger,
                &format::section_mac_payload(
                    hash,
                    alloc.epoch_size_sec,
                    alloc.prune_floor,
                    &rows,
                    &uuid,
                ),
            );
            Section {
                epoch_size_sec: alloc.epoch_size_sec,
                prune_floor: alloc.prune_floor,
                allocations: rows,
                mac: bytes_to_hex(&mac),
            }
        };
        let mac_bytes = hex_to_vec(&section.mac)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0u8; 32]);
        macs.insert(hash.clone(), mac_bytes);
        sections.insert(hash.clone(), section);
    }
    let root = format::mac(&session.keys.ledger, &format::root_mac_payload(&macs, &uuid));
    let file = AllocationsFile {
        format: format::FORMAT_ALLOCATIONS.to_string(),
        version: format::FORMAT_VERSION,
        store_uuid: bytes_to_hex(&uuid),
        sections,
        root_mac: bytes_to_hex(&root),
    };
    fs::write_durable_json(dir, format::ALLOCATIONS_FILE, &file)
        .map_err(|e| ApiError::internal(&format!("allocations save: {e}")))?;
    inner.raw_sections = file.sections;
    inner.root_mac_raw = Some(root);
    Ok(())
}

fn write_cache(dir: &Path, inner: &Inner) -> Result<(), ApiError> {
    let file = CacheFile {
        format: FORMAT_CACHE.to_string(),
        version: format::FORMAT_VERSION,
        entries: inner.cache.clone(),
    };
    fs::write_atomic_loose_json(dir, format::CACHE_FILE, &file)
        .map_err(|e| ApiError::internal(&format!("cache save: {e}")))
}

fn build_snapshot(inner: &Inner) -> Snapshot {
    let mut records = BTreeMap::new();
    if let Some(f) = &inner.sealed {
        for (hash, entry) in &f.credentials {
            records.insert(
                hash.clone(),
                MembershipRecord {
                    hash: hash.clone(),
                    identity: entry.identity.clone(),
                    cache: inner.cache.get(hash).cloned().unwrap_or_default(),
                    alloc: inner.sections.get(hash).cloned().unwrap_or_default(),
                    quarantined: inner.census_quarantined.contains(hash)
                        || inner.keyed_quarantined.contains(hash),
                },
            );
        }
    }
    let has_credentials = records.values().any(|r| !r.quarantined);
    Snapshot { records, has_credentials }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KDF-count assertions read a process-global counter; serialize this
    /// module's tests against each other and let concurrent modules' derives
    /// (crypto.rs) go quiet before measuring.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn settle_kdf() -> u64 {
        let mut last = crypto::kdf_runs();
        let mut stable = 0;
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(25));
            let now = crypto::kdf_runs();
            if now == last {
                stable += 1;
                if stable >= 2 {
                    return now;
                }
            } else {
                stable = 0;
                last = now;
            }
        }
        last
    }

    fn test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("rln-sealed-store-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn identity_for(registry: &str, commitment: &[u8; 32]) -> IdentityBlock {
        IdentityBlock {
            registry_id: registry.to_string(),
            rln_identifier: String::new(),
            identity_commitment: registry_id::bytes_to_hex(commitment),
            submitted_at: crate::now_unix(),
        }
    }

    fn credential_for(registry: &str, commitment: &[u8; 32]) -> StoredCredential {
        StoredCredential {
            identity_commitment: registry_id::bytes_to_hex(commitment),
            identity_nullifier: None,
            identity_secret_hash: "77".repeat(32),
            identity_trapdoor: None,
            registry_id: registry.to_string(),
        }
    }

    fn insert_membership(store: &Store, registry: &str, commitment: &[u8; 32]) -> String {
        let hash = registry_id::membership_hash(registry, commitment);
        store
            .insert(&hash, identity_for(registry, commitment), &credential_for(registry, commitment))
            .unwrap();
        hash
    }

    fn edit_json(path: &Path, f: impl FnOnce(&mut serde_json::Value)) {
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        f(&mut v);
        std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn has_bad_file(dir: &Path, prefix: &str) -> bool {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().starts_with(&format!("{prefix}.bad.")))
    }

    #[test]
    fn reservation_floor_and_epoch_size_survive_restart() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("floor");
        let registry = format!("logos:local:{}", "aa".repeat(32));
        let commitment = [0x66u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        // Reserve in epoch 10, then in epoch 12 with the window floor at 11 —
        // the second reservation prunes epoch 10's spent row and records
        // floor 11, all under epoch_size 600.
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 0);
        assert_eq!(store.reserve_message_id(&hash, "aa", 12, 11, 5, 600).unwrap(), 0);
        store.close();
        drop(store);

        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 1);
        assert_eq!(store.epoch_size_bindings(), vec![(hash.clone(), 600)]);
        // A rewound (or gap-widened) window re-admits pruned epoch 10, but
        // the persisted floor must refuse it instead of reissuing slot 0.
        let rewound = store.reserve_message_id(&hash, "aa", 10, 9, 5, 600);
        assert!(matches!(rewound, Err(e) if e.kind == ErrorKind::Permanent));
        // The quota read mirrors the SAME permanent refusals.
        let q_floor = store.remaining_budget(&hash, "aa", 10, 5, 600);
        assert!(matches!(q_floor, Err(e) if e.kind == ErrorKind::Permanent));
        let q_size = store.remaining_budget(&hash, "aa", 12, 5, 1200);
        assert!(matches!(q_size, Err(e) if e.kind == ErrorKind::Permanent));
        // Epoch 12 continues its persisted counter — slot 1, never a fresh 0.
        assert_eq!(store.reserve_message_id(&hash, "aa", 12, 11, 5, 600).unwrap(), 1);
        // A different epoch_size_sec rebases the epoch numbering: refused.
        let rebased = store.reserve_message_id(&hash, "aa", 12, 11, 5, 1200);
        assert!(matches!(rebased, Err(e) if e.kind == ErrorKind::Permanent));

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locked_cache_updates_do_not_invalidate() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("locked-cache");
        let registry = format!("logos:local:{}", "cc".repeat(32));
        let commitment = [0x61u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 0);
        store.lock();
        // Locked-mode cache mutations (the poller's path) must never touch
        // the authenticated files.
        store.update_cache(&hash, |c| c.leaf_index = Some(7)).unwrap();
        store.update_cache(&hash, |c| c.state = MembershipState::Active).unwrap();
        store.update_cache(&hash, |c| c.rate_limit = Some(100)).unwrap();
        store.close();
        drop(store);

        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 1, "no membership may be quarantined");
        assert!(!store.is_quarantined(&hash));
        let rec = store.membership(&hash).unwrap();
        assert_eq!(rec.cache.state, MembershipState::Active);
        assert_eq!(rec.cache.leaf_index, Some(7));
        assert_eq!(rec.cache.rate_limit, Some(100));
        assert!(rec.cache.first_active_at.is_some(), "active observation must stamp it");
        // Counters intact: the next slot continues, never a fresh 0.
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 1);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn census_and_unlock_matrix() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("census");
        let registry = format!("logos:local:{}", "cd".repeat(32));
        let commitment_a = [0x51u8; 32];
        let commitment_b = [0x52u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        assert_eq!(store.records_for(&registry).len(), 2);
        store.close();
        drop(store);

        // Tamper A's identity block on disk: the open-time census quarantines
        // it without any password; the sibling still verifies and unseals.
        let sealed_path = dir.join(format::SEALED_FILE);
        edit_json(&sealed_path, |v| {
            v["credentials"][hash_a.as_str()]["identity"]["identity_commitment"] =
                "ff".repeat(32).into();
        });
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.is_quarantined(&hash_a));
        assert!(!store.is_quarantined(&hash_b));
        assert_eq!(store.unlock("pw").unwrap(), 1);
        assert!(store.unseal_credential(&hash_b).is_ok());
        let denied = store.unseal_credential(&hash_a);
        assert!(matches!(denied, Err(ref e) if e.message.contains("quarantined")));
        store.close();
        drop(store);

        // Wrong password against the surviving envelope is rejected.
        let store = Store::open(dir.clone()).unwrap();
        let bad = store.unlock("not-pw");
        assert!(matches!(bad, Err(e) if e.kind == ErrorKind::BadPassword));
        store.close();
        drop(store);

        // All-census-quarantined: with nothing left to verify against, ANY
        // password is refused — and BEFORE any KDF runs.
        edit_json(&sealed_path, |v| {
            v["credentials"][hash_b.as_str()]["identity"]["identity_commitment"] =
                "ee".repeat(32).into();
        });
        let store = Store::open(dir.clone()).unwrap();
        let before = settle_kdf();
        for pw in ["pw", "other", ""] {
            let denied = store.unlock(pw);
            assert!(
                matches!(denied, Err(ref e) if e.kind == ErrorKind::Internal
                    && e.message.contains("quarantined")),
                "an all-quarantined store must refuse every password: {denied:?}"
            );
        }
        assert_eq!(crypto::kdf_runs(), before, "the refusal must precede any KDF");

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_allocations_matrix() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("alloc-tamper");
        let registry = format!("logos:local:{}", "bb".repeat(32));
        let commitment_a = [0x51u8; 32];
        let commitment_b = [0x52u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        // Spend a slot on A so its MAC covers live allocation state.
        assert_eq!(store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).unwrap(), 0);
        store.close();
        drop(store);

        let alloc_path = dir.join(format::ALLOCATIONS_FILE);
        let honest = std::fs::read_to_string(&alloc_path).unwrap();

        // (a) Rewind A's spent counter on disk (file-write access, no
        // password): unlock must quarantine A; untampered B stays usable.
        edit_json(&alloc_path, |v| {
            v["sections"][hash_a.as_str()]["allocations"][0]["used"] = 0.into();
        });
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 1);
        assert!(store.is_quarantined(&hash_a), "a rewound counter must quarantine");
        assert!(!store.is_quarantined(&hash_b), "the untampered sibling stays usable");
        assert!(store.unseal_credential(&hash_a).is_err());
        assert!(store.unseal_credential(&hash_b).is_ok());
        store.close();
        drop(store);
        std::fs::write(&alloc_path, &honest).unwrap();

        // (b) Strip A's section MAC. A stripped tag breaks the root binding
        // (the set of section MACs no longer matches the root), which is
        // unattributable — so the store fails closed and BOTH quarantine.
        edit_json(&alloc_path, |v| {
            v["sections"][hash_a.as_str()]["mac"] = "".into();
        });
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 0);
        assert!(store.is_quarantined(&hash_a), "a stripped MAC must quarantine");
        assert!(store.is_quarantined(&hash_b), "a broken root binding fails closed store-wide");
        store.close();
        drop(store);
        std::fs::write(&alloc_path, &honest).unwrap();

        // (c) SPLICE: advance A's counter, then graft the older (individually
        // valid) section back into the newer file. Every section verifies on
        // its own, but the root doesn't — unattributable, so EVERYTHING
        // quarantines.
        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        assert_eq!(store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).unwrap(), 1);
        store.close();
        drop(store);
        let old: serde_json::Value = serde_json::from_str(&honest).unwrap();
        edit_json(&alloc_path, |v| {
            v["sections"][hash_a.as_str()] = old["sections"][hash_a.as_str()].clone();
        });
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 0, "a splice must quarantine everything");
        assert!(store.is_quarantined(&hash_a));
        assert!(store.is_quarantined(&hash_b));
        store.close();
        drop(store);
        std::fs::write(&alloc_path, &honest).unwrap();

        // (d) Deleting the ledger while credentials exist is tamper: all
        // quarantined at OPEN, and unlock refuses outright.
        std::fs::remove_file(&alloc_path).unwrap();
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.is_quarantined(&hash_a));
        assert!(store.is_quarantined(&hash_b));
        let denied = store.unlock("pw");
        assert!(matches!(denied, Err(ref e) if e.message.contains("quarantined")));
        store.close();
        drop(store);
        std::fs::write(&alloc_path, &honest).unwrap();

        // (e) Removing one section: A census-quarantines at open (a credential
        // with no section), and the root no longer covers the surviving set —
        // unattributable, so B fails closed too.
        edit_json(&alloc_path, |v| {
            v["sections"].as_object_mut().unwrap().remove(hash_a.as_str());
        });
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.is_quarantined(&hash_a), "a credential with no section census-quarantines at open");
        assert_eq!(store.unlock("pw").unwrap(), 0);
        assert!(store.is_quarantined(&hash_b), "a broken root binding fails closed store-wide");
        assert!(store.unseal_credential(&hash_b).is_err());
        store.close();
        drop(store);
        std::fs::write(&alloc_path, &honest).unwrap();

        // (f) Splice A's older section WHILE B is independently quarantined by
        // a decoy tamper. The decoy must not mask the splice: A — individually
        // valid and would-be-usable — must still quarantine (regression for the
        // suppressed-escalation reissue path).
        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        assert_eq!(store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).unwrap(), 1);
        store.close();
        drop(store);
        let old: serde_json::Value = serde_json::from_str(&honest).unwrap();
        edit_json(&alloc_path, |v| {
            v["sections"][hash_a.as_str()] = old["sections"][hash_a.as_str()].clone();
            // decoy: corrupt B's own section content so B quarantines on its own
            v["sections"][hash_b.as_str()]["prune_floor"] = 999u64.into();
        });
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 0, "a splice behind a decoy must still be caught");
        assert!(store.is_quarantined(&hash_a), "the spliced entry must not ride through B's quarantine");
        assert!(store.is_quarantined(&hash_b));

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_store_verifier_flow() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("verifier");
        let registry = format!("logos:local:{}", "ee".repeat(32));
        let commitment = [0x42u8; 32];
        let sealed_path = dir.join(format::SEALED_FILE);
        let uuid_of = |p: &Path| read_json(p)["store_uuid"].as_str().unwrap().to_string();

        let store = Store::open(dir.clone()).unwrap();
        let before = settle_kdf();
        assert_eq!(store.unlock("pw1").unwrap(), 0);
        assert_eq!(crypto::kdf_runs(), before + 1, "provisioning is exactly one KDF run");
        let uuid1 = uuid_of(&sealed_path);
        store.lock();

        // Re-provision while still empty: a different password is adopted,
        // the store_uuid survives.
        let before = crypto::kdf_runs();
        assert_eq!(store.unlock("pw2").unwrap(), 0);
        assert_eq!(crypto::kdf_runs(), before + 1);
        assert_eq!(uuid_of(&sealed_path), uuid1, "re-provisioning must keep the uuid");

        // The first write freezes the password.
        let hash = insert_membership(&store, &registry, &commitment);
        store.lock();
        let before = crypto::kdf_runs();
        let denied = store.unlock("pw1");
        assert!(matches!(denied, Err(e) if e.kind == ErrorKind::BadPassword));
        assert_eq!(crypto::kdf_runs(), before + 1, "a verify is exactly one KDF run");
        let before = crypto::kdf_runs();
        assert_eq!(store.unlock("pw2").unwrap(), 1);
        assert_eq!(crypto::kdf_runs(), before + 1);
        assert!(store.unseal_credential(&hash).is_ok());

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn insert_orphans_and_reinsert() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("orphans");
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let commitment_a = [0x51u8; 32];
        let commitment_b = [0x52u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        assert_eq!(store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).unwrap(), 0);
        store.close();
        drop(store);

        // Simulate a crash between the allocations/cache writes and the
        // sealed commit point: B's credential never landed, leaving an orphan
        // section and cache row. Both must be inert.
        edit_json(&dir.join(format::SEALED_FILE), |v| {
            v["credentials"].as_object_mut().unwrap().remove(hash_b.as_str());
        });
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.membership(&hash_b).is_none(), "an orphan is not a membership");
        assert_eq!(store.unlock("pw").unwrap(), 1, "the orphan must not quarantine A");
        assert!(!store.is_quarantined(&hash_a));

        // Re-inserting the same hash keeps the spent counters: the next
        // reservation continues at slot 1, never a fresh 0.
        store
            .insert(
                &hash_a,
                identity_for(&registry, &commitment_a),
                &credential_for(&registry, &commitment_a),
            )
            .unwrap();
        assert_eq!(store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600).unwrap(), 1);

        // The insert's writes pruned the orphans from both sidecars.
        let alloc = read_json(&dir.join(format::ALLOCATIONS_FILE));
        assert!(alloc["sections"].get(hash_b.as_str()).is_none());
        let cache = read_json(&dir.join(format::CACHE_FILE));
        assert!(cache["entries"].get(hash_b.as_str()).is_none());

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_format_refusal() {
        let _serial = crate::lock(&SERIAL);

        // Only an old-format keystore present: refused, bytes untouched.
        let dir = test_dir("oldfmt-only");
        std::fs::create_dir_all(&dir).unwrap();
        let old_bytes: &[u8] = b"{\"credentials\":{\"legacy\":true}}";
        std::fs::write(dir.join(format::OLD_FORMAT_FILE), old_bytes).unwrap();
        let denied = Store::open(dir.clone());
        assert!(
            matches!(denied, Err(OpenError::OldFormatPresent(ref m))
                if m.contains("rln_keystore.json") && m.contains("no migration")),
            "an old-only dir must refuse with migration guidance"
        );
        assert_eq!(std::fs::read(dir.join(format::OLD_FORMAT_FILE)).unwrap(), old_bytes);
        let _ = std::fs::remove_dir_all(&dir);

        // Both formats present: the sealed store opens, the old file is
        // ignored and untouched.
        let dir = test_dir("oldfmt-both");
        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        store.close();
        drop(store);
        std::fs::write(dir.join(format::OLD_FORMAT_FILE), old_bytes).unwrap();
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 0);
        assert_eq!(std::fs::read(dir.join(format::OLD_FORMAT_FILE)).unwrap(), old_bytes);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locked_structural_gates() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("locked-gates");
        let registry = format!("logos:local:{}", "de".repeat(32));
        let commitment_a = [0x51u8; 32];
        let commitment_b = [0x52u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        store.lock();

        let hash_b = registry_id::membership_hash(&registry, &commitment_b);
        let denied = store.insert(
            &hash_b,
            identity_for(&registry, &commitment_b),
            &credential_for(&registry, &commitment_b),
        );
        assert!(matches!(denied, Err(e) if e.kind == ErrorKind::Locked));
        let denied = store.unseal_credential(&hash_a);
        assert!(matches!(denied, Err(e) if e.kind == ErrorKind::Locked));
        let denied = store.reserve_message_id(&hash_a, "aa", 10, 9, 5, 600);
        assert!(matches!(denied, Err(e) if e.kind == ErrorKind::Locked));
        // The structural reads and the cache path stay open while locked.
        store.update_cache(&hash_a, |c| c.leaf_index = Some(3)).unwrap();
        assert_eq!(store.pending_records().len(), 1);
        assert_eq!(store.remaining_budget(&hash_a, "aa", 10, 5, 600).unwrap(), 5);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_corruption_heals() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("cache-heal");
        let registry = format!("logos:local:{}", "ef".repeat(32));
        let commitment = [0x44u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        store.close();
        drop(store);

        std::fs::write(dir.join(format::CACHE_FILE), b"{not json").unwrap();
        let store = Store::open(dir.clone()).unwrap();
        assert!(
            has_bad_file(&dir, format::CACHE_FILE),
            "the corrupt cache must be moved aside as evidence"
        );
        let rec = store.membership(&hash).unwrap();
        assert!(!rec.quarantined, "cache corruption is self-DoS, never quarantine");
        assert_eq!(rec.cache.state, MembershipState::Unknown);
        // Unknown is refreshable — the heal-only widening — so the poller
        // re-reads the state from the registry.
        assert!(store.refreshable_records().iter().any(|r| r.hash == hash));

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_field_tamper_matrix() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("aad-tamper");
        let registry = format!("logos:local:{}", "fa".repeat(32));
        let commitment_a = [0x53u8; 32];
        let commitment_b = [0x54u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        store.close();
        drop(store);

        let sealed_path = dir.join(format::SEALED_FILE);
        let honest = std::fs::read_to_string(&sealed_path).unwrap();

        // Every identity field is covered, by one of two mechanisms:
        // registry_id and identity_commitment feed the membership_hash, so
        // the unkeyed census catches them at OPEN; rln_identifier and
        // submitted_at live only under the credential AEAD's AAD, caught at
        // unlock. Either way: quarantined, sibling usable, no plaintext.
        let other_registry = format!("logos:local:{}", "fb".repeat(32));
        let cases: [(&str, serde_json::Value, bool); 4] = [
            ("registry_id", other_registry.into(), true),
            ("identity_commitment", "fd".repeat(32).into(), true),
            ("rln_identifier", "de".repeat(32).into(), false),
            ("submitted_at", 12_345.into(), false),
        ];
        for (field, value, census_caught) in cases {
            edit_json(&sealed_path, |v| {
                v["credentials"][hash_a.as_str()]["identity"][field] = value;
            });
            let store = Store::open(dir.clone()).unwrap();
            assert_eq!(
                store.is_quarantined(&hash_a),
                census_caught,
                "{field}: pre-unlock quarantine marks the census-caught fields"
            );
            assert_eq!(store.unlock("pw").unwrap(), 1, "{field}: the sibling must unlock");
            assert!(store.is_quarantined(&hash_a), "{field} tamper must quarantine");
            assert!(!store.is_quarantined(&hash_b), "{field}: the sibling stays usable");
            let denied = store.unseal_credential(&hash_a);
            assert!(
                matches!(denied, Err(ref e) if e.message.contains("quarantined")),
                "{field}: unseal must refuse without plaintext release"
            );
            assert!(store.unseal_credential(&hash_b).is_ok());
            store.close();
            drop(store);
            std::fs::write(&sealed_path, &honest).unwrap();
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn persist_failure_wastes_slot_never_reissues() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("persist-fail");
        let registry = format!("logos:local:{}", "fc".repeat(32));
        let commitment = [0x55u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 0);

        // An unwritable dir fails the durable persist AFTER the in-memory
        // counter advanced: the reservation errors and slot 1 stays spent.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let denied = store.reserve_message_id(&hash, "aa", 10, 9, 5, 600);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(denied, Err(ref e) if e.kind == ErrorKind::Internal), "{denied:?}");

        // The wasted slot is spent, never reissued: the quota already
        // reflects it and the next reservation skips to slot 2.
        assert_eq!(store.remaining_budget(&hash, "aa", 10, 5, 600).unwrap(), 3);
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 2);
        assert_eq!(store.remaining_budget(&hash, "aa", 10, 5, 600).unwrap(), 2);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_storm_holds_the_one_write_mutex_rule() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("storm");
        let registry = format!("logos:local:{}", "fd".repeat(32));
        let commitment = [0x56u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);

        let writer = {
            let store = Arc::clone(&store);
            let hash = hash.clone();
            std::thread::spawn(move || {
                let states = [
                    MembershipState::Pending,
                    MembershipState::Active,
                    MembershipState::Failed,
                ];
                for state in states.iter().cycle().take(50) {
                    store.update_cache(&hash, |c| c.state = *state).unwrap();
                }
            })
        };
        // 20 reservations across epochs 10..14, racing the cache storm.
        let mut issued = BTreeSet::new();
        for i in 0..20u64 {
            let epoch = 10 + i / 4;
            let slot = store.reserve_message_id(&hash, "aa", epoch, 9, 10, 600).unwrap();
            assert!(issued.insert((epoch, slot)), "reissued ({epoch}, {slot})");
        }
        writer.join().unwrap();

        // No lost updates: the final snapshot's counters equal the
        // reservations made.
        let rec = store.membership(&hash).unwrap();
        assert_eq!(rec.alloc.allocations.iter().map(|a| a.used).sum::<u64>(), 20);
        store.close();
        drop(store);

        // And the persisted state re-verifies wholesale.
        let store = Store::open(dir.clone()).unwrap();
        assert_eq!(store.unlock("pw").unwrap(), 1, "zero quarantined after the storm");
        assert!(!store.is_quarantined(&hash));
        let rec = store.membership(&hash).unwrap();
        assert_eq!(rec.alloc.allocations.iter().map(|a| a.used).sum::<u64>(), 20);
        // Continuation, never reissue: epoch 10's next slot is 4.
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 10, 600).unwrap(), 4);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overcap_allocations_file_quarantines_all() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("overcap-alloc");
        let registry = format!("logos:local:{}", "fe".repeat(32));
        let commitment_a = [0x57u8; 32];
        let commitment_b = [0x58u8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        store.close();
        drop(store);

        // A section count over the cap degrades to .bad + quarantine-all —
        // never a panic or an unbounded parse.
        let mut sections = serde_json::Map::new();
        for i in 0..=format::MAX_SECTIONS {
            sections.insert(
                format!("hash{i:04}"),
                serde_json::json!({
                    "epoch_size_sec": 600, "prune_floor": 0,
                    "allocations": [], "mac": "00".repeat(32),
                }),
            );
        }
        let file = serde_json::json!({
            "format": format::FORMAT_ALLOCATIONS,
            "version": format::FORMAT_VERSION,
            "store_uuid": "00".repeat(16),
            "sections": sections,
            "root_mac": "00".repeat(32),
        });
        std::fs::write(
            dir.join(format::ALLOCATIONS_FILE),
            serde_json::to_string(&file).unwrap(),
        )
        .unwrap();

        let store = Store::open(dir.clone()).unwrap();
        assert!(has_bad_file(&dir, format::ALLOCATIONS_FILE));
        assert!(store.is_quarantined(&hash_a));
        assert!(store.is_quarantined(&hash_b));
        let denied = store.unlock("pw");
        assert!(matches!(denied, Err(ref e) if e.message.contains("quarantined")), "{denied:?}");

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overcap_cache_file_degrades_to_defaults() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("overcap-cache");
        let registry = format!("logos:local:{}", "df".repeat(32));
        let commitment = [0x5du8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        store.close();
        drop(store);

        let oversize = vec![b' '; format::MAX_FILE_BYTES as usize + 1];
        std::fs::write(dir.join(format::CACHE_FILE), oversize).unwrap();
        let store = Store::open(dir.clone()).unwrap();
        assert!(has_bad_file(&dir, format::CACHE_FILE));
        let rec = store.membership(&hash).unwrap();
        assert!(!rec.quarantined, "cache over-cap is self-DoS, never quarantine");
        assert_eq!(rec.cache.state, MembershipState::Unknown);
        assert_eq!(store.unlock("pw").unwrap(), 1);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversize_sealed_file_refuses_open() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("oversize-sealed");
        let registry = format!("logos:local:{}", "ea".repeat(32));
        let commitment = [0x5eu8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        insert_membership(&store, &registry, &commitment);
        store.close();
        drop(store);

        // >4MiB of padding inside a JSON field: the byte cap fires before
        // any parse, and open() fails closed as Unreadable — the file is
        // never renamed or adopted (this pins the impl's actual behavior;
        // the .bad + fresh-empty path is the PARSE-cap breach's, below).
        let sealed_path = dir.join(format::SEALED_FILE);
        edit_json(&sealed_path, |v| {
            v["padding"] = " ".repeat(format::MAX_FILE_BYTES as usize + 1).into();
        });
        let denied = Store::open(dir.clone());
        assert!(
            matches!(denied, Err(OpenError::Unreadable(ref m)) if m.contains("size cap")),
            "an over-cap sealed file must refuse open as Unreadable"
        );
        assert!(sealed_path.exists(), "the oversized file stays in place");
        assert!(!has_bad_file(&dir, format::SEALED_FILE));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overcount_sealed_credentials_starts_fresh() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("overcount-sealed");
        std::fs::create_dir_all(&dir).unwrap();

        // A parse-cap breach (too many credentials) is corrupt, not a
        // refusal: .bad + fresh empty (I2b).
        let mut credentials = serde_json::Map::new();
        for i in 0..=format::MAX_CREDENTIALS {
            credentials.insert(
                format!("hash{i:04}"),
                serde_json::json!({
                    "identity": {
                        "registry_id": "r", "rln_identifier": "",
                        "identity_commitment": "11", "submitted_at": 1,
                    },
                    "nonce": "22".repeat(24), "ct": "33",
                }),
            );
        }
        let file = serde_json::json!({
            "format": format::FORMAT_SEALED,
            "version": format::FORMAT_VERSION,
            "kdf": {"m_cost_kib": 8, "t_cost": 1, "p_cost": 1, "salt": "44".repeat(16)},
            "verifier": "55".repeat(32),
            "store_uuid": "66".repeat(16),
            "credentials": credentials,
        });
        std::fs::write(dir.join(format::SEALED_FILE), serde_json::to_string(&file).unwrap())
            .unwrap();

        let store = Store::open(dir.clone()).unwrap();
        assert!(has_bad_file(&dir, format::SEALED_FILE));
        assert!(!store.has_credentials());
        assert_eq!(store.unlock("pw").unwrap(), 0, "a fresh empty store provisions");

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn insert_crash_windows_are_inert_or_healed() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("crash-windows");
        let registry = format!("logos:local:{}", "da".repeat(32));
        let commitment_a = [0x59u8; 32];
        let commitment_b = [0x5au8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash_a = insert_membership(&store, &registry, &commitment_a);
        let hash_b = insert_membership(&store, &registry, &commitment_b);
        store.close();
        drop(store);

        // (a) Crash BEFORE the sealed commit point: B's section and cache
        // row landed but no sealed entry. Both leftovers are inert, nothing
        // quarantines, and B is registerable from scratch.
        edit_json(&dir.join(format::SEALED_FILE), |v| {
            v["credentials"].as_object_mut().unwrap().remove(hash_b.as_str());
        });
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.membership(&hash_b).is_none(), "the orphan is not a membership");
        assert_eq!(store.unlock("pw").unwrap(), 1, "zero quarantined");
        assert!(!store.is_quarantined(&hash_a));
        assert_eq!(insert_membership(&store, &registry, &commitment_b), hash_b);
        assert!(store.unseal_credential(&hash_b).is_ok());
        assert_eq!(store.reserve_message_id(&hash_b, "aa", 10, 9, 5, 600).unwrap(), 0);
        store.close();
        drop(store);

        // (b) Post-commit cache loss: the row vanishes while the sealed
        // entry and section stay. Open synthesizes state Unknown and routes
        // the record to the heal path.
        edit_json(&dir.join(format::CACHE_FILE), |v| {
            v["entries"].as_object_mut().unwrap().remove(hash_b.as_str());
        });
        let store = Store::open(dir.clone()).unwrap();
        let rec = store.membership(&hash_b).unwrap();
        assert!(!rec.quarantined);
        assert_eq!(rec.cache.state, MembershipState::Unknown);
        assert!(store.refreshable_records().iter().any(|r| r.hash == hash_b));
        assert_eq!(store.unlock("pw").unwrap(), 2, "zero quarantined");

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_reads_stay_consistent_during_persist() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("snapshot-reads");
        let registry = format!("logos:local:{}", "db".repeat(32));
        let commitment = [0x5bu8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);

        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let store = Arc::clone(&store);
            let done = Arc::clone(&done);
            let registry = registry.clone();
            std::thread::spawn(move || {
                // Bounded: readers only clone the published Arc, so the loop
                // ends with the writer instead of waiting on any fsync.
                let mut last_total = 0u64;
                let mut reads = 0u64;
                loop {
                    let recs = store.records_for(&registry);
                    assert_eq!(recs.len(), 1, "a snapshot is always whole");
                    let rec = &recs[0];
                    // Never torn: counters within the limit, rows above the
                    // floor, totals monotone across observations.
                    for row in &rec.alloc.allocations {
                        assert!((1..=5).contains(&row.used));
                        assert!(row.epoch >= rec.alloc.prune_floor);
                    }
                    let total: u64 = rec.alloc.allocations.iter().map(|a| a.used).sum();
                    assert!(total >= last_total, "a snapshot went backwards");
                    last_total = total;
                    reads += 1;
                    if done.load(Ordering::Relaxed) || reads >= 5_000_000 {
                        return (reads, last_total);
                    }
                }
            })
        };
        for i in 0..20u64 {
            store.reserve_message_id(&hash, "aa", 10 + i / 5, 9, 5, 600).unwrap();
        }
        done.store(true, Ordering::Relaxed);
        let (reads, last_total) = reader.join().unwrap();
        assert!(reads > 0 && reads < 5_000_000, "the reader must terminate with the writer");
        assert!(last_total <= 20);
        let rec = store.membership(&hash).unwrap();
        assert_eq!(rec.alloc.allocations.iter().map(|a| a.used).sum::<u64>(), 20);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_updates_never_touch_covered_bytes() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("cache-bytes");
        let registry = format!("logos:local:{}", "dc".repeat(32));
        let commitment = [0x5cu8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        assert_eq!(store.reserve_message_id(&hash, "aa", 10, 9, 5, 600).unwrap(), 0);

        let sealed_before = std::fs::read(dir.join(format::SEALED_FILE)).unwrap();
        let alloc_before = std::fs::read(dir.join(format::ALLOCATIONS_FILE)).unwrap();

        // Unlocked and locked cache mutations alike: the covered files'
        // bytes are untouchable by construction.
        store.update_cache(&hash, |c| c.state = MembershipState::Active).unwrap();
        store.update_cache(&hash, |c| c.leaf_index = Some(9)).unwrap();
        store.lock();
        store.update_cache(&hash, |c| c.rate_limit = Some(100)).unwrap();
        store.update_cache(&hash, |c| c.state = MembershipState::Failed).unwrap();

        assert_eq!(std::fs::read(dir.join(format::SEALED_FILE)).unwrap(), sealed_before);
        assert_eq!(std::fs::read(dir.join(format::ALLOCATIONS_FILE)).unwrap(), alloc_before);

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_active_at_is_monotone_through_update_cache() {
        let _serial = crate::lock(&SERIAL);
        let dir = test_dir("first-active");
        let registry = format!("logos:local:{}", "dd".repeat(32));
        let commitment = [0x5fu8; 32];

        let store = Store::open(dir.clone()).unwrap();
        store.unlock("pw").unwrap();
        let hash = insert_membership(&store, &registry, &commitment);
        assert!(store.membership(&hash).unwrap().cache.first_active_at.is_none());

        store.update_cache(&hash, |c| c.state = MembershipState::Active).unwrap();
        assert!(store.membership(&hash).unwrap().cache.first_active_at.is_some());
        // Pin a sentinel through the same seam so a (buggy) re-stamp with
        // the wall clock would be visible regardless of test timing.
        store.update_cache(&hash, |c| c.first_active_at = Some(12_345)).unwrap();
        store.update_cache(&hash, |c| c.state = MembershipState::Failed).unwrap();
        store.update_cache(&hash, |c| c.state = MembershipState::Active).unwrap();
        assert_eq!(
            store.membership(&hash).unwrap().cache.first_active_at,
            Some(12_345),
            "a second activation must not restamp the monotone timestamp"
        );

        store.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
