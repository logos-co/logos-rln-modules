//! WAKU-RLN-KEYSTORE-format encrypted credential store: file schema,
//! per-credential crypto envelope, and atomic on-disk persistence.
//!
//! ## Format
//!
//! One JSON document (`rln_keystore.json` under the module instance's
//! persistence path) with a `credentials` map keyed by `membership_hash`
//! (the generalized construction of RLN-MEMBERSHIP-MANAGEMENT — see
//! `registry_id::membership_hash`). Each entry holds:
//!
//! - `crypto`: the encrypted credential envelope. PBKDF2-HMAC-SHA256 key
//!   derivation, AES-128-CTR cipher over `dk[0..16]`, and
//!   `mac = keccak256(dk[16..32] ‖ ciphertext)`. NOTE the MAC hash: the
//!   WAKU-RLN-KEYSTORE prose says SHA256, but its own test vector (password
//!   "sup3rsecure") only verifies under keccak256 — the Ethereum-V3 /
//!   nim-eth keyfile construction the nwaku ecosystem actually writes.
//!   Compatibility with real keystores wins; pinned by
//!   `spec_test_vector_decrypts`.
//! - `membership`: plaintext-safe sidecar metadata (`store::MembershipMeta`).
//!   No secrets: lifecycle state, provisional leaf/rate, timestamps. The
//!   identity-critical fields (`registry_id`, `identity_commitment`) are
//!   tamper-bound by the map key (recomputing the membership_hash must
//!   reproduce it — checked at load, see `store::init`) and authoritative
//!   copies also live INSIDE the ciphertext for post-decrypt cross-checks.
//!
//! Reads honor each envelope's own `kdfparams` (so foreign iteration counts
//! decrypt); writes use `WRITE_KDF_ROUNDS`.
//!
//! ## Sidecar authentication & its limits
//!
//! The reservation-critical sidecar state (`AllocationState` — the struct
//! IS the covered set) is HMAC'd per entry (`allocations_mac`): HMAC-SHA256
//! under a PBKDF2 key derived at unlock from the keystore password + the
//! file-level `metaMacSalt`, over a canonical payload bound to the entry's
//! membership_hash and a domain separator. Verified at every unlock: a
//! missing or mismatched MAC quarantines the entry, and a non-empty file
//! without `metaMacSalt` refuses to unlock — there is no MAC-less legacy
//! shape; entries are MAC'd from birth (every unlocked persist stamps every
//! non-quarantined entry). It CANNOT detect:
//! (1) whole-file rollback to an older honest snapshot; (2) per-entry
//! splice of an older honest (state + MAC) block; (3) an attacker who also
//! knows the password (with keychain auto-unlock in use, any same-user
//! process can read it — see `keychain`); (4) a COPIED keystore: the file
//! is self-contained, so a second live instance verifies and forks the
//! counters — migrate by moving, never copying (see README).
//! `CacheState` (`rate_limit`, `leaf_index`, …) stays OUTSIDE the MAC by
//! design: the locked-mode poller self-heals it, and tampering it is
//! self-DoS, not disclosure.
//!
//! ## Atomicity & durability
//!
//! Writes go to `rln_keystore.json.tmp` (0600), which is fsync'd, then POSIX
//! `rename`d over the target, then the directory is fsync'd — a crash
//! mid-write leaves the prior file intact, and a power cut cannot land the
//! rename without the data. An unparseable file is renamed to
//! `.bad.<unix-ts>` so the next save never overwrites evidence.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::registry_id::bytes_to_hex;

// The domain-agnostic layer — the V3-keyfile envelope and the durable-file
// primitives — lives in the sibling `logos-keystore-core` crate
// (keystore-core/); this module re-exports the pieces the store consumes so
// `keystore::` stays the single path for keystore machinery.
pub(crate) use logos_keystore_core::{
    ct_eq, decrypt, derive_key, encrypt, CryptoEnvelope, KdfParams, KeystoreError, DKLEN,
    WRITE_KDF_ROUNDS,
};

pub(crate) const KEYSTORE_FILE: &str = "rln_keystore.json";
/// Sentinel file `store::init` takes an exclusive OS lock on: two processes
/// sharing one persistence path would last-writer-wins clobber each other's
/// whole-file rewrites (allocation counters included), so the second one
/// fails closed instead.
pub(crate) const LOCK_FILE: &str = "rln_keystore.lock";

// ---------------------------------------------------------------- file schema

#[derive(Serialize, Deserialize)]
pub(crate) struct KeystoreFile {
    pub(crate) application: String,
    #[serde(rename = "appIdentifier")]
    pub(crate) app_identifier: String,
    pub(crate) credentials: BTreeMap<String, KeystoreEntry>,
    /// Salt (hex) for the sidecar-MAC key (PBKDF2 from the keystore
    /// password — see "Sidecar authentication" above). Generated at the
    /// unlock that initializes an EMPTY keystore; a non-empty file without
    /// it refuses to unlock.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "metaMacSalt")]
    pub(crate) meta_mac_salt: Option<String>,
    pub(crate) version: String,
}

impl Default for KeystoreFile {
    fn default() -> Self {
        KeystoreFile {
            application: "logos-rln-membership".to_string(),
            app_identifier: "liblogos_rln_module".to_string(),
            credentials: BTreeMap::new(),
            meta_mac_salt: None,
            version: "1".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeystoreEntry {
    pub(crate) crypto: CryptoEnvelope,
    pub(crate) membership: MembershipMeta,
}

/// The module-local lifecycle state, persisted as `MembershipMeta.state` and
/// each `StateChange.state`. `#[serde(rename_all = "snake_case")]` serializes
/// each variant to the EXACT wire string logos-lez-rln-module's
/// `rln_core::membership_status` returns (`GracePeriod → "grace_period"`);
/// the crates deliberately share no type — the `membership_state_wire_strings`
/// test anchors the contract. No `#[serde(other)]`: a stray persisted string
/// loud-fails deserialize rather than silently degrading.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MembershipState {
    Unknown,
    Pending,
    Failed,
    Active,
    GracePeriod,
    Expired,
    Erased,
}

impl MembershipState {
    /// The usable ("selectable") states: a membership that can currently back
    /// a proof — the one predicate selection, scope resolution, and the quota
    /// read all share.
    pub(crate) fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }

    /// The live states (spec): a membership that blocks a new registration for
    /// its scope — usable, or still awaiting confirmation. Terminal states
    /// (failed, expired, erased, unknown) never block a fresh registration.
    pub(crate) fn is_live(self) -> bool {
        matches!(self, Self::Pending) || self.is_usable()
    }

    /// Ever observed on the registry — the "was Active, now gone → erased"
    /// removal signal's building block (see `store::merge_state`).
    pub(crate) fn is_active_like(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::Expired | Self::Erased)
    }
}

/// The MAC-covered reservation-critical state; this struct IS the covered
/// set — a field added here is authenticated, a field added elsewhere is
/// not. Local security state with NO authoritative source to re-read (see
/// "Sidecar authentication" above), tamper-bound by `allocations_mac`.
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct AllocationState {
    /// Per-application `message_id` allocation, one row per active
    /// `(rln_identifier, current epoch)`. Plaintext-safe counters (no
    /// secret), persisted with the sidecar — fsync-durably, under
    /// `allocations_mac`, and floored by `prune_floor` — so neither a
    /// restart, power loss, sidecar edit, clock rewind, nor gap/size
    /// reconfiguration reissues a spent slot.
    /// Omitted from older files (serde default = empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allocations: Vec<crate::rate_limit::EpochAllocation>,
    /// Epoch length (seconds) `allocations` and `prune_floor` are denominated
    /// in. 0 = unset (no reservation yet); adopted from the configured
    /// `epoch_size_sec` at the first successful reservation. A
    /// reservation under a DIFFERENT configured size fails `permanent`:
    /// changing the epoch size rebases the numeric epoch indexing that keys
    /// spent slots (and their external nullifiers), which no floor conversion
    /// can make safe. Recovery: register a fresh membership.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) epoch_size_sec: u64,
    /// Monotonically NON-DECREASING allocation floor, in units of
    /// `epoch_size_sec`: epochs below it may have had rows pruned, so a
    /// reservation there is permanently refused — even when the wall clock
    /// rewinds past the window or `max_epoch_gap` is widened across restarts.
    /// Raised (never lowered) on every successful reservation.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) prune_floor: u64,
}

/// Registry-derived, poller-healed cache state, deliberately OUTSIDE the
/// MAC — mutable while locked via `Store::update_cache`. Tampering it is
/// self-DoS, not disclosure; the locked-mode poller heals it from the
/// registry.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CacheState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failed_reason: Option<String>,
    /// Provisional while pending (pre-submit estimate); authoritative after
    /// the pending→active re-read (spec MUST).
    pub(crate) leaf_index: u64,
    pub(crate) rate_limit: u64,
    /// Whether a `failed` state is worth retrying (spec: a failed submission
    /// SHALL report whether it is retryable). `None` outside the failed
    /// state (never set, or cleared on the next successful observation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retryable: Option<bool>,
    pub(crate) state: MembershipState,
    pub(crate) state_history: Vec<StateChange>,
    pub(crate) submitted_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tx_result: Option<String>,
}

/// Plaintext-safe sidecar metadata stored NEXT TO the crypto envelope.
/// `registry_id` + `identity_commitment` are tamper-bound by the entry's
/// membership_hash key (recomputed at load) and duplicated inside the
/// ciphertext; `alloc` is MAC-bound (see `AllocationState`); `cache` is
/// deliberately outside the MAC (see `CacheState`).
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MembershipMeta {
    #[serde(flatten)]
    pub(crate) alloc: AllocationState,
    /// HMAC (hex) over `alloc` — see `meta_mac`. Keyed by the
    /// unlock-derived store MAC key; recomputed for every non-quarantined
    /// entry at every unlocked persist, so entries are authenticated from
    /// birth. Missing or mismatched = quarantined at unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) allocations_mac: Option<String>,
    #[serde(flatten)]
    pub(crate) cache: CacheState,
    pub(crate) identity_commitment: String,
    pub(crate) registry_id: String,
    /// The rln_identifier of the scope that REGISTERED this membership —
    /// register's per-scope idempotency key (spec: "idempotent for a scope").
    /// Local bookkeeping only: the membership_hash excludes it (Appendix B).
    /// Empty on pre-scope records — treated as matching ANY scope.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) rln_identifier: String,
}

/// serde `skip_serializing_if` for the defaulted u64 fields: they are
/// omitted while unset (0).
fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct StateChange {
    pub(crate) at: u64,
    pub(crate) state: MembershipState,
}

// ------------------------------------------------------------- sidecar MAC

/// Derive the store-level sidecar-MAC key: PBKDF2 (WRITE_KDF_ROUNDS) from the
/// keystore password and the file's `metaMacSalt` — one derivation per
/// unlock, cached by the store. A salt distinct from every envelope's
/// kdfparams salt keeps this key independent of the credential dk.
pub(crate) fn derive_meta_mac_key(
    password: &str,
    salt_hex: &str,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    // Delegate to the one PBKDF2 site (derive_key) so the two KDF paths can
    // never drift apart — drift would silently invalidate every stored MAC.
    let params = KdfParams {
        c: WRITE_KDF_ROUNDS,
        dklen: DKLEN as u32,
        prf: "hmac-sha256".to_string(),
        salt: salt_hex.to_string(),
    };
    let dk = derive_key(password, &params)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&dk);
    Ok(key)
}

/// The canonical HMAC payload: the reservation-critical sidecar fields, bound
/// to the entry's membership_hash (no MAC transplants between entries) and a
/// version/domain separator. Serialized field order is this declaration
/// order — changing it invalidates every stored MAC.
#[derive(Serialize)]
struct MetaMacPayload<'a> {
    allocations: &'a [crate::rate_limit::EpochAllocation],
    epoch_size_sec: u64,
    membership_hash: &'a str,
    prune_floor: u64,
    v: &'static str,
}

/// HMAC-SHA256 (hex) over the entry's reservation-critical sidecar state.
pub(crate) fn meta_mac(key: &[u8; 32], membership_hash: &str, alloc: &AllocationState) -> String {
    use hmac::Mac;
    let payload = MetaMacPayload {
        allocations: &alloc.allocations,
        epoch_size_sec: alloc.epoch_size_sec,
        membership_hash,
        prune_floor: alloc.prune_floor,
        v: "rln-meta-mac-1",
    };
    // Serializing a struct of ints/strs/derived-Serialize slices cannot fail,
    // and HMAC accepts any key length.
    let bytes = serde_json::to_vec(&payload).expect("meta MAC payload serializes");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(&bytes);
    bytes_to_hex(&mac.finalize().into_bytes())
}

/// Verify an entry's `allocations_mac`. `false` when the MAC is absent,
/// malformed, or does not match the recomputation.
pub(crate) fn meta_mac_ok(key: &[u8; 32], membership_hash: &str, meta: &MembershipMeta) -> bool {
    match &meta.allocations_mac {
        Some(stored) => {
            ct_eq(meta_mac(key, membership_hash, &meta.alloc).as_bytes(), stored.as_bytes())
        }
        None => false,
    }
}

// ------------------------------------------------------------------- file IO
//
// Both delegate to logos-keystore-core's durable-file layer: fail-closed
// loads with `.bad.<ts>` evidence preservation, and the fsync-atomic 0600
// write (write → fsync(tmp) → rename → fsync(dir)).

pub(crate) fn load(dir: &Path) -> io::Result<KeystoreFile> {
    logos_keystore_core::load_json(dir, KEYSTORE_FILE)
}

pub(crate) fn save_atomic(dir: &Path, file: &KeystoreFile) -> io::Result<()> {
    logos_keystore_core::write_durable_json(dir, KEYSTORE_FILE, file)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Golden vector pinning the sidecar-MAC payload bytes: the covered set
    /// (allocations, epoch_size_sec, prune_floor, bound to membership_hash and
    /// the domain tag) and its serialized field order. If this assertion ever
    /// fails, every stored `allocations_mac` in existing keystores is
    /// invalidated — that must be a deliberate, versioned decision, never a
    /// refactor side effect.
    #[test]
    fn meta_mac_golden_vector() {
        let key = [0x42u8; 32];
        let hash = "6fd7bb69f9d54371c1b26e57e0f4f108c018de65e4e214d8ec858e1d3855c0e2";
        let mut meta = MembershipMeta {
            alloc: AllocationState {
                allocations: vec![
                    crate::rate_limit::EpochAllocation {
                        rln_identifier: "ab".repeat(32),
                        epoch: 41,
                        used: 2,
                    },
                    crate::rate_limit::EpochAllocation {
                        rln_identifier: "cd".repeat(32),
                        epoch: 43,
                        used: 1,
                    },
                ],
                epoch_size_sec: 600,
                prune_floor: 7,
            },
            allocations_mac: None,
            cache: CacheState {
                failed_reason: None,
                leaf_index: 5,
                rate_limit: 100,
                retryable: None,
                state: MembershipState::Active,
                state_history: Vec::new(),
                submitted_at: 1_700_000_000,
                tx_result: None,
            },
            identity_commitment: "11".repeat(32),
            registry_id: "logos:local:test".into(),
            rln_identifier: "ab".repeat(32),
        };
        let mac = meta_mac(&key, hash, &meta.alloc);
        // Fields outside the covered set must not perturb the MAC.
        meta.cache.leaf_index = 999;
        meta.cache.rate_limit = 1;
        meta.cache.state = MembershipState::Failed;
        meta.cache.tx_result = Some("tx".into());
        assert_eq!(meta_mac(&key, hash, &meta.alloc), mac, "non-covered fields leaked into the MAC");
        assert_eq!(mac, "577ba1b62829c35f52a406f06940de8005267ba96a4bfb4edbd13c1a78356472");
    }

    #[test]
    fn load_missing_is_fresh_and_save_roundtrips() {
        let dir = std::env::temp_dir().join(format!(
            "rln-ms-keystore-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);

        let fresh = load(&dir).unwrap();
        assert!(fresh.credentials.is_empty());
        save_atomic(&dir, &fresh).unwrap();
        let reloaded = load(&dir).unwrap();
        assert_eq!(reloaded.application, "logos-rln-membership");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(KEYSTORE_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "keystore must be private to the owner");
        }

        // Corrupt file → quarantined to .bad.<ts>, fresh keystore returned.
        fs::write(dir.join(KEYSTORE_FILE), "{not json").unwrap();
        let recovered = load(&dir).unwrap();
        assert!(recovered.credentials.is_empty());
        let quarantined = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".bad."));
        assert!(quarantined, "corrupt keystore must be moved aside");
        let _ = fs::remove_dir_all(&dir);
    }
}
