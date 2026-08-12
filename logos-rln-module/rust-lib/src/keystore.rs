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
//! ## Atomicity
//!
//! Writes go to `rln_keystore.json.tmp`, then POSIX `rename` over the
//! target — a crash mid-write leaves the prior file intact. An unparseable
//! file is renamed to `.bad.<unix-ts>` so the next save never overwrites
//! evidence.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::registry_id::{bytes_to_hex, hex_to_vec};

pub(crate) const KEYSTORE_FILE: &str = "rln_keystore.json";
/// PBKDF2 rounds for envelopes THIS module writes — the nwaku ecosystem
/// default (and the spec vector's count). Reads honor stored kdfparams.
const WRITE_KDF_ROUNDS: u32 = 1_000_000;
const DKLEN: usize = 32;

#[derive(Debug)]
pub(crate) enum KeystoreError {
    /// MAC verification failed — wrong password or tampered ciphertext.
    BadPassword,
    /// Envelope declares a cipher/kdf/prf/dklen this module doesn't speak.
    Unsupported(&'static str),
    /// Hex/length problems in envelope fields.
    Malformed(&'static str),
    /// No CSPRNG available (encrypt only).
    NoEntropy,
}

impl core::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeystoreError::BadPassword => write!(f, "MAC mismatch (wrong password or tampered data)"),
            KeystoreError::Unsupported(what) => write!(f, "unsupported {what}"),
            KeystoreError::Malformed(what) => write!(f, "malformed {what}"),
            KeystoreError::NoEntropy => write!(f, "no CSPRNG available"),
        }
    }
}

// ---------------------------------------------------------------- file schema

#[derive(Serialize, Deserialize)]
pub(crate) struct KeystoreFile {
    pub(crate) application: String,
    #[serde(rename = "appIdentifier")]
    pub(crate) app_identifier: String,
    pub(crate) credentials: BTreeMap<String, KeystoreEntry>,
    pub(crate) version: String,
}

impl Default for KeystoreFile {
    fn default() -> Self {
        KeystoreFile {
            application: "logos-rln-membership".to_string(),
            app_identifier: "liblogos_rln_module".to_string(),
            credentials: BTreeMap::new(),
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

/// Plaintext-safe sidecar metadata stored NEXT TO the crypto envelope.
/// `registry_id` + `identity_commitment` are tamper-bound by the entry's
/// membership_hash key (recomputed at load) and duplicated inside the
/// ciphertext; the rest are self-healing caches of registry state.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct MembershipMeta {
    /// Per-application `message_id` allocation, one row per active
    /// `(rln_identifier, current epoch)`. Plaintext-safe counters; persisted
    /// with the sidecar so a restart never reissues a spent slot.
    /// Omitted from older files (serde default = empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allocations: Vec<crate::rate_limit::EpochAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failed_reason: Option<String>,
    pub(crate) identity_commitment: String,
    /// Provisional while pending (pre-submit estimate); authoritative after
    /// the pending→active re-read (spec MUST).
    pub(crate) leaf_index: u64,
    pub(crate) rate_limit: u64,
    pub(crate) registry_id: String,
    /// Whether a `failed` state is worth retrying (spec: a failed submission
    /// SHALL report whether it is retryable). `None` outside the failed
    /// state (never set, or cleared on the next successful observation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retryable: Option<bool>,
    /// The rln_identifier of the scope that REGISTERED this membership —
    /// register's per-scope idempotency key (spec: "idempotent for a scope").
    /// Local bookkeeping only: the membership_hash excludes it (Appendix B).
    /// Empty on pre-scope records — treated as matching ANY scope.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) rln_identifier: String,
    pub(crate) state: MembershipState,
    pub(crate) state_history: Vec<StateChange>,
    pub(crate) submitted_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tx_result: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct StateChange {
    pub(crate) at: u64,
    pub(crate) state: MembershipState,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CryptoEnvelope {
    pub(crate) cipher: String,
    pub(crate) cipherparams: CipherParams,
    pub(crate) ciphertext: String,
    pub(crate) kdf: String,
    pub(crate) kdfparams: KdfParams,
    pub(crate) mac: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct CipherParams {
    pub(crate) iv: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KdfParams {
    pub(crate) c: u32,
    pub(crate) dklen: u32,
    pub(crate) prf: String,
    pub(crate) salt: String,
}

// -------------------------------------------------------------------- crypto

fn derive_key(password: &str, params: &KdfParams) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if params.prf != "hmac-sha256" {
        return Err(KeystoreError::Unsupported("kdf prf"));
    }
    if params.dklen as usize != DKLEN {
        return Err(KeystoreError::Unsupported("kdf dklen"));
    }
    let salt = hex_to_vec(&params.salt).ok_or(KeystoreError::Malformed("kdf salt"))?;
    let mut dk = Zeroizing::new(vec![0u8; DKLEN]);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, params.c, &mut dk)
        .map_err(|_| KeystoreError::Malformed("kdf output length"))?;
    Ok(dk)
}

/// The V3-keyfile checksum the spec vector pins (see module docs).
fn mac_bytes(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&dk[16..32]);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Constant-time-ish comparison: MAC bytes never early-exit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn apply_aes128ctr(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<(), KeystoreError> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
        .map_err(|_| KeystoreError::Malformed("cipher key/iv length"))?;
    cipher.apply_keystream(buf);
    Ok(())
}

/// Encrypt one credential plaintext under `password` with fresh salt + IV.
pub(crate) fn encrypt(password: &str, plaintext: &[u8]) -> Result<CryptoEnvelope, KeystoreError> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| KeystoreError::NoEntropy)?;
    getrandom::getrandom(&mut iv).map_err(|_| KeystoreError::NoEntropy)?;

    let kdfparams = KdfParams {
        c: WRITE_KDF_ROUNDS,
        dklen: DKLEN as u32,
        prf: "hmac-sha256".to_string(),
        salt: bytes_to_hex(&salt),
    };
    let dk = derive_key(password, &kdfparams)?;

    let mut buf = plaintext.to_vec();
    apply_aes128ctr(&dk[..16], &iv, &mut buf)?;
    let mac = mac_bytes(&dk, &buf);

    Ok(CryptoEnvelope {
        cipher: "aes-128-ctr".to_string(),
        cipherparams: CipherParams { iv: bytes_to_hex(&iv) },
        ciphertext: bytes_to_hex(&buf),
        kdf: "pbkdf2".to_string(),
        kdfparams,
        mac: bytes_to_hex(&mac),
    })
}

/// MAC-verify then decrypt. `BadPassword` covers both a wrong password and
/// a tampered ciphertext/mac — indistinguishable by construction.
pub(crate) fn decrypt(
    password: &str,
    envelope: &CryptoEnvelope,
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    if envelope.cipher != "aes-128-ctr" {
        return Err(KeystoreError::Unsupported("cipher"));
    }
    if envelope.kdf != "pbkdf2" {
        return Err(KeystoreError::Unsupported("kdf"));
    }
    let iv = hex_to_vec(&envelope.cipherparams.iv)
        .filter(|v| v.len() == 16)
        .ok_or(KeystoreError::Malformed("cipher iv"))?;
    let ciphertext = hex_to_vec(&envelope.ciphertext).ok_or(KeystoreError::Malformed("ciphertext"))?;
    let mac = hex_to_vec(&envelope.mac).ok_or(KeystoreError::Malformed("mac"))?;

    let dk = derive_key(password, &envelope.kdfparams)?;
    if !ct_eq(&mac_bytes(&dk, &ciphertext), &mac) {
        return Err(KeystoreError::BadPassword);
    }

    let mut buf = Zeroizing::new(ciphertext);
    apply_aes128ctr(&dk[..16], &iv, &mut buf)?;
    Ok(buf)
}

// ------------------------------------------------------------------- file IO

/// Load the keystore. A missing file is a fresh (empty) one; an unparseable
/// file is quarantined to `.bad.<ts>` and replaced. A file that EXISTS but
/// cannot be read (EIO/EACCES/…) returns `Err`: the caller MUST fail closed —
/// treating "unreadable" as "empty" would invent a new secret over, then
/// clobber, credentials that were merely temporarily unreadable.
pub(crate) fn load(dir: &Path) -> io::Result<KeystoreFile> {
    let path = dir.join(KEYSTORE_FILE);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(KeystoreFile::default()),
        Err(e) => return Err(e),
    };
    match serde_json::from_str::<KeystoreFile>(&raw) {
        Ok(file) => Ok(file),
        Err(e) => {
            let ts = crate::now_unix();
            let bad = dir.join(format!("{KEYSTORE_FILE}.bad.{ts}"));
            eprintln!("keystore: unparseable ({e}); attempting to move aside to {}", bad.display());
            if let Err(re) = fs::rename(&path, &bad) {
                eprintln!("keystore: quarantine rename failed ({re}); bad file left in place");
            }
            Ok(KeystoreFile::default())
        }
    }
}

/// tmp + rename write; creates `dir` if needed.
pub(crate) fn save_atomic(dir: &Path, file: &KeystoreFile) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{KEYSTORE_FILE}.tmp"));
    let json = serde_json::to_string_pretty(file).map_err(io::Error::other)?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, dir.join(KEYSTORE_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let plaintext = br#"{"identity_secret_hash":"deadbeef"}"#;
        let env = encrypt("hunter2", plaintext).unwrap();
        assert_eq!(env.cipher, "aes-128-ctr");
        assert_eq!(env.kdfparams.c, WRITE_KDF_ROUNDS);
        let out = decrypt("hunter2", &env).unwrap();
        assert_eq!(&out[..], plaintext);
        assert!(matches!(decrypt("hunter3", &env), Err(KeystoreError::BadPassword)));
    }

    #[test]
    fn tampering_any_crypto_field_is_detected() {
        let env = encrypt("pw", b"secret bytes").unwrap();
        let mut flip_ct = env.clone();
        // Flip one ciphertext nibble.
        let mut ct = flip_ct.ciphertext.into_bytes();
        ct[0] = if ct[0] == b'0' { b'1' } else { b'0' };
        flip_ct.ciphertext = String::from_utf8(ct).unwrap();
        assert!(matches!(decrypt("pw", &flip_ct), Err(KeystoreError::BadPassword)));

        let mut flip_mac = env.clone();
        let mut mac = flip_mac.mac.into_bytes();
        mac[0] = if mac[0] == b'0' { b'1' } else { b'0' };
        flip_mac.mac = String::from_utf8(mac).unwrap();
        assert!(matches!(decrypt("pw", &flip_mac), Err(KeystoreError::BadPassword)));

        let mut flip_salt = env.clone();
        let mut salt = flip_salt.kdfparams.salt.into_bytes();
        salt[0] = if salt[0] == b'0' { b'1' } else { b'0' };
        flip_salt.kdfparams.salt = String::from_utf8(salt).unwrap();
        assert!(matches!(decrypt("pw", &flip_salt), Err(KeystoreError::BadPassword)));

        // A flipped IV survives the MAC (the IV isn't MAC'd in V3 keyfiles)
        // but must yield garbage, not the plaintext.
        let mut flip_iv = env;
        let mut iv = flip_iv.cipherparams.iv.into_bytes();
        iv[0] = if iv[0] == b'0' { b'1' } else { b'0' };
        flip_iv.cipherparams.iv = String::from_utf8(iv).unwrap();
        let out = decrypt("pw", &flip_iv).unwrap();
        assert_ne!(&out[..], b"secret bytes");
    }

    // The WAKU-RLN-KEYSTORE test vector (password "sup3rsecure"): MAC
    // verifies under keccak256(dk[16..32] ‖ ct) — NOT the SHA256 the spec
    // prose claims — and the plaintext decrypts to JSON. Pins wire-level
    // compatibility with real nwaku keystores.
    #[test]
    fn spec_test_vector_decrypts() {
        let envelope = CryptoEnvelope {
            cipher: "aes-128-ctr".to_string(),
            cipherparams: CipherParams {
                iv: "fd6b39eb71d44c59f6bf5ff3d8945c80".to_string(),
            },
            ciphertext: "9c72f47ce95de03ed34502d0288e7576b66b51b9e7d5ae882c27bd89f94e6a03c2c44c2ddf0c982e72003d67212105f1b64614f57cabb0ceadab7e07be165eee1121ad6b81951368a9f3be2dd99ea294515f6013d5f2bd4702a40e36cfde2ea298b23b31e5ce719d8040c3331f73d6bf44f88bca39bac0e917d8bf545500e4f40d321c235426a80f315ac70666acbd3bdf803fbc1e7e7103fed466525ed332b25d72b2dbedf6fa383b2305987c1fe276b029570519b3e79930edf08c1029868d05c2c08ab61d7c64f63c054b4f6a5a12d43cdc79751b6fe58d3ed26b69443eb7c9f7efce27912340129c91b6b813ac94efd5776a40b1dda896d61357de208c7c47a14af911cc231355c8093ee6626e89c07e1037f9e0b22c690e3e049014399ca0212c509cb04c71c7860d1b17a0c47711c490c27bad2825926148a1f15a507f36ba2cdaa04897fce2914e53caed0beaf1bebd2a83af76511cc15bff2165ff0860ad6eca1f30022d7739b2a6b6a72f2feeef0f5941183cda015b4631469e1f4cf27003cab9a90920301cb30d95e4554686922dc5a05c13dfb575cdf113c700d607896011970e6ee7d6edb61210ab28ac8f0c84c606c097e3e300f0a5f5341edfd15432bef6225a498726b62a98283829ad51023b2987f30686cfb4ea3951f3957654035ec291f9b0964a3a8665d81b16cec20fb40f944d5f9bf03ac1e444ad45bae3fa85e7465ce620c0966d8148d6e2856f676c4fbbe3ebe470453efb4bbda1866680037917e37765f680e3da96ef3991f3fe5cda80c523996c2234758bf5f7b6d052dc6942f5a92c8b8eec5d2d8940203bbb6b1cba7b7ebc1334334ca69cdb509a5ea58ec6b2ebaea52307589eaae9430eb15ad234c0c39c83accdf3b77e52a616e345209c5bc9b442f9f0fa96836d9342f983a7".to_string(),
            kdf: "pbkdf2".to_string(),
            kdfparams: KdfParams {
                c: 1_000_000,
                dklen: 32,
                prf: "hmac-sha256".to_string(),
                salt: "60f0aa92fbf63a8356dfdbed2ab18058".to_string(),
            },
            mac: "51a227ac6db7f2797c63925880b3db664e034231a4c68daa919ab42d8df38bc6".to_string(),
        };
        let plaintext = decrypt("sup3rsecure", &envelope).expect("vector must decrypt");
        let text = std::str::from_utf8(&plaintext).expect("utf8 plaintext");
        let value: serde_json::Value =
            serde_json::from_str(text).expect("vector plaintext is JSON");
        assert!(value.is_object());
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
