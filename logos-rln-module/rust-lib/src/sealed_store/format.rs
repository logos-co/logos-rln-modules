//! The on-disk format layer: file names, serde schemas for the sealed and
//! allocations files, the canonical byte encodings behind every AAD and MAC,
//! pre-unlock parse caps for hostile input, and old-format detection.

use std::collections::BTreeMap;
use std::path::Path;

use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::sealed_store::crypto::KdfParams;

pub const SEALED_FILE: &str = "rln_sealed.json";
pub const ALLOCATIONS_FILE: &str = "rln_allocations.json";
pub const CACHE_FILE: &str = "rln_cache.json";
// Never rename: pre-0.6.0 and current binaries must contend on one lock.
pub const LOCK_FILE: &str = "rln_keystore.lock";
pub const OLD_FORMAT_FILE: &str = "rln_keystore.json";

pub const FORMAT_SEALED: &str = "rln-sealed-store";
pub const FORMAT_ALLOCATIONS: &str = "rln-sealed-allocations";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedFile {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub verifier: String,   // hex, 32 bytes
    pub store_uuid: String, // hex, 16 bytes
    pub credentials: BTreeMap<String, SealedEntry>, // keyed by membership_hash
}

impl SealedFile {
    pub fn provision(kdf: KdfParams, verifier_hex: String, store_uuid_hex: String) -> SealedFile {
        SealedFile {
            format: FORMAT_SEALED.to_string(),
            version: FORMAT_VERSION,
            kdf,
            verifier: verifier_hex,
            store_uuid: store_uuid_hex,
            credentials: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedEntry {
    pub identity: IdentityBlock,
    pub nonce: String, // hex, 24 bytes
    pub ct: String,    // hex
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityBlock {
    pub registry_id: String,
    pub rln_identifier: String,
    pub identity_commitment: String,
    pub submitted_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AllocationsFile {
    pub format: String,
    pub version: u32,
    pub store_uuid: String,
    pub sections: BTreeMap<String, Section>, // keyed by membership_hash
    pub root_mac: String, // hex, 32 bytes
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Section {
    pub epoch_size_sec: u64,
    pub prune_floor: u64,
    pub allocations: Vec<AllocRow>,
    pub mac: String, // hex, 32 bytes
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AllocRow {
    pub rln_identifier: String,
    pub epoch: u64,
    pub used: u64,
}

// The frozen authenticated surface. These canonical byte encodings are what
// the credential AEAD's AAD and the ledger HMACs bind; the golden-vector
// tests below pin them byte for byte. Never change an encoding without a
// format version bump.

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

pub fn credential_aad(
    membership_hash: &str,
    identity: &IdentityBlock,
    store_uuid: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"rln-sealed/v1/credential");
    put_str(&mut buf, membership_hash);
    put_str(&mut buf, &identity.registry_id);
    put_str(&mut buf, &identity.rln_identifier);
    put_str(&mut buf, &identity.identity_commitment);
    buf.extend_from_slice(&identity.submitted_at.to_be_bytes());
    buf.extend_from_slice(store_uuid);
    buf
}

pub fn section_mac_payload(
    membership_hash: &str,
    epoch_size_sec: u64,
    prune_floor: u64,
    rows: &[AllocRow],
    store_uuid: &[u8; 16],
) -> Vec<u8> {
    let mut sorted: Vec<&AllocRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.rln_identifier.cmp(&b.rln_identifier).then(a.epoch.cmp(&b.epoch)));
    let mut buf = Vec::new();
    buf.extend_from_slice(b"rln-sealed/v1/section");
    put_str(&mut buf, membership_hash);
    buf.extend_from_slice(store_uuid);
    buf.extend_from_slice(&epoch_size_sec.to_be_bytes());
    buf.extend_from_slice(&prune_floor.to_be_bytes());
    buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for row in sorted {
        put_str(&mut buf, &row.rln_identifier);
        buf.extend_from_slice(&row.epoch.to_be_bytes());
        buf.extend_from_slice(&row.used.to_be_bytes());
    }
    buf
}

pub fn root_mac_payload(
    section_macs: &BTreeMap<String, [u8; 32]>,
    store_uuid: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"rln-sealed/v1/root");
    buf.extend_from_slice(store_uuid);
    buf.extend_from_slice(&(section_macs.len() as u32).to_be_bytes());
    for (membership_hash, section_mac) in section_macs {
        put_str(&mut buf, membership_hash);
        buf.extend_from_slice(section_mac);
    }
    buf
}

pub fn mac(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    // HMAC's own key schedule zero-pads a short key to the block size; doing
    // it by hand keeps construction infallible under panic=abort.
    let mut block = hmac::digest::Key::<hmac::Hmac<Sha256>>::default();
    block[..32].copy_from_slice(key);
    let mut h = hmac::Hmac::<Sha256>::new(&block);
    h.update(payload);
    h.finalize().into_bytes().into()
}

pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024; // each of the three files
pub const MAX_CREDENTIALS: usize = 1024;
pub const MAX_SECTIONS: usize = 1024;
pub const MAX_ROWS_PER_SECTION: usize = 4096;

pub fn check_sealed_caps(f: &SealedFile) -> Result<(), &'static str> {
    if f.credentials.len() > MAX_CREDENTIALS {
        return Err("too many credentials");
    }
    Ok(())
}

pub fn check_allocations_caps(f: &AllocationsFile) -> Result<(), &'static str> {
    if f.sections.len() > MAX_SECTIONS {
        return Err("too many sections");
    }
    for section in f.sections.values() {
        if section.allocations.len() > MAX_ROWS_PER_SECTION {
            return Err("too many allocation rows in a section");
        }
    }
    Ok(())
}

pub fn file_within_cap(path: &Path) -> std::io::Result<bool> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.len() <= MAX_FILE_BYTES),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatPresence {
    Neither,
    NewOnly,
    OldOnly,
    Both,
}

pub fn detect(dir: &Path) -> FormatPresence {
    match (dir.join(SEALED_FILE).exists(), dir.join(OLD_FORMAT_FILE).exists()) {
        (false, false) => FormatPresence::Neither,
        (true, false) => FormatPresence::NewOnly,
        (false, true) => FormatPresence::OldOnly,
        (true, true) => FormatPresence::Both,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_store::hex::bytes_to_hex;

    const UUID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    const KEY: [u8; 32] = [0x42; 32];
    const MEMBERSHIP_HASH: &str = "6d656d626572736869702d68617368";
    const SECOND_HASH: &str = "7365636f6e64";

    fn identity() -> IdentityBlock {
        IdentityBlock {
            registry_id: "eip155:1:0x00000000000000000000000000000000000000aa".to_string(),
            rln_identifier: "0xdeadbeef".to_string(),
            identity_commitment: "0x1234".to_string(),
            submitted_at: 1_700_000_000,
        }
    }

    fn row(rln_identifier: &str, epoch: u64, used: u64) -> AllocRow {
        AllocRow { rln_identifier: rln_identifier.to_string(), epoch, used }
    }

    // Deliberately unsorted: "0xbeef" must come out first in the payload.
    fn rows() -> Vec<AllocRow> {
        vec![row("0xdeadbeef", 9, 2), row("0xbeef", 8, 1)]
    }

    #[test]
    fn credential_aad_matches_golden_vector() {
        let aad = credential_aad(MEMBERSHIP_HASH, &identity(), &UUID);
        assert_eq!(
            bytes_to_hex(&aad),
            "726c6e2d7365616c65642f76312f63726564656e7469616c0000001e3664363536643632363537323733\
             36383639373032643638363137333638000000336569703135353a313a30783030303030303030303030\
             30303030303030303030303030303030303030303030303030303061610000000a307864656164626565\
             6600000006307831323334000000006553f100000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn section_payload_and_mac_match_golden_vectors() {
        let payload = section_mac_payload(MEMBERSHIP_HASH, 600, 7, &rows(), &UUID);
        assert_eq!(
            bytes_to_hex(&payload),
            "726c6e2d7365616c65642f76312f73656374696f6e0000001e3664363536643632363537323733363836\
             39373032643638363137333638000102030405060708090a0b0c0d0e0f00000000000002580000000000\
             0000070000000200000006307862656566000000000000000800000000000000010000000a3078646561\
             646265656600000000000000090000000000000002"
        );
        assert_eq!(
            bytes_to_hex(&mac(&KEY, &payload)),
            "7665f3886b1e6016e01f4c231ac6b0aa71a41d7a72b23798d2fdeac8cc971974"
        );
    }

    #[test]
    fn root_payload_and_mac_match_golden_vectors() {
        let mut section_macs = BTreeMap::new();
        section_macs.insert(
            MEMBERSHIP_HASH.to_string(),
            mac(&KEY, &section_mac_payload(MEMBERSHIP_HASH, 600, 7, &rows(), &UUID)),
        );
        section_macs.insert(
            SECOND_HASH.to_string(),
            mac(&KEY, &section_mac_payload(SECOND_HASH, 0, 0, &[], &UUID)),
        );
        let payload = root_mac_payload(&section_macs, &UUID);
        assert_eq!(
            bytes_to_hex(&payload),
            "726c6e2d7365616c65642f76312f726f6f74000102030405060708090a0b0c0d0e0f000000020000001e\
             3664363536643632363537323733363836393730326436383631373336387665f3886b1e6016e01f4c23\
             1ac6b0aa71a41d7a72b23798d2fdeac8cc9719740000000c373336353633366636653634970b7c7cc217\
             2e9f4a9eaf8529eb9110f6f2067b974cbf1b6776dfbcc2c52507"
        );
        assert_eq!(
            bytes_to_hex(&mac(&KEY, &payload)),
            "700868e8de8406704fcc63217045f75b18f04262b6b6b037d626f77e5fa11e26"
        );
    }

    #[test]
    fn section_payload_is_input_order_independent() {
        let forward = rows();
        let mut reversed = rows();
        reversed.reverse();
        let a = section_mac_payload(MEMBERSHIP_HASH, 600, 7, &forward, &UUID);
        let b = section_mac_payload(MEMBERSHIP_HASH, 600, 7, &reversed, &UUID);
        assert_eq!(a, b);
        // And the input itself is untouched.
        assert_eq!(forward[0].rln_identifier, "0xdeadbeef");
    }

    fn sealed_with(n: usize) -> SealedFile {
        let mut f = SealedFile::provision(
            KdfParams::fast_for_tests(),
            "aa".repeat(32),
            bytes_to_hex(&UUID),
        );
        for i in 0..n {
            f.credentials.insert(
                format!("hash{i:04}"),
                SealedEntry { identity: identity(), nonce: "bb".repeat(24), ct: "cc".into() },
            );
        }
        f
    }

    fn allocations_with(sections: usize, rows_each: usize) -> AllocationsFile {
        let mut f = AllocationsFile {
            format: FORMAT_ALLOCATIONS.to_string(),
            version: FORMAT_VERSION,
            store_uuid: bytes_to_hex(&UUID),
            sections: BTreeMap::new(),
            root_mac: "00".repeat(32),
        };
        for i in 0..sections {
            f.sections.insert(
                format!("hash{i:04}"),
                Section {
                    epoch_size_sec: 600,
                    prune_floor: 0,
                    allocations: (0..rows_each).map(|e| row("0xid", e as u64, 1)).collect(),
                    mac: "00".repeat(32),
                },
            );
        }
        f
    }

    #[test]
    fn caps_accept_at_limit_and_reject_over_limit() {
        assert!(check_sealed_caps(&sealed_with(MAX_CREDENTIALS)).is_ok());
        assert!(check_sealed_caps(&sealed_with(MAX_CREDENTIALS + 1)).is_err());
        assert!(check_allocations_caps(&allocations_with(MAX_SECTIONS, 0)).is_ok());
        assert!(check_allocations_caps(&allocations_with(MAX_SECTIONS + 1, 0)).is_err());
        assert!(check_allocations_caps(&allocations_with(1, MAX_ROWS_PER_SECTION)).is_ok());
        assert!(check_allocations_caps(&allocations_with(1, MAX_ROWS_PER_SECTION + 1)).is_err());
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sealed-format-test-{tag}-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_cap_is_true_for_missing_and_small_false_for_oversize() {
        let dir = tmp_dir("cap");
        assert!(file_within_cap(&dir.join("absent.json")).unwrap());
        std::fs::write(dir.join("small.json"), b"{}").unwrap();
        assert!(file_within_cap(&dir.join("small.json")).unwrap());
        std::fs::write(dir.join("big.json"), vec![0u8; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(!file_within_cap(&dir.join("big.json")).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_covers_all_four_presence_states() {
        let dir = tmp_dir("detect");
        assert_eq!(detect(&dir), FormatPresence::Neither);
        std::fs::write(dir.join(OLD_FORMAT_FILE), b"{}").unwrap();
        assert_eq!(detect(&dir), FormatPresence::OldOnly);
        std::fs::write(dir.join(SEALED_FILE), b"{}").unwrap();
        assert_eq!(detect(&dir), FormatPresence::Both);
        std::fs::remove_file(dir.join(OLD_FORMAT_FILE)).unwrap();
        assert_eq!(detect(&dir), FormatPresence::NewOnly);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sealed_file_roundtrips_through_json() {
        let f = sealed_with(3);
        let json = serde_json::to_string_pretty(&f).unwrap();
        let back: SealedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string_pretty(&back).unwrap(), json);
        assert_eq!(back.format, FORMAT_SEALED);
        assert_eq!(back.version, FORMAT_VERSION);
        assert_eq!(back.store_uuid, bytes_to_hex(&UUID));
        assert_eq!(back.credentials.len(), 3);
        let entry = &back.credentials["hash0000"];
        assert_eq!(entry.identity.registry_id, identity().registry_id);
        assert_eq!(entry.identity.submitted_at, 1_700_000_000);
        assert_eq!(entry.nonce, "bb".repeat(24));
    }

    #[test]
    fn allocations_file_roundtrips_through_json() {
        let f = allocations_with(2, 2);
        let json = serde_json::to_string_pretty(&f).unwrap();
        let back: AllocationsFile = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string_pretty(&back).unwrap(), json);
        assert_eq!(back.format, FORMAT_ALLOCATIONS);
        assert_eq!(back.sections.len(), 2);
        let section = &back.sections["hash0001"];
        assert_eq!(section.epoch_size_sec, 600);
        assert_eq!(section.allocations.len(), 2);
        assert_eq!(section.allocations[1].epoch, 1);
        // BTreeMap keys serialize in sorted order.
        assert!(json.find("hash0000").unwrap() < json.find("hash0001").unwrap());
    }
}
