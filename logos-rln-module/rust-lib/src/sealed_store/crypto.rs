//! The sealed-store crypto layer: Argon2id password KDF → HKDF-SHA256
//! sub-keys → XChaCha20-Poly1305 AEAD. Nonce and AAD both sit under the
//! AEAD tag, so every tamper is a hard failure.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::sealed_store::hex::{bytes_to_hex, hex_to_vec};

#[derive(Debug)]
pub enum CryptoError {
    /// AEAD open failed — wrong password or tampered ciphertext/AAD/nonce.
    BadPassword,
    /// Hex/length problems in stored fields.
    Malformed(&'static str),
    /// Header declares parameters this crate doesn't speak. Reserved for
    /// format evolution — nothing constructs it yet.
    #[allow(dead_code)]
    Unsupported(&'static str),
    /// No CSPRNG available (seal/generate only).
    NoEntropy,
    /// KDF machinery rejected its inputs.
    Kdf(&'static str),
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::BadPassword => {
                write!(f, "AEAD open failed (wrong password or tampered data)")
            }
            CryptoError::Malformed(what) => write!(f, "malformed {what}"),
            CryptoError::Unsupported(what) => write!(f, "unsupported {what}"),
            CryptoError::NoEntropy => write!(f, "no CSPRNG available"),
            CryptoError::Kdf(what) => write!(f, "kdf failure: {what}"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String, // hex, 16 bytes
}

impl KdfParams {
    pub fn generate() -> Result<KdfParams, CryptoError> {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| CryptoError::NoEntropy)?;
        Ok(KdfParams { m_cost_kib: 65536, t_cost: 3, p_cost: 1, salt: bytes_to_hex(&salt) })
    }

    #[cfg(test)]
    pub fn fast_for_tests() -> KdfParams {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).expect("test entropy");
        KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1, salt: bytes_to_hex(&salt) }
    }
}

// The accounting seam: a later test pins "unlock = exactly one KDF run".
#[cfg(test)]
static KDF_RUNS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub fn kdf_runs() -> u64 {
    KDF_RUNS.load(core::sync::atomic::Ordering::Relaxed)
}

pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn derive(password: &str, params: &KdfParams) -> Result<MasterKey, CryptoError> {
        #[cfg(test)]
        KDF_RUNS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let salt = hex_to_vec(&params.salt).ok_or(CryptoError::Malformed("kdf salt"))?;
        if salt.len() != 16 {
            return Err(CryptoError::Malformed("kdf salt length"));
        }
        let argon_params =
            argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
                .map_err(|_| CryptoError::Kdf("argon2 params"))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
        let mut out = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(password.as_bytes(), &salt, &mut out[..])
            .map_err(|_| CryptoError::Kdf("argon2 derive"))?;
        Ok(MasterKey(out))
    }
}

pub struct SubKeys {
    pub verify: Zeroizing<[u8; 32]>,
    pub seal: Zeroizing<[u8; 32]>,
    pub ledger: Zeroizing<[u8; 32]>,
}

impl SubKeys {
    pub fn derive(mk: &MasterKey) -> Result<SubKeys, CryptoError> {
        let hk = Hkdf::<Sha256>::from_prk(&*mk.0).map_err(|_| CryptoError::Kdf("hkdf prk"))?;
        Ok(SubKeys {
            verify: expand32(&hk, b"rln-sealed/v1/verify")?,
            seal: expand32(&hk, b"rln-sealed/v1/seal")?,
            ledger: expand32(&hk, b"rln-sealed/v1/ledger")?,
        })
    }
}

fn expand32(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..]).map_err(|_| CryptoError::Kdf("hkdf expand"))?;
    Ok(out)
}

pub fn seal(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::NoEntropy)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Malformed("aead input"))?;
    Ok((nonce, ct))
}

pub fn unseal(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce: [u8; 24] =
        nonce.try_into().map_err(|_| CryptoError::Malformed("nonce length"))?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::BadPassword)?;
    Ok(Zeroizing::new(pt))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_key() -> Zeroizing<[u8; 32]> {
        let mk = MasterKey::derive("pw", &KdfParams::fast_for_tests()).unwrap();
        SubKeys::derive(&mk).unwrap().seal
    }

    #[test]
    fn seal_unseal_roundtrips() {
        let key = seal_key();
        let (nonce, ct) = seal(&key, b"aad", b"secret material").unwrap();
        let pt = unseal(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(&pt[..], b"secret material");
    }

    #[test]
    fn wrong_key_fails_bad_password() {
        let key = seal_key();
        let (nonce, ct) = seal(&key, b"aad", b"secret").unwrap();
        let mut other = *key.clone();
        other[0] ^= 1;
        let r = unseal(&other, &nonce, b"aad", &ct);
        assert!(matches!(r, Err(CryptoError::BadPassword)));
    }

    #[test]
    fn aad_flip_fails() {
        let key = seal_key();
        let (nonce, ct) = seal(&key, b"aad", b"secret").unwrap();
        assert!(matches!(unseal(&key, &nonce, b"axd", &ct), Err(CryptoError::BadPassword)));
    }

    #[test]
    fn nonce_flip_fails() {
        let key = seal_key();
        let (mut nonce, ct) = seal(&key, b"aad", b"secret").unwrap();
        nonce[0] ^= 1;
        assert!(matches!(unseal(&key, &nonce, b"aad", &ct), Err(CryptoError::BadPassword)));
    }

    #[test]
    fn ciphertext_flip_fails() {
        let key = seal_key();
        let (nonce, mut ct) = seal(&key, b"aad", b"secret").unwrap();
        ct[0] ^= 1;
        assert!(matches!(unseal(&key, &nonce, b"aad", &ct), Err(CryptoError::BadPassword)));
    }

    #[test]
    fn derive_is_deterministic_in_password_and_salt() {
        let params = KdfParams::fast_for_tests();
        let a = MasterKey::derive("pw", &params).unwrap();
        let b = MasterKey::derive("pw", &params).unwrap();
        assert_eq!(*a.0, *b.0);
        let other_salt = KdfParams { salt: KdfParams::fast_for_tests().salt, ..params };
        let c = MasterKey::derive("pw", &other_salt).unwrap();
        assert_ne!(*a.0, *c.0);
    }

    #[test]
    fn subkeys_are_pairwise_distinct() {
        let mk = MasterKey::derive("pw", &KdfParams::fast_for_tests()).unwrap();
        let sk = SubKeys::derive(&mk).unwrap();
        assert_ne!(*sk.verify, *sk.seal);
        assert_ne!(*sk.verify, *sk.ledger);
        assert_ne!(*sk.seal, *sk.ledger);
    }

    #[test]
    fn kdf_runs_counts_each_derive() {
        // Other tests derive concurrently, so the counter is only pinned to
        // "moves by at least one per derive" here; the exactly-one claim is
        // the later unlock test's, in isolation.
        let params = KdfParams::fast_for_tests();
        let before = kdf_runs();
        let _ = MasterKey::derive("pw", &params).unwrap();
        let mid = kdf_runs();
        assert!(mid > before);
        let _ = MasterKey::derive("pw", &params).unwrap();
        assert!(kdf_runs() > mid);
    }

    #[test]
    fn generate_uses_production_params_and_fresh_salt() {
        let p = KdfParams::generate().unwrap();
        assert_eq!(p.m_cost_kib, 65536);
        assert_eq!(p.t_cost, 3);
        assert_eq!(p.p_cost, 1);
        assert_eq!(hex_to_vec(&p.salt).unwrap().len(), 16);
        assert_ne!(p.salt, KdfParams::generate().unwrap().salt);
    }
}
