use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::hex::{bytes_to_hex, hex_to_vec};

pub const WRITE_KDF_ROUNDS: u32 = 1_000_000;
pub const DKLEN: usize = 32;

#[derive(Debug)]
pub enum KeystoreError {
    /// MAC verification failed — wrong password or tampered ciphertext.
    BadPassword,
    /// Envelope declares a cipher/kdf/prf/dklen this crate doesn't speak.
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

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfParams {
    pub c: u32,
    pub dklen: u32,
    pub prf: String,
    pub salt: String,
}

pub fn derive_key(password: &str, params: &KdfParams) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
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

fn mac_bytes(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&dk[16..32]);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn apply_aes128ctr(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<(), KeystoreError> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
        .map_err(|_| KeystoreError::Malformed("cipher key/iv length"))?;
    cipher.apply_keystream(buf);
    Ok(())
}

pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<CryptoEnvelope, KeystoreError> {
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

pub fn decrypt(
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

        let mut flip_iv = env;
        let mut iv = flip_iv.cipherparams.iv.into_bytes();
        iv[0] = if iv[0] == b'0' { b'1' } else { b'0' };
        flip_iv.cipherparams.iv = String::from_utf8(iv).unwrap();
        let out = decrypt("pw", &flip_iv).unwrap();
        assert_ne!(&out[..], b"secret bytes");
    }

    // The WAKU-RLN-KEYSTORE spec's own test vector (password "sup3rsecure"):
    // decrypting it is what pins the keccak256 MAC construction and thus
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
}
