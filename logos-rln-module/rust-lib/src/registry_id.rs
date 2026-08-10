//! CAIP-10 registry identification: parse + canonicalize `registry_id`
//! strings and compute the spec's `membership_hash`. Also hosts the crate's
//! hex helpers (single encoder/decoder, like the sibling module).
//!
//! The "logos" namespace binding (this stack's lez-rln registries): the
//! anchor account is the registration program's CONFIG PDA — the account
//! every other object of a deployment (tree main, subtrees, membership
//! PDAs, treasury) is derived from — and the canonical `account_address`
//! form is 64 lowercase hex chars, no prefix. Other namespaces parse
//! syntactically only (the spec forbids requiring parseability of accounts
//! in unsupported namespaces) and fail at provider routing with
//! `unknown_registry`.

use sha2::{Digest, Sha256};

/// A parsed, canonicalized CAIP-10 account id (`namespace:reference:account`).
#[derive(Clone)]
pub(crate) struct CanonicalRegistryId {
    pub(crate) namespace: String,
    pub(crate) account: String,
    /// The canonical textual form — the ONLY form ever compared, stored, or
    /// hashed (registry_ids are opaque strings once canonicalized).
    pub(crate) canonical: String,
}

/// Parse + canonicalize. `Err` carries a human-readable reason; callers map
/// it to the `invalid_argument` error kind.
pub(crate) fn parse(raw: &str) -> Result<CanonicalRegistryId, String> {
    let raw = raw.trim();
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "registry_id must be namespace:reference:account_address (CAIP-10), got {} segment(s)",
            parts.len()
        ));
    }
    let (namespace, reference, account_raw) = (parts[0], parts[1], parts[2]);

    // CAIP-2 syntax bounds.
    if namespace.len() < 3
        || namespace.len() > 8
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("chain namespace must match [-a-z0-9]{3,8}".to_string());
    }
    if reference.is_empty()
        || reference.len() > 32
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("chain reference must match [-_a-zA-Z0-9]{1,32}".to_string());
    }

    // The logos binding pins the reference to lowercase (Appendix A): network
    // names are lowercase, and since references compare opaquely a case
    // variant would silently identify a distinct registry with a distinct
    // membership_hash, fragmenting stored memberships. Foreign namespaces
    // keep their case (we cannot know their canonical form).
    let reference = if namespace == "logos" {
        reference.to_ascii_lowercase()
    } else {
        reference.to_string()
    };

    let account = if namespace == "logos" {
        match hex_to_bytes32(account_raw) {
            Some(bytes) => bytes_to_hex(&bytes),
            None => {
                return Err(
                    "logos account_address must be the 64-hex config account (0x prefix ok)"
                        .to_string(),
                )
            }
        }
    } else {
        // CAIP-10 account_address syntax only; case is preserved (we cannot
        // know a foreign namespace's canonical form).
        if account_raw.is_empty()
            || account_raw.len() > 128
            || !account_raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'%')
        {
            return Err("account_address must match [-.%a-zA-Z0-9]{1,128}".to_string());
        }
        account_raw.to_string()
    };

    Ok(CanonicalRegistryId {
        namespace: namespace.to_string(),
        canonical: format!("{namespace}:{reference}:{account}"),
        account,
    })
}

/// Spec: `membership_hash = lowercase_hex(SHA256(utf8(registry_id) || 0x00
/// || identity_commitment))` with `registry_id` canonical, a single NUL
/// separator (unambiguous — CAIP-10 ids cannot contain it), and the
/// commitment as its 32-byte little-endian representation. Deliberately
/// excludes provisional fields (leaf_index, rate_limit); keys the keystore.
pub(crate) fn membership_hash(
    canonical_registry_id: &str,
    identity_commitment_le: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_registry_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(identity_commitment_le);
    bytes_to_hex(&hasher.finalize())
}

/// Lowercase hex, no prefix — the crate's single hex encoder.
pub(crate) fn bytes_to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Whitespace-trimming, 0x/0X-tolerant hex decoder (the sibling module's
/// input semantics). Even length required.
pub(crate) fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
    let s = hex.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Exactly 32 bytes or None.
pub(crate) fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    let v = hex_to_vec(hex)?;
    v.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logos_ids_canonicalize_to_lowercase_hex() {
        let account = "8f3a2b1c4d5e6f708192a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4";
        let mixed = format!("logos:testnet:0x{}", account.to_uppercase());
        let id = parse(&mixed).unwrap();
        assert_eq!(id.namespace, "logos");
        assert_eq!(id.account, account);
        assert_eq!(id.canonical, format!("logos:testnet:{account}"));
    }

    #[test]
    fn logos_reference_pins_to_lowercase_foreign_preserved() {
        // logos: the Appendix A binding lowercases the reference, so case
        // variants can't fragment membership_hashes.
        let id = parse(&format!("logos:TestNet-1:{}", "ab".repeat(32))).unwrap();
        assert_eq!(id.canonical, format!("logos:testnet-1:{}", "ab".repeat(32)));
        // Foreign namespaces: case preserved (their canonical form is theirs).
        let id = parse("eip155:59144:0xB9cd878C90E49F797B4431fBF4fb333108CB90e6").unwrap();
        assert!(id.canonical.starts_with("eip155:59144:0xB9cd"));
    }

    #[test]
    fn unsupported_namespace_parses_but_stays_verbatim() {
        let id = parse("eip155:59144:0xB9cd878C90E49F797B4431fBF4fb333108CB90e6").unwrap();
        assert_eq!(id.namespace, "eip155");
        assert_eq!(id.account, "0xB9cd878C90E49F797B4431fBF4fb333108CB90e6");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        assert!(parse("logos:testnet").is_err());
        assert!(parse("logos:testnet:extra:deadbeef").is_err());
        assert!(parse(&format!("logos:testnet:{}", "ab".repeat(31))).is_err());
        assert!(parse(&format!("logos:testnet:zz{}", "ab".repeat(31))).is_err());
        assert!(parse(&format!("LOGOS:testnet:{}", "ab".repeat(32))).is_err());
        assert!(parse(&format!("xy:testnet:{}", "ab".repeat(32))).is_err());
        assert!(parse(&format!("logos::{}", "ab".repeat(32))).is_err());
    }

    // Frozen vector (computed independently: python3 hashlib over
    // utf8(registry) ‖ 0x00 ‖ 32×0x11): pins the exact byte construction.
    // A change here breaks every existing keystore key — never rebind.
    #[test]
    fn membership_hash_matches_frozen_vector() {
        let registry = "logos:testnet:8f3a2b1c4d5e6f708192a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4";
        assert_eq!(
            membership_hash(registry, &[0x11u8; 32]),
            "400683426fc56e13d6f7b6cf8b31a825ab4356ac294ef98f91784514c5cbfc08"
        );
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_to_vec("0xAbCd").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(hex_to_vec(" 00ff ").unwrap(), vec![0x00, 0xff]);
        assert!(hex_to_vec("abc").is_none());
        assert!(hex_to_bytes32(&"ab".repeat(31)).is_none());
        assert_eq!(bytes_to_hex(&[0xab, 0xcd]), "abcd");
    }
}
