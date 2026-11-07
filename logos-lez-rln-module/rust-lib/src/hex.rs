//! Hex and account-id decoding.

use crate::base58;
use crate::rln_core::bytes_to_hex;

/// Trim whitespace and strip an optional 0x/0X prefix.
fn strip_hex_prefix(s: &str) -> &str {
    let trimmed = s.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

/// Trims whitespace, strips an optional 0x/0X prefix, requires an even
/// number of hex digits and (when expected_len is given) an exact decoded
/// length.
pub(crate) fn hex_to_bytes(hex: &str, expected_len: Option<usize>) -> Option<Vec<u8>> {
    let digits = strip_hex_prefix(hex);
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let bytes = digits.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    if let Some(expected) = expected_len {
        if out.len() != expected {
            return None;
        }
    }
    Some(out)
}

pub(crate) fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    hex_to_bytes(hex, Some(32)).map(|v| {
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    })
}

/// An account id in its one canonical form, bare lowercase 64-hex: 32 bytes
/// of hex (optional 0x/0X) or a base58 account id, surrounding whitespace
/// ignored. `None` when it is neither. Needs no wallet, so it answers before
/// bring-up has finished; the fee payer is resolved on the register path.
pub(crate) fn canonical_account_hex(raw: &str) -> Option<String> {
    hex_to_bytes32(raw)
        .or_else(|| base58::decode32(raw.trim()))
        .map(|bytes| bytes_to_hex(&bytes))
}
