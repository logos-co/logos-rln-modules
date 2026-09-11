//! Base58 account ids.
//!
//! The wallet speaks 32-byte account ids; humans, deployment descriptors and
//! `LEZ_RLN_PAYER` all speak base58. `lez_core` used to do this conversion on
//! the far side of an lp call. Now that the wallet is ours, it happens here.
//!
//! No alphabet variants and no checksum: this is the plain Bitcoin alphabet
//! over a fixed 32 bytes, which is what `AccountId`'s own `FromStr`/`Display`
//! implement. `tests::roundtrip_matches_a_known_vector` pins it against an id
//! taken from a real deployment.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a base58 account id to its 32 bytes, or `None` if the string holds
/// a character outside the alphabet or does not describe exactly 32 bytes.
pub(crate) fn decode32(input: &str) -> Option<[u8; 32]> {
    let mut bytes: Vec<u8> = vec![0];
    for c in input.chars() {
        let value = ALPHABET.iter().position(|&b| b as char == c)? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's are leading zero bytes, and the accumulator above is
    // little-endian, so they go on the end before the reverse.
    for c in input.chars() {
        if c == '1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    while bytes.len() > 1 && *bytes.last()? == 0 && bytes.len() > 32 {
        bytes.pop();
    }
    bytes.reverse();
    // A short decode is a shorter number, not an error in the input: left-pad.
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

/// Encode 32 bytes as base58.
pub(crate) fn encode32(input: &[u8; 32]) -> String {
    let mut digits: Vec<usize> = vec![0];
    for &byte in input.iter() {
        let mut carry = byte as usize;
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for &byte in input.iter() {
        if byte == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    for &digit in digits.iter().rev() {
        out.push(ALPHABET[digit] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An account id and its bytes, taken from a live deployment descriptor —
    /// the pairing the sequencer's `getAccount` and the registry id agree on.
    const ID: &str = "FqNyaKjaeUxjMxJszC88Z6SUUL8pxBgN6qRHC4ZsJjgn";
    const HEX: &str = "dc6857ef4236ef416fb6357c1f9988a7c7558b07492d7284c411b3864a1fccf3";

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn roundtrip_matches_a_known_vector() {
        assert_eq!(decode32(ID).unwrap(), hex32(HEX));
        assert_eq!(encode32(&hex32(HEX)), ID);
    }

    #[test]
    fn a_character_outside_the_alphabet_is_rejected() {
        // '0', 'O', 'I' and 'l' are the excluded look-alikes.
        for bad in ["0", "O", "I", "l"] {
            let mut s = ID.to_owned();
            s.replace_range(0..1, bad);
            assert!(decode32(&s).is_none(), "{bad} should not decode");
        }
    }

    #[test]
    fn leading_zero_bytes_survive_the_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[31] = 7;
        assert_eq!(decode32(&encode32(&bytes)).unwrap(), bytes);
    }
}
