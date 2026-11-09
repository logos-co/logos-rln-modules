//! The RLN signal binding — the ONLY preprocessing liblogos_rln_module applies
//! to a message before proving or verifying over it:
//!
//! ```text
//! x = Fr::from_le_bytes_mod_order(keccak256(signal))
//! ```
//!
//! That is zerokit's `hash_to_field_le`, reproduced here over the same crates
//! (`tiny-keccak`, `ark-bn254`) so a consumer can hash a message locally and
//! hand the module the 32-byte field element instead of the whole payload
//! (`generate_proof_prehashed` / `validate_proof_prehashed`, argument
//! `signal_hash_hex`). The value equals the `share_x` field of every
//! `RateLimitProof` the module replies with.
//!
//! The wire form is the canonical 32-byte little-endian encoding of `x`
//! (arkworks `serialize_compressed`). The module deserializes it strictly: a
//! value at or above the field modulus is refused, never re-reduced.
//!
//! Byte-exactness against zerokit is pinned by the tests in this crate; a
//! change here breaks cross-node verification.

#![deny(unsafe_op_in_unsafe_fn)]

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use tiny_keccak::{Hasher, Keccak};

pub use ark_bn254::Fr;

/// `x = hash_to_field_le(signal)`: keccak256, then little-endian reduction
/// into the BN254 scalar field.
pub fn signal_to_x(signal: &[u8]) -> Fr {
    let mut digest = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(signal);
    keccak.finalize(&mut digest);
    Fr::from_le_bytes_mod_order(&digest)
}

/// [`signal_to_x`] in its wire form: the canonical 32-byte little-endian
/// encoding, i.e. the `signal_hash_hex` bytes and the reply's `share_x`.
pub fn signal_hash(signal: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    signal_to_x(signal)
        .serialize_compressed(&mut out[..])
        .expect("invariant: Fr's canonical LE form is exactly 32 bytes");
    out
}

/// C ABI: write [`signal_hash`]`(signal[0..len])` into `out`.
///
/// Returns 0 on success, 1 when `out` is null, 2 when `signal` is null with a
/// non-zero `len` (a null `signal` with `len == 0` hashes the empty message).
///
/// # Safety
/// `signal` must be readable for `len` bytes and `out` writable for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn rln_signal_hash(signal: *const u8, len: usize, out: *mut u8) -> i32 {
    if out.is_null() {
        return 1;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else if signal.is_null() {
        return 2;
    } else {
        // SAFETY: the caller guarantees `signal` is readable for `len` bytes.
        unsafe { core::slice::from_raw_parts(signal, len) }
    };
    let hash = signal_hash(bytes);
    // SAFETY: the caller guarantees `out` is writable for 32 bytes.
    unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zerokit(signal: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        rln::prelude::hash_to_field_le(signal)
            .serialize_compressed(&mut out[..])
            .expect("32 bytes");
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_zerokit_hash_to_field_le() {
        let inputs: [&[u8]; 5] = [
            b"",
            b"\x00",
            b"Hello, RLN!",
            &[0xffu8; 64],
            b"payload bytes, then a content topic, then eight timestamp bytes",
        ];
        for s in inputs {
            assert_eq!(signal_hash(s), zerokit(s), "input {:?}", s);
            assert_eq!(signal_to_x(s), rln::prelude::hash_to_field_le(s));
        }
    }

    // liblogos_rln_module's frozen interop vector (proof.rs
    // frozen_interop_vectors): x = hash_to_field_le("Hello, RLN!").
    #[test]
    fn frozen_interop_vector() {
        assert_eq!(
            hex(&signal_hash(b"Hello, RLN!")),
            "9af96b554db1bc4bfb806f3bcd587c8c0ee80d4d79c440a87b51861235461412"
        );
    }

    #[test]
    fn ffi_entry_matches_library() {
        let signal = b"Hello, RLN!";
        let mut out = [0u8; 32];
        let rc = unsafe { rln_signal_hash(signal.as_ptr(), signal.len(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out, signal_hash(signal));

        let mut empty = [0u8; 32];
        let rc = unsafe { rln_signal_hash(core::ptr::null(), 0, empty.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(empty, signal_hash(b""));
    }

    #[test]
    fn ffi_entry_refuses_null_pointers() {
        let signal = b"x";
        assert_eq!(
            unsafe { rln_signal_hash(signal.as_ptr(), 1, core::ptr::null_mut()) },
            1
        );
        let mut out = [0u8; 32];
        assert_eq!(
            unsafe { rln_signal_hash(core::ptr::null(), 1, out.as_mut_ptr()) },
            2
        );
    }
}
