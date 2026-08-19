//! Domain-agnostic keystore building blocks: the encrypted credential
//! envelope (Ethereum-V3-keyfile construction, nwaku-interoperable) and the
//! durable-file layer (fsync-atomic writes, fail-closed loads, an exclusive
//! per-directory process lock).
//!
//! This crate holds the *generic* layer of the RLN module's keystore — the
//! parts whose guarantees transfer to any tenant unchanged. It must never
//! grow domain types: schemas, sidecar-MAC payloads, and store semantics
//! belong to the consuming module. Planned trajectory (see the module's
//! design record): a trait-parameterized authenticated store and a modern
//! AEAD/Argon2id envelope will land HERE alongside the frozen V3 one; until
//! then the surface is deliberately small.
//!
//! Interop freeze: the envelope's keccak256 MAC (not the spec prose's
//! SHA256) is what real nwaku keystores verify under — pinned by
//! `spec_test_vector_decrypts`. Do not "correct" it.

mod envelope;
mod fs;
mod hex;

pub use envelope::{
    ct_eq, decrypt, derive_key, encrypt, CipherParams, CryptoEnvelope, KdfParams, KeystoreError,
    DKLEN, WRITE_KDF_ROUNDS,
};
pub use fs::{acquire_dir_lock, load_json, write_durable, write_durable_json};
