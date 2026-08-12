//! RLN rate-limit proof engine: the spec's `generate_proof` / `verify_proof`
//! crypto, over stateless zerokit `rln`.
//!
//! Identity secrets touch the RLN circuit only here, and are never persisted,
//! logged, or returned: the caller passes the decrypted
//! `identity_secret_hash` in and gets back only the public `RateLimitProof`.
//! The one exception is [`recover_identity_secret_hex`], which reconstructs a
//! double-signaller's OWN secret (`recovered_secret`) from their two
//! colliding shares — never one of this module's credentials.
//!
//! Two constructions are PINNED (they are the wire contract every
//! implementation has to match — see `external_nullifier` and `signal_to_x`):
//!
//! - `external_nullifier = poseidon(hash_to_field_le(epoch),
//!   hash_to_field_le(rln_identifier))`, where `epoch` is the spec's
//!   `epoch[32]`: the epoch index as a 32-byte little-endian integer
//! - `x = hash_to_field_le(signal)`
//!
//! Both match logos-delivery byte-for-byte, so proofs cross-verify with its
//! embedded zerokit. They diverge from nwaku
//! (`waku_rln_relay/rln/wrappers.nim`), which keccak256-hashes both poseidon
//! inputs; nwaku interop requires agreeing this at the spec level.
//!
//! Canonical `RateLimitProof` serialization (the proof is a wire type that
//! crosses from the generating node to verifying nodes) is zerokit's own
//! `RLNProof` LE format: the 128-byte compressed Groth16 proof, then the
//! mode tag byte and the LE-serialized public values — 289 bytes in Single
//! mode. The named spec fields (`root`, `external_nullifier`, `share_x`,
//! `share_y`, `nullifier`) are a decoded view; verification always
//! recomputes from the canonical bytes and never trusts the decoded fields.

use std::sync::LazyLock;

use rand_chacha::ChaCha20Rng;
use rln::prelude::{
    compute_id_secret, default_graph_single, default_zkey_single, hash_to_field_le,
    ArkGroth16Backend, CanonicalDeserialize, CanonicalSerialize, Fr, Hasher, IdentityKeys,
    PoseidonHash, Proof, RLNBuilder, RLNMerkleProof, RLNProof, RLNProofValues, RLNWitnessInput,
    SecretFr, Stateless, VerifyProofError, DEFAULT_TREE_DEPTH, RLN,
};
use zeroize::Zeroize;

use crate::registry_id::{bytes_to_hex, hex_to_bytes32, hex_to_vec};

/// The circuit's fixed Merkle depth (zerokit stateless default = 20); a
/// supplied path MUST have this length or witness construction fails.
pub(crate) const RLN_TREE_DEPTH: usize = DEFAULT_TREE_DEPTH;

/// Failures the proof engine can raise. `Invalid` is NOT modelled here — a
/// proof that simply does not verify is `Ok(false)` from [`verify`], so the
/// hot path can distinguish "invalid message" from "engine could not run"
/// (the spec's `verify_proof` bool vs `RLN_ERR_*` split).
#[derive(Debug)]
pub(crate) enum ProofError {
    /// Malformed caller input (bad hex, wrong path length, out-of-range
    /// message id): retrying cannot help — maps to `RLN_ERR_PERMANENT`.
    BadInput(String),
    /// The circuit/engine could not run (RLN init, witness calc): maps to
    /// `RLN_ERR_TRANSIENT` / `RLN_ERR_NOT_READY` at the call site.
    Engine(String),
}

/// Everything the circuit needs about the membership, assembled by the caller
/// (`generate_proof`) from the keystore credential and the registry's Merkle
/// proof. Hex is lowercase, 32-byte little-endian — the crate-wide encoding.
pub(crate) struct WitnessMaterial {
    /// Decrypted `identity_secret_hash` (LE hex) — used only to build the
    /// witness, never stored or returned.
    pub(crate) identity_secret_hash_hex: String,
    /// The membership's rate limit = the circuit's `user_message_limit`.
    pub(crate) rate_limit: u64,
    /// The slot allocated for this proof; MUST be `< rate_limit`.
    pub(crate) message_id: u64,
    /// Merkle path sibling hashes, root→leaf order as the registry returns
    /// them, each 32-byte LE hex; length MUST equal [`RLN_TREE_DEPTH`].
    pub(crate) path_elements_hex: Vec<String>,
    /// Per-level path direction bits (0/1), same length/order as
    /// `path_elements_hex`.
    pub(crate) path_indices: Vec<u8>,
}

/// A generated RLN proof in the spec's `RateLimitProof` shape. `canonical` is
/// the authoritative zerokit serialization; the five 32-byte fields are the
/// decoded public-value view (spec's `share_x`/`share_y` are the circuit's
/// `x`/`y`).
#[derive(Debug)]
pub(crate) struct RateLimitProof {
    canonical: Vec<u8>,
    root: [u8; 32],
    external_nullifier: [u8; 32],
    share_x: [u8; 32],
    share_y: [u8; 32],
    nullifier: [u8; 32],
    /// The spec's `epoch[32]`, decoded — carried on proofs this module
    /// generates; `None` for a wire proof reconstructed without one, which
    /// `verify_proof` resolves by scanning instead of checking directly.
    epoch: Option<u64>,
}

impl RateLimitProof {
    /// Bundle the Groth16 proof with its public values and capture both the
    /// canonical bytes and the decoded field view. `epoch` is `None` here —
    /// callers that know the epoch (generation, a parsed wire `epoch[32]`)
    /// attach it afterward.
    fn from_parts(proof: Proof, values: RLNProofValues) -> Result<Self, ProofError> {
        let (share_y, nullifier) = single_values(&values)?;
        let root = fr_to_u32(&values.root());
        let external_nullifier = fr_to_u32(&values.external_nullifier());
        let share_x = fr_to_u32(&values.x());
        let rln_proof = RLNProof::new(proof, values);
        let mut canonical = Vec::new();
        rln_proof
            .serialize_compressed(&mut canonical)
            .map_err(|e| ProofError::Engine(format!("serialize proof: {e}")))?;
        Ok(RateLimitProof {
            canonical,
            root,
            external_nullifier,
            share_x,
            share_y: fr_to_u32(&share_y),
            nullifier: fr_to_u32(&nullifier),
            epoch: None,
        })
    }

    /// The root the proof was generated against — the value `verify_proof`
    /// checks against its valid-root window. Production verification reads
    /// the root out of the canonical bytes inside zerokit; this decoded view
    /// serves tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The spec `RateLimitProof` as a JSON object: `proof` is the canonical
    /// hex the consumer round-trips unchanged, the rest a decoded view.
    /// `epoch` (the spec's `epoch[32]`, 32-byte LE hex) is present only when
    /// this proof carries one.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut out = serde_json::json!({
            "proof": bytes_to_hex(&self.canonical),
            "root": bytes_to_hex(&self.root),
            "external_nullifier": bytes_to_hex(&self.external_nullifier),
            "share_x": bytes_to_hex(&self.share_x),
            "share_y": bytes_to_hex(&self.share_y),
            "nullifier": bytes_to_hex(&self.nullifier),
        });
        if let Some(epoch) = self.epoch {
            out["epoch"] = serde_json::Value::String(bytes_to_hex(&epoch_to_bytes(epoch)));
        }
        out
    }

    /// Rebuild from the wire form. Two accepted shapes:
    ///
    /// 1. Canonical: `proof` carries the full zerokit serialization (what
    ///    [`Self::to_json`] emits). The decoded fields are recomputed from it,
    ///    so a tampered field can never desync from what verification checks.
    /// 2. Decomposed (the spec's `RateLimitProof` struct, what a consumer
    ///    reassembles from its own network message): `proof` is the bare
    ///    128-byte compressed Groth16 proof and `root` /
    ///    `external_nullifier` / `share_x` / `share_y` / `nullifier` carry
    ///    the public values. The zerokit proof is rebuilt from those fields
    ///    and re-serialized into the canonical form, so both shapes land in
    ///    the identical verified representation.
    ///
    /// Both shapes accept an optional `epoch` (the spec's `epoch[32]`,
    /// 32-byte LE hex): absent leaves the proof epoch-less, present decodes
    /// via [`epoch_from_bytes`] and rejects a malformed or non-canonical
    /// value outright — a bad epoch is never silently dropped.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, ProofError> {
        let proof_hex = value
            .get("proof")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProofError::BadInput("proof: missing proof bytes".into()))?;
        let bytes = hex_to_vec(proof_hex)
            .ok_or_else(|| ProofError::BadInput("proof: not valid hex".into()))?;

        const GROTH16_LEN: usize = 128;
        let canonical: Vec<u8> = if bytes.len() == GROTH16_LEN {
            // Spec-struct shape: rebuild the zerokit proof around the bare
            // Groth16 proof and re-serialize it into the canonical form.
            let field = |key: &str| -> Result<Fr, ProofError> {
                let hex = value.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
                    ProofError::BadInput(format!(
                        "{key}: expected 32-byte hex alongside a bare proof"
                    ))
                })?;
                hex_to_fr(hex, key)
            };
            let zk_proof = Proof::deserialize_compressed(&bytes[..]).map_err(|e| {
                ProofError::BadInput(format!("proof: not a valid Groth16 proof: {e}"))
            })?;
            let values = RLNProofValues::new_single()
                .y(field("share_y")?)
                .root(field("root")?)
                .nullifier(field("nullifier")?)
                .x(field("share_x")?)
                .external_nullifier(field("external_nullifier")?)
                .build();
            let rln_proof = RLNProof::new(zk_proof, values);
            let mut out = Vec::new();
            rln_proof
                .serialize_compressed(&mut out)
                .map_err(|e| ProofError::Engine(format!("serialize proof: {e}")))?;
            out
        } else {
            bytes
        };

        // Two accepted encodings of the same epoch: the spec's epoch[32]
        // LE hex, and the u64 index generate_proof's reply carries.
        let epoch = match value.get("epoch") {
            None => None,
            Some(v) => {
                if let Some(index) = v.as_u64() {
                    Some(index)
                } else {
                    let hex = v.as_str().ok_or_else(|| {
                        ProofError::BadInput("epoch: expected 32-byte hex or u64 index".into())
                    })?;
                    let bytes = hex_to_bytes32(hex).ok_or_else(|| {
                        ProofError::BadInput("epoch: expected 32-byte hex or u64 index".into())
                    })?;
                    Some(epoch_from_bytes(&bytes).ok_or_else(|| {
                        ProofError::BadInput("epoch: non-canonical padding".into())
                    })?)
                }
            }
        };

        let rln_proof = parse_canonical(&canonical)?;
        let mut proof = Self::from_parts(rln_proof.proof, rln_proof.values)?;
        proof.epoch = epoch;
        Ok(proof)
    }

    /// The external nullifier the proof was bound to — checked by
    /// `verify_proof` against the scope's expected epoch window.
    pub(crate) fn external_nullifier(&self) -> [u8; 32] {
        self.external_nullifier
    }

    /// The proof's nullifier — the per-epoch identity+slot fingerprint the
    /// nullifier log keys on to detect a reused slot.
    pub(crate) fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    /// The signal-bound share coordinate `x`. Two proofs sharing a nullifier
    /// but differing here are a double-signal; matching here is a
    /// retransmission — the split the log's verdict turns on.
    pub(crate) fn share_x(&self) -> [u8; 32] {
        self.share_x
    }

    /// The share coordinate `y`. Paired with `share_x`, it is one Shamir point;
    /// two colliding points reconstruct the double-signaller's secret.
    pub(crate) fn share_y(&self) -> [u8; 32] {
        self.share_y
    }

    /// The epoch this proof carries (the spec's `epoch[32]`, decoded), or
    /// `None` for a wire proof reconstructed without one — `verify_proof`
    /// checks the former directly and resolves the latter by scanning.
    pub(crate) fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// Reconstruct the zerokit proof for verification.
    fn to_rln_proof(&self) -> Result<RLNProof, ProofError> {
        parse_canonical(&self.canonical)
    }
}

/// The stateless RLN engine over the embedded Single-mode circuit, built
/// once — the zkey/graph clones are several MB, too expensive to repeat on
/// the per-message verify path.
static RLN_STATELESS: LazyLock<RLN<Stateless, ArkGroth16Backend<PoseidonHash>>> =
    LazyLock::new(|| {
        RLNBuilder::stateless()
            .graph(default_graph_single().clone())
            .zkey(default_zkey_single().clone())
            .build()
    });

/// The Single-mode `y` and `nullifier` out of zerokit's mode-generic proof
/// values. This module only ever produces/parses Single-mode proofs, so a
/// Multi value here is an engine invariant break, not caller input.
fn single_values(values: &RLNProofValues) -> Result<(Fr, Fr), ProofError> {
    match (values.y(), values.nullifier()) {
        (Some(y), Some(nullifier)) => Ok((y, nullifier)),
        _ => Err(ProofError::Engine(
            "multi-mode proof values unsupported".into(),
        )),
    }
}

/// Parse canonical bytes back into the zerokit proof via zerokit's own
/// deserializer. This module's protocol is Single-mode only — a Multi-tagged
/// proof is rejected as caller input.
fn parse_canonical(bytes: &[u8]) -> Result<RLNProof, ProofError> {
    let rln_proof = RLNProof::deserialize_compressed(bytes)
        .map_err(|e| ProofError::BadInput(format!("proof: not a valid RLN proof: {e}")))?;
    if rln_proof.values.y().is_none() {
        return Err(ProofError::BadInput(
            "proof: multi-mode proofs are not supported".into(),
        ));
    }
    Ok(rln_proof)
}

/// The spec's `epoch[32]` wire encoding: the epoch index as a 32-byte
/// little-endian integer (logos-delivery's `toEpoch`). PINNED.
fn epoch_to_bytes(epoch: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&epoch.to_le_bytes());
    out
}

/// Decode the spec's `epoch[32]`: an LE `u64` in bytes `0..8`, bytes `8..32`
/// MUST be zero. Non-canonical padding (a nonzero high byte) is rejected
/// rather than masked off — accepting it would let a single epoch index be
/// carried by many distinct byte strings, minting unlimited nullifier-log
/// buckets for what should key to one epoch.
pub(crate) fn epoch_from_bytes(bytes: &[u8; 32]) -> Option<u64> {
    if bytes[8..32].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_le_bytes(
        bytes[..8].try_into().expect("8-byte slice"),
    ))
}

/// The external nullifier binding one epoch and one application:
/// `poseidon(hash_to_field_le(epoch[32]), hash_to_field_le(rln_identifier))`.
/// PINNED — see the module docs on the nwaku divergence.
fn external_nullifier(epoch: u64, rln_identifier: &[u8; 32]) -> Fr {
    let epoch_fr = hash_to_field_le(&epoch_to_bytes(epoch));
    let rln_identifier_fr = hash_to_field_le(rln_identifier);
    Hasher::<PoseidonHash>::hash_pair(epoch_fr, rln_identifier_fr)
}

/// The circuit's signal binding: `x = hash_to_field_le(signal)`. PINNED.
fn signal_to_x(signal: &[u8]) -> Fr {
    hash_to_field_le(signal)
}

/// The external nullifier expected for `(epoch, rln_identifier)`, as the
/// 32-byte LE value a proof's `external_nullifier` field must equal — the
/// verify-side application + epoch-freshness binding.
pub(crate) fn expected_external_nullifier(epoch: u64, rln_identifier: &[u8; 32]) -> [u8; 32] {
    fr_to_u32(&external_nullifier(epoch, rln_identifier))
}

/// `Fr` → 32-byte LE (arkworks `serialize_compressed`, which for `Fr` is the
/// 32-byte LE canonical form). A short write would silently corrupt
/// security-relevant bytes, so it is asserted rather than tolerated.
fn fr_to_u32(fr: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    fr.serialize_compressed(&mut out[..])
        .expect("Fr canonical LE form is exactly 32 bytes");
    out
}

/// `SecretFr` → 32-byte LE, same encoding as [`fr_to_u32`]. The caller owns
/// the lifetime of the returned copy.
fn secret_to_u32(secret: &SecretFr) -> [u8; 32] {
    let mut out = [0u8; 32];
    secret
        .serialize_compressed(&mut out[..])
        .expect("SecretFr canonical LE form is exactly 32 bytes");
    out
}

/// LE-hex 32-byte string → `Fr`. A non-canonical value (≥ the field modulus)
/// is rejected, never reduced.
fn hex_to_fr(hex: &str, label: &str) -> Result<Fr, ProofError> {
    let bytes = hex_to_bytes32(hex)
        .ok_or_else(|| ProofError::BadInput(format!("{label}: expected 32-byte hex")))?;
    Fr::deserialize_compressed(&bytes[..])
        .map_err(|e| ProofError::BadInput(format!("{label}: not a field element: {e}")))
}

/// Generate a fresh RLN identity in-module (spec: `register` generates the
/// credential itself). Returns `(id_commitment_hex, id_secret_hash_hex)`,
/// both 32-byte little-endian hex. The secret is handed back only to be
/// encrypted into the keystore by the caller — it never crosses the module
/// boundary.
pub(crate) fn generate_identity() -> Result<(String, String), ProofError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| ProofError::Engine(format!("rng: {e}")))?;
    let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&seed);
    seed.zeroize();
    Ok((
        bytes_to_hex(&fr_to_u32(&keys.id_commitment())),
        bytes_to_hex(&secret_to_u32(&keys.identity_secret())),
    ))
}

/// Generate an RLN proof that `signal` came from the membership backing
/// `material`, for `(epoch, rln_identifier)`, spending slot `message_id`.
pub(crate) fn generate(
    material: &WitnessMaterial,
    signal: &[u8],
    epoch: u64,
    rln_identifier: &[u8; 32],
) -> Result<RateLimitProof, ProofError> {
    if material.path_elements_hex.len() != material.path_indices.len() {
        return Err(ProofError::BadInput(format!(
            "merkle path length mismatch: {} elements vs {} indices",
            material.path_elements_hex.len(),
            material.path_indices.len()
        )));
    }
    if material.path_elements_hex.len() != RLN_TREE_DEPTH {
        return Err(ProofError::BadInput(format!(
            "merkle path depth {} != circuit depth {RLN_TREE_DEPTH}",
            material.path_elements_hex.len()
        )));
    }

    let secret_bytes = hex_to_bytes32(&material.identity_secret_hash_hex)
        .ok_or_else(|| ProofError::BadInput("identity_secret_hash: expected 32-byte hex".into()))?;
    let identity_secret = SecretFr::deserialize_compressed(&secret_bytes[..])
        .map_err(|e| ProofError::BadInput(format!("identity_secret: {e}")))?;

    let path_elements = material
        .path_elements_hex
        .iter()
        .map(|h| hex_to_fr(h, "path_element"))
        .collect::<Result<Vec<Fr>, _>>()?;

    let witness = RLNWitnessInput::new_single()
        .identity_secret(identity_secret)
        .user_message_limit(Fr::from(material.rate_limit))
        .message_id(Fr::from(material.message_id))
        .merkle_proof(RLNMerkleProof::new(
            path_elements,
            material.path_indices.clone(),
        ))
        .x(signal_to_x(signal))
        .external_nullifier(external_nullifier(epoch, rln_identifier))
        .build()
        .map_err(|e| ProofError::BadInput(format!("witness: {e}")))?;

    let (proof, values) = RLN_STATELESS
        .generate_proof(&witness)
        .map_err(|e| ProofError::Engine(format!("generate: {e}")))?;
    let mut rlp = RateLimitProof::from_parts(proof, values)?;
    rlp.epoch = Some(epoch);
    Ok(rlp)
}

/// Verify an RLN proof for `signal` against a valid-root window. `Ok(true)`
/// only if the proof is cryptographically valid, its signal matches, and its
/// root is one of `valid_roots`. A proof that fails any of those is `Ok(false)`
/// (an invalid message, not an engine error); only an engine failure is `Err`.
/// An empty `valid_roots` skips the window check (zerokit semantics) — callers
/// on the hot path MUST pass a non-empty window.
pub(crate) fn verify(
    proof: &RateLimitProof,
    signal: &[u8],
    valid_roots: &[[u8; 32]],
) -> Result<bool, ProofError> {
    let rln_proof = proof.to_rln_proof()?;
    let x = signal_to_x(signal);
    // A non-canonical root entry is skipped, but a non-empty window yielding
    // NO usable root must verify false — never fall through to zerokit's
    // empty-window "skip the root check" semantics.
    let roots: Vec<Fr> = valid_roots
        .iter()
        .filter_map(|r| Fr::deserialize_compressed(&r[..]).ok())
        .collect();
    if !valid_roots.is_empty() && roots.is_empty() {
        return Ok(false);
    }

    match RLN_STATELESS.verify_with_roots(&rln_proof.proof, &rln_proof.values, &x, &roots) {
        // `Ok(false)` is the zkSNARK verdict for an invalid proof. A signal
        // or root mismatch is a typed error — for this module both are
        // still "the message is invalid", not "the engine broke".
        Ok(verdict) => Ok(verdict),
        Err(VerifyProofError::InvalidRoot | VerifyProofError::InvalidSignal) => Ok(false),
        Err(e) => Err(ProofError::Engine(format!("verify: {e}"))),
    }
}

/// Reconstruct a DOUBLE-SIGNALLER's OWN identity secret from the two colliding
/// Shamir shares their proofs exposed — the spec-sanctioned `recovered_secret`
/// of a rate-limit violation, and the ONE place a secret legitimately crosses
/// this module's boundary. It is ALWAYS the violator's secret, never one of
/// this module's credentials: two accepted proofs sharing a nullifier but
/// carrying distinct `share_x` are two points `(x, y)` on the same degree-1
/// sharing polynomial whose constant term is the secret. Returns 32-byte LE
/// hex. The four coordinates are the recorded prior share and the current one.
pub(crate) fn recover_identity_secret_hex(
    prior: ([u8; 32], [u8; 32]),
    current: ([u8; 32], [u8; 32]),
) -> Result<String, ProofError> {
    let field = |bytes: &[u8; 32], label: &str| -> Result<Fr, ProofError> {
        Fr::deserialize_compressed(&bytes[..])
            .map_err(|e| ProofError::BadInput(format!("{label}: not a field element: {e}")))
    };
    let share1 = (
        field(&prior.0, "prior share_x")?,
        field(&prior.1, "prior share_y")?,
    );
    let share2 = (field(&current.0, "share_x")?, field(&current.1, "share_y")?);
    // compute_id_secret fails only on equal share_x (DivisionByZero).
    let secret = compute_id_secret(share1, share2)
        .map_err(|e| ProofError::Engine(format!("recover id secret: {e}")))?;
    Ok(bytes_to_hex(&secret_to_u32(&secret)))
}

/// Build a proof from a seed over a synthetic zero-sibling depth-20 path — for
/// cross-module wiring tests (e.g. `verify_proof_impl`) that need a real,
/// verifiable proof without an on-chain tree.
#[cfg(test)]
pub(crate) fn generate_for_test(
    seed: &[u8],
    signal: &[u8],
    epoch: u64,
    rln_identifier: &[u8; 32],
) -> RateLimitProof {
    let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
    let material = WitnessMaterial {
        identity_secret_hash_hex: bytes_to_hex(&secret_to_u32(&keys.identity_secret())),
        rate_limit: 100,
        message_id: 0,
        path_elements_hex: vec!["00".repeat(32); RLN_TREE_DEPTH],
        path_indices: vec![0u8; RLN_TREE_DEPTH],
    };
    generate(&material, signal, epoch, rln_identifier).expect("test proof")
}

#[cfg(test)]
mod tests {
    use super::*;

    // All-zero siblings, all left turns. The circuit COMPUTES the root from
    // the path, so any well-formed path yields a self-consistent proof —
    // enough to exercise generate/verify/serialize without an on-chain tree.
    fn zero_path() -> (Vec<String>, Vec<u8>) {
        let elements = vec!["00".repeat(32); RLN_TREE_DEPTH];
        let indices = vec![0u8; RLN_TREE_DEPTH];
        (elements, indices)
    }

    fn material_from_seed(seed: &[u8], rate_limit: u64, message_id: u64) -> WitnessMaterial {
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
        let secret_hex = bytes_to_hex(&secret_to_u32(&keys.identity_secret()));
        let (elements, indices) = zero_path();
        WitnessMaterial {
            identity_secret_hash_hex: secret_hex,
            rate_limit,
            message_id,
            path_elements_hex: elements,
            path_indices: indices,
        }
    }

    // Frozen interop vectors — the wire contract other implementations must
    // match. Every value below is deterministic; only the Groth16 proof bytes
    // are randomized, so the proof is pinned structurally (layout) while its
    // public values are pinned byte-exact. Inputs: seed = 32×0x07,
    // rln_identifier = 32×0x09, epoch index = 1231028105, signal =
    // "Hello, RLN!", zero-sibling all-left depth-20 path.
    // A change here breaks cross-node verification — never rebind silently.
    #[test]
    fn frozen_interop_vectors() {
        // Identity derivation (zerokit seeded keygen, LE hex).
        let keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[7u8; 32]);
        assert_eq!(
            bytes_to_hex(&secret_to_u32(&keys.identity_secret())),
            "3c87aa7480ec2cad022ef39c256ddb6e4fb083c7d4a0dfdc4eee891feda7a62b"
        );
        assert_eq!(
            bytes_to_hex(&fr_to_u32(&keys.id_commitment())),
            "08772427f3a88a9787e8f899c13dc10c2b0a226d7500c99edba0f993ba770729"
        );

        // external_nullifier = poseidon(hash_to_field_le(epoch[32]),
        // hash_to_field_le(rln_identifier)) — NOT nwaku's keccak construction.
        let rln_id = [9u8; 32];
        assert_eq!(
            bytes_to_hex(&fr_to_u32(&external_nullifier(1231028105, &rln_id))),
            "a432bb300aeda21d8c14186e134639ecac20732e9ebcbb73139741cef293612a"
        );

        // x = hash_to_field_le(signal).
        assert_eq!(
            bytes_to_hex(&fr_to_u32(&signal_to_x(b"Hello, RLN!"))),
            "9af96b554db1bc4bfb806f3bcd587c8c0ee80d4d79c440a87b51861235461412"
        );

        // Public values of a proof over the fixed witness.
        let material = material_from_seed(&[7u8; 32], 100, 0);
        let j = generate(&material, b"Hello, RLN!", 1231028105, &rln_id)
            .expect("generate")
            .to_json();
        assert_eq!(
            j["root"].as_str().unwrap(),
            "e6b1124d580df28efdb5a009ee7eb485cc33625df6b98fc058054217160d8a07"
        );
        assert_eq!(
            j["nullifier"].as_str().unwrap(),
            "0d78806341fee59517f2526662095294eee5f590be3c36d9e7d29680b73aa21a"
        );
        // The spec's share_x IS the circuit's signal hash x.
        assert_eq!(
            j["share_x"].as_str().unwrap(),
            "9af96b554db1bc4bfb806f3bcd587c8c0ee80d4d79c440a87b51861235461412"
        );
        // epoch[32]: 1231028105 = 0x495fff89, LE bytes 89 ff 5f 49 then 24
        // zero padding bytes.
        assert_eq!(
            j["epoch"].as_str().unwrap(),
            "89ff5f4900000000000000000000000000000000000000000000000000000000"
        );

        // The nullifier is slot-dependent: reusing a slot collides (the
        // double-signal detection signal), a fresh slot never does.
        let j2 = generate(
            &material_from_seed(&[7u8; 32], 100, 1),
            b"Hello, RLN!",
            1231028105,
            &rln_id,
        )
        .expect("generate mid=1")
        .to_json();
        assert_eq!(
            j2["nullifier"].as_str().unwrap(),
            "cbf8daa2f4d16e31165c6789a738681b0871a5cc775206af276ad4295e185e1e"
        );

        // Canonical serialization layout (zerokit's `RLNProof` LE format):
        // the 128-byte compressed Groth16 proof, the Single-mode tag byte,
        // then the 160-byte LE public values — 289 bytes total.
        let canonical = hex_to_vec(j["proof"].as_str().unwrap()).unwrap();
        assert_eq!(canonical.len(), 289);
        assert_eq!(canonical[128], 0x00);
    }

    #[test]
    fn generate_then_verify_roundtrips() {
        let material = material_from_seed(&[7u8; 32], 100, 0);
        let rln_id = [9u8; 32];
        let proof = generate(&material, b"hello", 1231028105, &rln_id).expect("generate");
        let root = proof.root();
        assert!(verify(&proof, b"hello", &[root]).expect("verify"));
    }

    #[test]
    fn wrong_signal_is_invalid_not_error() {
        let material = material_from_seed(&[7u8; 32], 100, 0);
        let rln_id = [9u8; 32];
        let proof = generate(&material, b"hello", 1231028105, &rln_id).expect("generate");
        let root = proof.root();
        // A different signal must verify false, NOT raise an engine error.
        assert!(!verify(&proof, b"goodbye", &[root]).expect("verify"));
    }

    #[test]
    fn root_outside_window_is_invalid() {
        let rln_id = [9u8; 32];
        // Two distinct identities → distinct leaves → distinct (canonical)
        // roots. Verifying proof A against only B's root must be false.
        let a = generate(
            &material_from_seed(&[7u8; 32], 100, 0),
            b"hello",
            1,
            &rln_id,
        )
        .expect("generate a");
        let b = generate(
            &material_from_seed(&[8u8; 32], 100, 0),
            b"hello",
            1,
            &rln_id,
        )
        .expect("generate b");
        assert_ne!(a.root(), b.root());
        assert!(!verify(&a, b"hello", &[b.root()]).expect("verify"));
        // A window that is present but entirely non-canonical is also invalid.
        assert!(!verify(&a, b"hello", &[[0xffu8; 32]]).expect("verify non-canonical"));
    }

    // The spec-struct path: a consumer that reassembles the proof from its
    // OWN network message fields (bare 128-byte Groth16 + the five public
    // values) must land in the identical verified representation as the
    // canonical form.
    #[test]
    fn decomposed_spec_struct_roundtrip_verifies() {
        let material = material_from_seed(&[5u8; 32], 100, 2);
        let rln_id = [6u8; 32];
        let proof = generate(&material, b"net msg", 77, &rln_id).expect("generate");
        let root = proof.root();
        let j = proof.to_json();

        // Slice the bare Groth16 proof out of the canonical bytes — exactly
        // what the spec's proof[128] carries.
        let canonical = hex_to_vec(j["proof"].as_str().unwrap()).unwrap();
        let bare = bytes_to_hex(&canonical[..128]);
        let decomposed = serde_json::json!({
            "proof": bare,
            "root": j["root"],
            "external_nullifier": j["external_nullifier"],
            "share_x": j["share_x"],
            "share_y": j["share_y"],
            "nullifier": j["nullifier"],
        });

        let restored = RateLimitProof::from_json(&decomposed).expect("decomposed from_json");
        assert_eq!(restored.root(), root);
        assert_eq!(
            restored.to_json()["proof"],
            j["proof"],
            "reconstruction must be byte-identical to the canonical form"
        );
        assert!(verify(&restored, b"net msg", &[root]).expect("verify"));

        // A tampered public value breaks reconstruction or verification —
        // never a silent pass.
        let mut bad = decomposed.clone();
        bad["share_y"] = serde_json::json!("11".repeat(32));
        match RateLimitProof::from_json(&bad) {
            Err(_) => {}
            Ok(p) => assert!(!verify(&p, b"net msg", &[root]).expect("verify tampered")),
        }
    }

    #[test]
    fn json_roundtrip_preserves_verification() {
        let material = material_from_seed(&[3u8; 32], 100, 1);
        let rln_id = [4u8; 32];
        let proof = generate(&material, b"signal", 42, &rln_id).expect("generate");
        let root = proof.root();
        let json = proof.to_json();
        let restored = RateLimitProof::from_json(&json).expect("from_json");
        assert_eq!(restored.root(), root);
        assert!(verify(&restored, b"signal", &[root]).expect("verify"));
    }

    #[test]
    fn message_id_at_or_above_rate_limit_is_bad_input() {
        // message_id must be < rate_limit; the circuit rejects otherwise.
        let material = material_from_seed(&[1u8; 32], 5, 5);
        let err = generate(&material, b"x", 1, &[0u8; 32]).unwrap_err();
        assert!(matches!(err, ProofError::BadInput(_)));
    }

    #[test]
    fn short_merkle_path_is_bad_input() {
        let mut material = material_from_seed(&[1u8; 32], 100, 0);
        material.path_elements_hex.truncate(RLN_TREE_DEPTH - 1);
        material.path_indices.truncate(RLN_TREE_DEPTH - 1);
        let err = generate(&material, b"x", 1, &[0u8; 32]).unwrap_err();
        assert!(matches!(err, ProofError::BadInput(_)));
    }

    #[test]
    fn epoch_from_bytes_rejects_non_canonical_padding() {
        let canonical = epoch_to_bytes(1231028105);
        assert_eq!(epoch_from_bytes(&canonical), Some(1231028105));

        let mut tampered = canonical;
        tampered[20] = 0xff;
        assert_eq!(epoch_from_bytes(&tampered), None);
    }

    #[test]
    fn epoch_survives_generate_and_json_roundtrip() {
        let material = material_from_seed(&[3u8; 32], 100, 1);
        let rln_id = [4u8; 32];
        let proof = generate(&material, b"signal", 42, &rln_id).expect("generate");
        assert_eq!(proof.epoch(), Some(42));

        let restored = RateLimitProof::from_json(&proof.to_json()).expect("from_json");
        assert_eq!(restored.epoch(), Some(42));
    }

    // The generate_proof handler's reply carries "epoch" as a u64 index, and
    // verify_proof accepts that object as-is — so from_json must decode a
    // numeric epoch identically to the epoch[32] hex form.
    #[test]
    fn from_json_accepts_numeric_epoch_from_the_handler_reply() {
        let material = material_from_seed(&[3u8; 32], 100, 1);
        let rln_id = [4u8; 32];
        let proof = generate(&material, b"signal", 42, &rln_id).expect("generate");

        let mut wire = proof.to_json();
        wire["epoch"] = serde_json::json!(42u64);
        let restored = RateLimitProof::from_json(&wire).expect("from_json");
        assert_eq!(restored.epoch(), Some(42));

        wire["epoch"] = serde_json::json!(-1);
        assert!(matches!(
            RateLimitProof::from_json(&wire).unwrap_err(),
            ProofError::BadInput(_)
        ));
    }

    // The double-signal path: two proofs from the SAME identity, epoch, and slot
    // (generate_for_test pins message_id = 0) over DIFFERENT signals share one
    // nullifier but split on share_x — the exact collision the nullifier log
    // flags as a rate-limit violation. Their two Shamir shares reconstruct the
    // offender's own secret, which for seed 32×0x07 is the frozen value.
    #[test]
    fn recover_identity_secret_from_colliding_shares() {
        let rln_id = [9u8; 32];
        let a = generate_for_test(&[7u8; 32], b"signal-A", 1231028105, &rln_id);
        let b = generate_for_test(&[7u8; 32], b"signal-B", 1231028105, &rln_id);
        assert_eq!(
            a.nullifier(),
            b.nullifier(),
            "same identity+epoch+slot ⇒ one nullifier"
        );
        assert_ne!(
            a.share_x(),
            b.share_x(),
            "distinct signals ⇒ distinct share_x"
        );

        let secret =
            recover_identity_secret_hex((a.share_x(), a.share_y()), (b.share_x(), b.share_y()))
                .expect("recover");
        assert_eq!(
            secret,
            "3c87aa7480ec2cad022ef39c256ddb6e4fb083c7d4a0dfdc4eee891feda7a62b"
        );
    }
}
