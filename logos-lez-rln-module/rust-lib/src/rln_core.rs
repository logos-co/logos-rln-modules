//! RLN core logic — register/proof/funding planning and account decoding,
//! called from `lib.rs` as plain Rust (no C ABI).

use borsh::{BorshDeserialize, BorshSerialize};
use rln_layouts::{
    config_seed, main_seed, membership_seed, read_sparse_node, MembershipState, TreeMainLayout,
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_ROOT, OFFSET_TREE_DATA, ROOT_HISTORY_SIZE,
    TREE_DEPTH,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The BN254 scalar field modulus, big-endian. The guest reads a commitment
/// as a little-endian field element and panics on one >= this.
const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Whether 32 little-endian bytes are a BN254 field element (< the modulus).
pub fn is_field_element_le(bytes: &[u8; 32]) -> bool {
    let mut be = *bytes;
    be.reverse();
    be < BN254_R_BE
}

/// The guest's own Register checks that a submitter can evaluate from chain
/// state it already holds (plus a zero commitment, which the guest accepts but
/// no identity derives), so a doomed registration is refused before it is
/// signed rather than charged on chain. A guest panic (a non-field commitment,
/// an out-of-range rate) is charged the full gas limit; an exit (capacity) its
/// measured cycles; neither registers anything. `next_index` is the tree's,
/// read with the plan.
pub fn check_register(
    config_data: &[u8],
    next_index: u64,
    id_commitment: &[u8; 32],
    rate_limit: u64,
) -> Result<(), String> {
    if *id_commitment == [0u8; 32] {
        return Err("invalid_commitment: the identity commitment is zero".into());
    }
    if !is_field_element_le(id_commitment) {
        return Err(
            "invalid_commitment: the identity commitment is not a BN254 field element \
                    (as little-endian bytes it is >= the modulus)"
                .into(),
        );
    }
    let min = config_field_u64(config_data, CONFIG_OFFSET_MIN_RATE_LIMIT);
    let max = config_field_u64(config_data, CONFIG_OFFSET_MAX_RATE_LIMIT);
    if !(min..=max).contains(&rate_limit) {
        return Err(format!(
            "invalid_rate_limit: {rate_limit} is outside the registry's {min}..={max}"
        ));
    }
    let current = config_field_u64(config_data, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT);
    let max = config_field_u64(config_data, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT);
    if current.saturating_add(rate_limit) > max {
        return Err(format!(
            "registry_full: {current} of {max} total rate limit is taken, {rate_limit} more does not fit"
        ));
    }
    if next_index >= 1u64 << TREE_DEPTH {
        return Err(format!(
            "tree_full: all {} leaves are taken",
            1u64 << TREE_DEPTH
        ));
    }
    Ok(())
}

/// A single merkle proof.
pub struct RlnMerkleProof {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub depth: u32,
    pub path_elements: [[u8; 32]; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
}

/// The accounts a registration transaction declares, and what the config and
/// tree say at planning time.
///
/// The program reads its own state when the message is delivered, so nothing
/// here is asserted on chain: the ids are what the transaction declares, the
/// rest is what a submitter checks before paying for a message the program
/// would refuse.
pub struct RlnRegisterPlan {
    pub config_account_id: [u8; 32],
    pub tree_main_account_id: [u8; 32],
    pub treasury_account_id: [u8; 32],
    /// Membership PDA from (registration program, tree_id, id_commitment).
    pub membership_account_id: [u8; 32],
    /// The config's tree_id (`CONFIG_OFFSET_TREE_ID`), carried so callers
    /// building the `Register` message never re-slice raw config bytes.
    pub tree_id: [u8; 32],
    /// The merkle program's header account id, from the config: the program
    /// whose actor state on `tree_main` holds the tree.
    pub merkle_program_id: [u8; 32],
    /// The tree's `next_index` at planning time: where this registration
    /// lands if nothing else does first. An estimate only — the tree assigns
    /// the slot itself when the registration applies.
    pub next_leaf_index: u64,
    /// The config's price per rate-limit unit, for the affordability check.
    pub price_per_unit: u128,
}

/// `rln_layouts::ConfigState` field offsets (borsh: fixed-width fields in
/// declaration order, no prefixes).
///
/// The layout is 160 bytes and not append-only: a field removed from the
/// middle re-points every offset after it.
///
/// `ConfigState` carries no version discriminator, so nothing in the account
/// distinguishes one layout from another — an old config read through these
/// offsets does not fail, it yields a plausible wrong treasury and a plausible
/// wrong price. The length is the only signal, which is why callers assert
/// `CONFIG_STATE_SIZE` exactly rather than a floor.
pub const CONFIG_OFFSET_MERKLE_PROGRAM_ID: usize = 0;
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 64;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 80;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 112;
pub const CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT: usize = 120;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 128;
pub const CONFIG_OFFSET_ACTIVE_DURATION: usize = 136;
pub const CONFIG_OFFSET_GRACE_DURATION: usize = 140;
pub const CONFIG_OFFSET_MIN_RATE_LIMIT: usize = 144;
pub const CONFIG_OFFSET_MAX_RATE_LIMIT: usize = 152;

/// Exact serialized size of the config account, from the shared crate rather
/// than restated here. A config of any other length belongs to a different
/// program generation and must be refused, not decoded.
pub const CONFIG_STATE_SIZE: usize = rln_layouts::state::CONFIG_STATE_SIZE;

/// Read a 32-byte field out of raw config-account bytes by offset.
pub fn config_field_32(config_data: &[u8], offset: usize) -> [u8; 32] {
    config_data[offset..offset + 32]
        .try_into()
        .expect("32-byte config field")
}

/// LE-integer field readers for the same offset scheme (callers pre-check
/// `CONFIG_STATE_SIZE`, matching config_field_32's panic-on-short slice).
pub fn config_field_u32(config_data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        config_data[offset..offset + 4]
            .try_into()
            .expect("u32 config field"),
    )
}

pub fn config_field_u64(config_data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        config_data[offset..offset + 8]
            .try_into()
            .expect("u64 config field"),
    )
}

pub fn config_field_u128(config_data: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(
        config_data[offset..offset + 16]
            .try_into()
            .expect("u128 config field"),
    )
}

/// Borsh size of the on-chain `MembershipState`, from the shared crate so a
/// layout change there reaches this decoder's length guard.
pub const MEMBERSHIP_STATE_SIZE: usize = rln_layouts::state::MEMBERSHIP_STATE_SIZE;

/// Errors surfaced by the RLN core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlnError {
    DataTooShort,
    InvalidConfig,
    InvalidLeafIndex,
    SerializationError,
}

impl core::fmt::Display for RlnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            RlnError::DataTooShort => "account data too short",
            RlnError::InvalidConfig => "invalid config account data",
            RlnError::InvalidLeafIndex => "invalid leaf index",
            RlnError::SerializationError => "serialization error",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for RlnError {}

const PDA_PREFIX: &[u8; 32] = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";

fn derive_pda(program_id: &[u8; 32], pda_seed: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(PDA_PREFIX);
    input[32..64].copy_from_slice(program_id);
    input[64..96].copy_from_slice(pda_seed);

    let hash = Sha256::digest(input);
    hash.into()
}

/// Borsh-encode a message — the deployed programs' wire format. A payload the
/// guest decodes differently does not fail to decode, it runs as a different
/// message, so this and the guests flip together.
fn serialize_message<T: BorshSerialize>(message: &T) -> Result<Vec<u8>, RlnError> {
    borsh::to_vec(message).map_err(|_| RlnError::SerializationError)
}

/// Parse tree-main account data and return the valid roots.
///
/// Index 0 = current root. Indices 1..N = non-zero history entries.
/// The tree's configured depth, from the main account header.
///
/// The prover's circuit is deeper than a shrunk registry, so a consumer has to
/// lift this tree's roots to the circuit's depth before comparing them with a
/// root a proof carries. It cannot do that without knowing the depth, so
/// `get_valid_roots` reports this alongside the roots — it is one byte of the
/// header the caller has already fetched.
pub fn tree_depth(data: &[u8]) -> Result<u8, RlnError> {
    if data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }
    Ok(TreeMainLayout::parse(data).tree_depth)
}

pub fn get_valid_roots(data: &[u8]) -> Result<Vec<[u8; 32]>, RlnError> {
    if data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }

    let header = TreeMainLayout::parse(data);

    let mut roots = Vec::with_capacity(1 + ROOT_HISTORY_SIZE);
    roots.push(header.current_root);

    let zero = [0u8; 32];
    for entry in &header.root_history {
        if *entry != zero {
            roots.push(*entry);
        }
    }

    Ok(roots)
}

/// Build a merkle proof for a single leaf from the tree's merkle shard.
///
/// The whole tree is kept in one shard of `tree_main`: the header,
/// then each level's default hash (root level first) at
/// `OFFSET_CACHED_NODES`, then one sparse node map from `OFFSET_TREE_DATA`.
/// There are no subtree accounts, so a proof is a read of one
/// account — which also makes it a consistent snapshot by construction.
pub fn build_merkle_proof(main_data: &[u8], leaf_index: u64) -> Result<RlnMerkleProof, RlnError> {
    if main_data.len() < OFFSET_TREE_DATA {
        return Err(RlnError::DataTooShort);
    }

    let depth = main_data[OFFSET_DEPTH] as usize;
    if depth == 0 || depth > TREE_DEPTH {
        return Err(RlnError::DataTooShort);
    }
    // Every offset past the header is a function of TREE_DEPTH; a shard
    // written at another depth would be misread rather than rejected.
    if depth != TREE_DEPTH {
        return Err(RlnError::InvalidConfig);
    }

    let max_leaves = 1u64 << depth;
    if leaf_index >= max_leaves {
        return Err(RlnError::InvalidLeafIndex);
    }

    let root: [u8; 32] = main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();

    let cached_defaults: Vec<[u8; 32]> = (0..=depth)
        .map(|level| {
            let start = OFFSET_CACHED_NODES + level * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect();
    let tree_data = &main_data[OFFSET_TREE_DATA..];
    let fetch_node = |level: usize, node_index: u64| -> [u8; 32] {
        read_sparse_node(
            tree_data,
            level,
            node_index as usize,
            &cached_defaults[level],
        )
    };

    let leaf = fetch_node(depth, leaf_index);

    let mut path_elements = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices = [0u8; TREE_DEPTH];
    let mut current_index = leaf_index;

    for i in 0..depth {
        let level = depth - i;
        path_indices[i] = (current_index % 2) as u8;
        path_elements[i] = fetch_node(level, current_index ^ 1);
        current_index /= 2;
    }

    Ok(RlnMerkleProof {
        leaf,
        root,
        leaf_index,
        depth: depth as u32,
        path_elements,
        path_indices,
    })
}

/// The tree's main account: a PDA of the REGISTRATION program, whose merkle
/// program actor state holds the tree.
pub fn tree_main_account_id(
    config_data: &[u8],
    registration_program: &[u8; 32],
) -> Result<[u8; 32], RlnError> {
    if config_data.len() != CONFIG_STATE_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    let tree_id = config_field_32(config_data, CONFIG_OFFSET_TREE_ID);
    Ok(derive_pda(registration_program, &main_seed(&tree_id)))
}

/// One wire proof object. Serialized by the caller via `serde_json::Value`
/// (BTreeMap ⇒ alphabetical keys, the frozen wire order), so field order
/// here is NOT wire-significant.
#[derive(Serialize)]
pub(crate) struct ProofJson {
    pub(crate) leaf: String,
    pub(crate) root: String,
    pub(crate) leaf_index: u64,
    pub(crate) depth: u32,
    pub(crate) path_elements: Vec<String>,
    pub(crate) path_indices: Vec<u8>,
}

/// Lowercase hex, no prefix — the module's single hex encoder (lib.rs
/// imports it for all wire hex).
pub(crate) fn bytes_to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Build all proofs from one read of the tree's merkle shard, as typed proof
/// objects (the caller serializes them together with `valid_roots`).
pub fn merkle_proofs_exec(
    main_data: &[u8],
    leaf_indices: &[u64],
) -> Result<Vec<ProofJson>, RlnError> {
    let mut proofs = Vec::with_capacity(leaf_indices.len());
    for &leaf_index in leaf_indices {
        let proof = build_merkle_proof(main_data, leaf_index)?;
        let depth = proof.depth as usize;
        proofs.push(ProofJson {
            leaf: bytes_to_hex(&proof.leaf),
            root: bytes_to_hex(&proof.root),
            leaf_index: proof.leaf_index,
            depth: proof.depth,
            path_elements: proof.path_elements[..depth]
                .iter()
                .map(|e| bytes_to_hex(e))
                .collect(),
            path_indices: proof.path_indices[..depth].to_vec(),
        });
    }
    Ok(proofs)
}

/// Plan a registration transaction: derive its accounts from the config and
/// read the tree's next slot from the merkle program's actor state.
pub fn register_plan(
    config_data: &[u8],
    tree_main_data: &[u8],
    registration_program: &[u8; 32],
    id_commitment: &[u8; 32],
) -> Result<RlnRegisterPlan, RlnError> {
    if config_data.len() != CONFIG_STATE_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    if tree_main_data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }

    let tree_main = TreeMainLayout::parse(tree_main_data);
    let tree_id = config_field_32(config_data, CONFIG_OFFSET_TREE_ID);

    Ok(RlnRegisterPlan {
        config_account_id: derive_pda(registration_program, &config_seed(&tree_id)),
        tree_main_account_id: derive_pda(registration_program, &main_seed(&tree_id)),
        treasury_account_id: config_field_32(config_data, CONFIG_OFFSET_TREASURY_ACCOUNT_ID),
        membership_account_id: derive_pda(
            registration_program,
            &membership_seed(&tree_id, id_commitment),
        ),
        tree_id,
        merkle_program_id: config_field_32(config_data, CONFIG_OFFSET_MERKLE_PROGRAM_ID),
        next_leaf_index: tree_main.next_index(),
        price_per_unit: config_field_u128(config_data, CONFIG_OFFSET_PRICE_PER_UNIT),
    })
}

/// Build the `Message::Register` payload as borsh bytes. `payer` signs the
/// transaction and is debited the price; `now_ms` is the submitter's reading
/// of chain time, read just before sending, which opens the message's
/// validity window.
pub fn register_build_message(
    plan: &RlnRegisterPlan,
    id_commitment: &[u8; 32],
    rate_limit: u64,
    payer: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<u8>, RlnError> {
    let message = rln_layouts::Message::Register {
        tree_id: plan.tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        payer: *payer,
        now_ms,
    };
    serialize_message(&message)
}

/// A membership's leaf: `rate_commitment = poseidon(id_commitment, rate_limit)`,
/// little-endian — the value the merkle program inserts. `None` when the
/// commitment is not a canonical BN254 field element.
pub fn registration_leaf(id_commitment: &[u8; 32], rate_limit: u64) -> Option<[u8; 32]> {
    use rln::prelude::{CanonicalDeserialize, CanonicalSerialize, Fr, Hasher, PoseidonHash};
    let id = Fr::deserialize_compressed(id_commitment.as_slice()).ok()?;
    let leaf = Hasher::<PoseidonHash>::hash_pair(id, Fr::from(rate_limit));
    let mut out = [0u8; 32];
    leaf.serialize_compressed(out.as_mut_slice()).ok()?;
    Some(out)
}

/// Where `leaf` sits in the tree, newest slot first, below `next_index`.
///
/// The merkle program assigns the slot when a registration applies and the
/// membership record does not carry it, so the tree is the only place the index lives. Mirrors lez-rln's
/// `merkle_tree::find_leaf_index`.
pub fn find_leaf_index(main_data: &[u8], leaf: &[u8; 32]) -> Option<u64> {
    if main_data.len() < OFFSET_TREE_DATA || main_data[OFFSET_DEPTH] as usize != TREE_DEPTH {
        return None;
    }
    let next = TreeMainLayout::parse(main_data)
        .next_index()
        .min(1u64 << TREE_DEPTH);
    let default: [u8; 32] = main_data
        [OFFSET_CACHED_NODES + TREE_DEPTH * 32..OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32]
        .try_into()
        .ok()?;
    let nodes = &main_data[OFFSET_TREE_DATA..];
    (0..next)
        .rev()
        .find(|&i| read_sparse_node(nodes, TREE_DEPTH, i as usize, &default) == *leaf)
}

/// Decode a fetched membership PDA's account data.
pub fn decode_membership(account_data: &[u8]) -> Result<MembershipState, RlnError> {
    if account_data.len() < MEMBERSHIP_STATE_SIZE {
        return Err(RlnError::DataTooShort);
    }
    MembershipState::try_from_slice(&account_data[..MEMBERSHIP_STATE_SIZE])
        .map_err(|_| RlnError::SerializationError)
}

/// Registry-visible lifecycle state of a membership at chain time `now_ms`.
/// Registration sets `grace_period_start_ms = now_ms + active_duration`, so
/// before grace_start the membership is active; the guest's own boundary
/// helpers classify the remaining phases (the leaf stays in the tree through
/// grace_period AND expired — expired only means permissionlessly erasable).
/// The conversion below must match the guest's or this module reports a
/// lifecycle the chain does not enforce.
///
/// Wire contract: the returned "active"/"grace_period"/"expired" strings are
/// consumed verbatim by the membership module's store ST_ACTIVE / ST_GRACE /
/// ST_EXPIRED consts (logos-rln-module). The two crates are
/// deliberately decoupled — no shared type — and the contract is pinned by
/// that crate's `membership_state_wire_strings` test.
pub fn membership_status(
    grace_start_ms: u64,
    grace_duration_sec: u32,
    now_ms: u64,
) -> &'static str {
    let grace_ms = rln_layouts::secs_to_millis(grace_duration_sec);
    if rln_layouts::is_expired(grace_start_ms, grace_ms, now_ms) {
        "expired"
    } else if rln_layouts::is_in_grace_period(grace_start_ms, grace_ms, now_ms) {
        "grace_period"
    } else {
        "active"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rln_layouts::{combine_seeds, label_seed, ConfigState};

    fn make_config_state() -> Vec<u8> {
        let cfg = ConfigState {
            merkle_program_id: [0x11; 32],
            tree_id: [0x42; 32],
            // Exceeds u64::MAX so the u128 offset read is proven 16 bytes wide.
            price_per_unit: 77_000_000_000_000_000_000,
            treasury_account_id: [0x33; 32],
            total_registrations: 12_345,
            max_total_rate_limit: 1_000_000,
            current_total_rate_limit: 4_242,
            active_duration_for_new_memberships_sec: 100,
            grace_period_duration_for_new_memberships_sec: 10,
            min_rate_limit: 100,
            max_rate_limit: 600,
        };
        borsh::to_vec(&cfg).unwrap()
    }

    // Pins the CONFIG_OFFSET_* consts to rln_layouts::ConfigState's borsh
    // layout: each offset read must recover exactly its field's bytes, and the
    // last one must end exactly at CONFIG_STATE_SIZE.
    #[test]
    fn config_offsets_match_shared_layout() {
        let bytes = make_config_state();
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREE_ID), [0x42; 32]);
        assert_eq!(
            config_field_32(&bytes, CONFIG_OFFSET_TREASURY_ACCOUNT_ID),
            [0x33; 32]
        );
        assert_eq!(
            config_field_u128(&bytes, CONFIG_OFFSET_PRICE_PER_UNIT),
            77_000_000_000_000_000_000
        );
        assert_eq!(
            config_field_u64(&bytes, CONFIG_OFFSET_TOTAL_REGISTRATIONS),
            12_345
        );
        assert_eq!(
            config_field_u64(&bytes, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT),
            1_000_000
        );
        assert_eq!(
            config_field_u64(&bytes, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT),
            4_242
        );
        assert_eq!(config_field_u32(&bytes, CONFIG_OFFSET_ACTIVE_DURATION), 100);
        assert_eq!(config_field_u32(&bytes, CONFIG_OFFSET_GRACE_DURATION), 10);
        assert_eq!(config_field_u64(&bytes, CONFIG_OFFSET_MIN_RATE_LIMIT), 100);
        assert_eq!(config_field_u64(&bytes, CONFIG_OFFSET_MAX_RATE_LIMIT), 600);
        // The last field ends exactly at the account's length. A floor would
        // let a config from another generation through; only an exact match
        // distinguishes this layout, since nothing in the account names it.
        assert_eq!(
            CONFIG_OFFSET_MAX_RATE_LIMIT + 8,
            CONFIG_STATE_SIZE,
            "the offset table must span the whole config, with nothing after it"
        );
        assert_eq!(bytes.len(), CONFIG_STATE_SIZE);
    }

    /// A config account of the wrong length is refused, not decoded.
    ///
    /// `ConfigState` carries no version discriminator, so nothing in the bytes
    /// says which generation they are. Read through this offset table, a
    /// 296-byte pre-native config does not error — it yields a treasury id and
    /// a price that are plausible and wrong, and a registration would pay a
    /// stranger.
    ///
    /// Both sizes below are the real ones: 296 is the config with the payment
    /// and credit tokens, 240 its ancestor before the policy fields.
    #[test]
    fn a_config_of_another_generation_is_refused() {
        let owner = [0x55; 32];
        let good = make_config_state();
        assert_eq!(good.len(), CONFIG_STATE_SIZE);

        for stale_len in [240usize, 296] {
            let mut stale = good.clone();
            stale.resize(stale_len, 0);
            assert!(
                matches!(
                    tree_main_account_id(&stale, &owner),
                    Err(RlnError::InvalidConfig)
                ),
                "a {stale_len}-byte config must be refused, not decoded"
            );
            assert!(
                matches!(
                    register_plan(&stale, &[0u8; 512], &owner, &[0x77; 32]),
                    Err(RlnError::InvalidConfig)
                ),
                "a {stale_len}-byte config must be refused before registering"
            );
        }

        // And the guard is a length check, not a rejection of everything: the
        // right size gets past it. (What it does next is the other tests'
        // business; only "not InvalidConfig" is claimed here.)
        assert!(!matches!(
            tree_main_account_id(&good, &owner),
            Err(RlnError::InvalidConfig)
        ));
    }

    // Boundary semantics come from the guest helpers: grace starts AT
    // grace_start_ms (inclusive) and expiry AT grace_start_ms + duration
    // (inclusive), so 50 s of grace runs to grace_start_ms + 50_000.
    #[test]
    fn membership_status_boundaries() {
        assert_eq!(membership_status(1_000, 50, 999), "active");
        assert_eq!(membership_status(1_000, 50, 1_000), "grace_period");
        assert_eq!(membership_status(1_000, 50, 50_999), "grace_period");
        assert_eq!(membership_status(1_000, 50, 51_000), "expired");
    }

    /// A 30-day membership must still be active an hour in.
    #[test]
    fn a_thirty_day_membership_is_active_an_hour_in() {
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
        let registered_ms = 1_700_000_000_000u64;
        let start_ms = registered_ms + 30 * DAY_MS;
        let grace_sec = 7 * 24 * 60 * 60;

        assert_eq!(
            membership_status(start_ms, grace_sec, registered_ms + 3_600_000),
            "active"
        );
        assert_eq!(
            membership_status(start_ms, grace_sec, registered_ms + 31 * DAY_MS),
            "grace_period"
        );
        assert_eq!(
            membership_status(start_ms, grace_sec, registered_ms + 38 * DAY_MS),
            "expired"
        );
    }

    /// An initialized, empty tree shard: header at depth TREE_DEPTH, each
    /// level's default at its own value, and an empty sparse map.
    fn make_tree_shard(next_index: u64) -> Vec<u8> {
        let mut shard = vec![0u8; OFFSET_TREE_DATA + 2];
        shard[OFFSET_DEPTH] = TREE_DEPTH as u8;
        shard[1..9].copy_from_slice(&next_index.to_le_bytes());
        for level in 0..=TREE_DEPTH {
            let at = OFFSET_CACHED_NODES + level * 32;
            shard[at..at + 32].copy_from_slice(&[level as u8 + 1; 32]);
        }
        shard
    }

    /// Put one node into a shard's sparse map (entries stay sorted, which
    /// `read_sparse_node`'s binary search needs).
    fn set_node(shard: &mut Vec<u8>, level: usize, index: usize, hash: [u8; 32]) {
        let mut entries: Vec<(u16, [u8; 32])> = Vec::new();
        let map = &shard[OFFSET_TREE_DATA..];
        let count = u16::from_le_bytes([map[0], map[1]]) as usize;
        for i in 0..count {
            let at = 2 + i * 34;
            let off = u16::from_le_bytes([map[at], map[at + 1]]);
            entries.push((off, map[at + 2..at + 34].try_into().unwrap()));
        }
        entries.push((rln_layouts::node_offset(level, index) as u16, hash));
        entries.sort_by_key(|e| e.0);
        shard.truncate(OFFSET_TREE_DATA);
        shard.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (off, h) in entries {
            shard.extend_from_slice(&off.to_le_bytes());
            shard.extend_from_slice(&h);
        }
    }

    // A proof reads every sibling from its own level of the one shard, and an
    // unset node reads as that level's cached default.
    #[test]
    fn a_proof_takes_each_sibling_from_its_own_level() {
        let mut shard = make_tree_shard(2);
        set_node(&mut shard, TREE_DEPTH, 0, [0xA0; 32]);
        set_node(&mut shard, TREE_DEPTH, 1, [0xA1; 32]);
        set_node(&mut shard, TREE_DEPTH - 1, 1, [0xB1; 32]);

        let p = build_merkle_proof(&shard, 1).unwrap();
        assert_eq!(p.leaf, [0xA1; 32]);
        assert_eq!(p.depth as usize, TREE_DEPTH);
        assert_eq!(p.path_indices[0], 1, "leaf 1 is a right child");
        assert_eq!(p.path_elements[0], [0xA0; 32], "its sibling is leaf 0");
        assert_eq!(p.path_elements[1], [0xB1; 32], "level depth-1, index 1");
        // Unset above that: the level's cached default.
        let level = TREE_DEPTH - 2;
        assert_eq!(p.path_elements[2], [level as u8 + 1; 32]);
    }

    #[test]
    fn a_proof_refuses_an_uninitialized_or_foreign_depth_shard() {
        assert_eq!(
            build_merkle_proof(&vec![0u8; OFFSET_TREE_DATA - 1], 0).err(),
            Some(RlnError::DataTooShort)
        );
        let mut shard = make_tree_shard(0);
        shard[OFFSET_DEPTH] = (TREE_DEPTH - 1) as u8;
        assert_eq!(
            build_merkle_proof(&shard, 0).err(),
            Some(RlnError::InvalidConfig)
        );
        let shard = make_tree_shard(0);
        assert_eq!(
            build_merkle_proof(&shard, 1u64 << TREE_DEPTH).err(),
            Some(RlnError::InvalidLeafIndex)
        );
    }

    #[test]
    fn field_elements_are_read_little_endian() {
        let mut ok = [0xffu8; 32];
        ok[31] = 0x00; // top byte, little-endian
        assert!(is_field_element_le(&ok));
        let mut bad = [0x00u8; 32];
        bad[31] = 0x31; // above the modulus' top byte 0x30
        assert!(!is_field_element_le(&bad));
        let mut r = BN254_R_BE;
        r.reverse();
        assert!(
            !is_field_element_le(&r),
            "the modulus itself is not an element"
        );
        let mut below = BN254_R_BE;
        below[31] = 0x00;
        below.reverse();
        assert!(is_field_element_le(&below));
    }

    #[test]
    fn check_register_refuses_what_the_guest_would() {
        let config = make_config_state();
        let (min_rate, max_rate) = (
            config_field_u64(&config, CONFIG_OFFSET_MIN_RATE_LIMIT),
            config_field_u64(&config, CONFIG_OFFSET_MAX_RATE_LIMIT),
        );
        let good = [0x01u8; 32];
        assert!(check_register(&config, 0, &good, min_rate).is_ok());
        assert!(check_register(&config, 0, &good, max_rate).is_ok());
        let mut bad = [0x01u8; 32];
        bad[31] = 0xff;
        assert!(check_register(&config, 0, &bad, min_rate)
            .unwrap_err()
            .starts_with("invalid_commitment"));
        assert!(check_register(&config, 0, &[0u8; 32], min_rate)
            .unwrap_err()
            .starts_with("invalid_commitment"));
        assert_eq!(
            check_register(&config, 0, &good, min_rate - 1).unwrap_err(),
            "invalid_rate_limit: 99 is outside the registry's 100..=600"
        );
        assert!(check_register(&config, 0, &good, max_rate + 1)
            .unwrap_err()
            .starts_with("invalid_rate_limit"));
        assert!(check_register(&config, 1u64 << TREE_DEPTH, &good, min_rate)
            .unwrap_err()
            .starts_with("tree_full"));
        let mut full = config.clone();
        let max = config_field_u64(&full, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT);
        full[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
            .copy_from_slice(&max.to_le_bytes());
        assert!(check_register(&full, 0, &good, min_rate)
            .unwrap_err()
            .starts_with("registry_full"));
    }

    /// The bounds are the registry's own, not a constant of this module.
    #[test]
    fn check_register_reads_the_registry_bounds() {
        let mut config = make_config_state();
        config[CONFIG_OFFSET_MIN_RATE_LIMIT..CONFIG_OFFSET_MIN_RATE_LIMIT + 8]
            .copy_from_slice(&20u64.to_le_bytes());
        config[CONFIG_OFFSET_MAX_RATE_LIMIT..CONFIG_OFFSET_MAX_RATE_LIMIT + 8]
            .copy_from_slice(&100u64.to_le_bytes());
        let good = [0x01u8; 32];
        assert!(check_register(&config, 0, &good, 20).is_ok());
        assert!(check_register(&config, 0, &good, 100).is_ok());
        assert!(check_register(&config, 0, &good, 19)
            .unwrap_err()
            .starts_with("invalid_rate_limit"));
        assert_eq!(
            check_register(&config, 0, &good, 101).unwrap_err(),
            "invalid_rate_limit: 101 is outside the registry's 20..=100"
        );
    }

    #[test]
    fn register_plan_derives_the_accounts_and_reads_the_tree() {
        let config = make_config_state();
        let program = [0xAA; 32];
        let plan = register_plan(&config, &make_tree_shard(37), &program, &[0x77; 32]).unwrap();
        assert_eq!(plan.merkle_program_id, [0x11; 32]);
        assert_eq!(plan.tree_id, [0x42; 32]);
        assert_eq!(plan.treasury_account_id, [0x33; 32]);
        assert_eq!(plan.next_leaf_index, 37);
        assert_eq!(plan.price_per_unit, 77_000_000_000_000_000_000);
        let tree_id = [0x42; 32];
        assert_eq!(
            plan.config_account_id,
            derive_pda(&program, &combine_seeds(&[&label_seed("config"), &tree_id]))
        );
        assert_eq!(
            plan.membership_account_id,
            derive_pda(
                &program,
                &combine_seeds(&[&label_seed("membership"), &tree_id, &[0x77; 32]])
            )
        );
        assert_eq!(
            plan.tree_main_account_id,
            tree_main_account_id(&config, &program).unwrap()
        );
        assert_eq!(
            plan.tree_main_account_id,
            derive_pda(&program, &combine_seeds(&[&label_seed("main"), &tree_id]))
        );
    }

    // Pins the Register message's byte encoding (borsh: a one-byte variant
    // discriminant, fixed-width arrays inline, integers little-endian). This is
    // consensus wire format shared with the deployed guest: a module encoding
    // against a guest that reads a different layout does not fail to decode,
    // it executes a different message — hence literals, not derivations.
    #[test]
    fn register_message_bytes_pin() {
        let mut plan = register_plan(
            &make_config_state(),
            &make_tree_shard(0x0102),
            &[0xAA; 32],
            &[0xCD; 32],
        )
        .unwrap();
        plan.tree_id = [0xAB; 32];
        let bytes =
            register_build_message(&plan, &[0xCD; 32], 0x1_0000_0002, &[0xEE; 32], 0x0A0B).unwrap();
        assert_eq!(bytes.len(), 1 + 32 + 32 + 8 + 32 + 8);
        assert_eq!(bytes[0], 2, "Register variant discriminant");
        assert_eq!(&bytes[1..33], &[0xABu8; 32], "tree_id");
        assert_eq!(&bytes[33..65], &[0xCDu8; 32], "id_commitment");
        assert_eq!(
            &bytes[65..73],
            &[2, 0, 0, 0, 1, 0, 0, 0],
            "rate_limit u64 LE"
        );
        assert_eq!(&bytes[73..105], &[0xEEu8; 32], "payer");
        assert_eq!(
            &bytes[105..113],
            &[0x0B, 0x0A, 0, 0, 0, 0, 0, 0],
            "now_ms u64 LE"
        );
    }

    // The guest decodes what this encodes, so the two must round-trip.
    #[test]
    fn register_message_round_trips_through_borsh() {
        let plan = register_plan(
            &make_config_state(),
            &make_tree_shard(5),
            &[0xAA; 32],
            &[0xCD; 32],
        )
        .unwrap();
        let bytes = register_build_message(&plan, &[0xCD; 32], 200, &[0xEE; 32], 9_999).unwrap();
        let rln_layouts::Message::Register {
            tree_id,
            id_commitment,
            rate_limit,
            payer,
            now_ms,
        } = rln_layouts::Message::try_from_slice(&bytes).expect("decodes")
        else {
            panic!("expected a Register message");
        };
        assert_eq!(tree_id, [0x42; 32]);
        assert_eq!(id_commitment, [0xCD; 32]);
        assert_eq!(rate_limit, 200);
        assert_eq!(payer, [0xEE; 32]);
        assert_eq!(now_ms, 9_999);
    }

    // The tree, not the membership, holds a member's index: found by its
    // leaf, newest slot first, and only below next_index.
    #[test]
    fn a_leaf_is_found_by_value_below_next_index() {
        let mut shard = make_tree_shard(3);
        set_node(&mut shard, TREE_DEPTH, 0, [0x11; 32]);
        set_node(&mut shard, TREE_DEPTH, 1, [0x22; 32]);
        set_node(&mut shard, TREE_DEPTH, 2, [0x11; 32]);
        set_node(&mut shard, TREE_DEPTH, 3, [0x33; 32]);
        assert_eq!(
            find_leaf_index(&shard, &[0x11; 32]),
            Some(2),
            "newest first"
        );
        assert_eq!(find_leaf_index(&shard, &[0x22; 32]), Some(1));
        assert_eq!(
            find_leaf_index(&shard, &[0x33; 32]),
            None,
            "at next_index, not below it"
        );
        assert_eq!(find_leaf_index(&shard, &[0x44; 32]), None);
    }

    // The leaf is poseidon(id_commitment, rate_limit): the rate limit is part
    // of it, so the same identity at another rate is another leaf.
    #[test]
    fn the_leaf_binds_the_rate_limit() {
        let id = [7u8; 32];
        let a = registration_leaf(&id, 100).expect("canonical commitment");
        assert_ne!(a, registration_leaf(&id, 200).unwrap());
        assert_eq!(a, registration_leaf(&id, 100).unwrap());
        assert!(
            registration_leaf(&[0xFF; 32], 100).is_none(),
            "non-canonical field element"
        );
    }
}
