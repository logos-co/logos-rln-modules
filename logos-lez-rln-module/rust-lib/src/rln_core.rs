//! RLN core logic — register/proof/funding planning and account decoding,
//! called from `lib.rs` as plain Rust (no C ABI).

use borsh::BorshDeserialize;
use rln_layouts::{
    combine_seeds, label_seed, u32_seed,
    MembershipState, TreeMainLayout, ROOT_HISTORY_SIZE,
    OFFSET_CACHED_NODES, OFFSET_DEPTH, OFFSET_ROOT, OFFSET_TOP_TREE_DATA,
    TOP_DEPTH, TREE_DEPTH, SUBTREE_LEAVES,
    read_sparse_node,
};
use serde::Serialize;
use sha2::{Sha256, Digest};

pub use rln_layouts::{MAX_RATE_LIMIT, MIN_RATE_LIMIT};

pub const MAX_SUBTREES_PER_CALL: usize = 64;

/// A single merkle proof.
pub struct RlnMerkleProof {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub depth: u32,
    pub path_elements: [[u8; 32]; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
}

/// The accounts a merkle-proofs call must fetch.
pub struct MerkleProofsPlan {
    pub main_account_id: [u8; 32],
    pub subtree_account_ids: [[u8; 32]; MAX_SUBTREES_PER_CALL],
    pub subtree_ids: [u32; MAX_SUBTREES_PER_CALL],
    pub subtree_count: u32,
}

/// Derived account IDs for a registration transaction.
pub struct RlnRegisterPlan {
    pub config_account_id: [u8; 32],
    pub tree_main_account_id: [u8; 32],
    pub treasury_account_id: [u8; 32],
    pub subtree_account_id: [u8; 32],
    pub clock_account_id: [u8; 32],
    /// Membership PDA from (program_owner, tree_id, id_commitment).
    /// Required by the `Register` instruction's `init`-marked membership account.
    pub membership_account_id: [u8; 32],
    /// The config's tree_id (`CONFIG_OFFSET_TREE_ID`), carried so callers
    /// building the `Register` instruction never re-slice raw config bytes.
    pub tree_id: [u8; 32],
    pub subtree_id: u32,
    pub next_leaf_index: u64,
}

/// `rln_layouts::ConfigState` field offsets (borsh: fixed-width fields in
/// declaration order, no prefixes). The layout is APPEND-ONLY, so these are
/// stable across config versions; reading by offset keeps this working
/// against both pre-policy (240-byte) and policy (296-byte) deployments,
/// where an exact-size borsh decode would reject the other version.
pub const CONFIG_OFFSET_TREE_ID: usize = 32;
// Not read at runtime; kept so the offset table stays complete and the
// layout-pin test covers the full append-only layout.
#[allow(dead_code)]
pub const CONFIG_OFFSET_PAYMENT_TOKEN_ID: usize = 64;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 128;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 144;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 176;
pub const CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT: usize = 184;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 192;
pub const CONFIG_OFFSET_ACTIVE_DURATION: usize = 200;
pub const CONFIG_OFFSET_GRACE_DURATION: usize = 204;
// Not read at runtime; see CONFIG_OFFSET_PAYMENT_TOKEN_ID.
#[allow(dead_code)]
pub const CONFIG_OFFSET_TOKEN_PROGRAM_ID: usize = 208;
/// Minimum (pre-policy) ConfigState size — the precheck floor. NOT the full
/// policy-era size (296, the host's `CONFIG_SIZE`); accepting 240 is what
/// keeps this working against pre-policy deployments.
pub const CONFIG_STATE_MIN_SIZE: usize = 240;

/// Read a 32-byte field out of raw config-account bytes by offset.
pub fn config_field_32(config_data: &[u8], offset: usize) -> [u8; 32] {
    config_data[offset..offset + 32]
        .try_into()
        .expect("32-byte config field")
}

/// LE-integer field readers for the same offset scheme (callers pre-check
/// `CONFIG_STATE_MIN_SIZE`, matching config_field_32's panic-on-short slice).
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

/// Borsh size of the on-chain `MembershipState` (8+8+32+8+4+4 bytes).
pub const MEMBERSHIP_STATE_SIZE: usize = 64;

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

    let hash = Sha256::digest(&input);
    hash.into()
}

/// risc0-serde an instruction into its u32 words — the deployed programs'
/// wire format (LE words on the wire); `send_generic_public_transaction`
/// takes the words directly.
fn serialize_instruction<T: Serialize>(instruction: &T) -> Result<Vec<u32>, RlnError> {
    risc0_zkvm::serde::to_vec(instruction).map_err(|_| RlnError::SerializationError)
}

/// Parse tree-main account data and return the valid roots.
///
/// Index 0 = current root. Indices 1..N = non-zero history entries.
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

/// Build a merkle proof for a single leaf given pre-fetched main + subtree data.
pub fn build_merkle_proof(
    main_data: &[u8],
    subtree_data: &[u8],
    leaf_index: u64,
) -> Result<RlnMerkleProof, RlnError> {
    let min_main_len = OFFSET_CACHED_NODES + (TREE_DEPTH + 1) * 32;
    if main_data.len() < min_main_len {
        return Err(RlnError::DataTooShort);
    }

    let depth = main_data[OFFSET_DEPTH] as usize;
    if depth == 0 || depth > TREE_DEPTH {
        return Err(RlnError::DataTooShort);
    }

    let max_leaves = 1u64 << depth;
    if leaf_index >= max_leaves {
        return Err(RlnError::InvalidLeafIndex);
    }

    let root: [u8; 32] = main_data[OFFSET_ROOT..OFFSET_ROOT + 32].try_into().unwrap();

    let cached_defaults: Vec<[u8; 32]> = (0..=depth)
        .map(|i| {
            let start = OFFSET_CACHED_NODES + i * 32;
            main_data[start..start + 32].try_into().unwrap()
        })
        .collect();

    let top_tree_data = if main_data.len() > OFFSET_TOP_TREE_DATA {
        &main_data[OFFSET_TOP_TREE_DATA..]
    } else {
        &[]
    };

    let fetch_node = |level: usize, node_index: u64| -> [u8; 32] {
        if level <= TOP_DEPTH {
            read_sparse_node(top_tree_data, level, node_index as usize, &cached_defaults[level])
        } else {
            let bottom_level = level - TOP_DEPTH;
            let nodes_per_subtree = 1usize << bottom_level;
            let local_index = node_index as usize % nodes_per_subtree;
            read_sparse_node(subtree_data, bottom_level, local_index, &cached_defaults[level])
        }
    };

    let leaf = fetch_node(depth, leaf_index);

    let mut path_elements = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices = [0u8; TREE_DEPTH];
    let mut current_index = leaf_index;

    for i in 0..depth {
        let level = depth - i;
        let is_right = (current_index % 2) as u8;
        path_indices[i] = is_right;

        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        path_elements[i] = fetch_node(level, sibling_index);
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

/// Phase 1: compute which accounts a merkle-proofs call must fetch.
///
/// `program_owner`: 32-byte registration program ID. Tree main and subtree
/// accounts are PDAs of this program, NOT the merkle program.
pub fn merkle_proofs_plan(
    config_data: &[u8],
    program_owner: &[u8; 32],
    leaf_indices: &[u64],
) -> Result<MerkleProofsPlan, RlnError> {
    if config_data.len() < CONFIG_STATE_MIN_SIZE {
        return Err(RlnError::InvalidConfig);
    }

    let tree_id: &[u8; 32] = &config_field_32(config_data, CONFIG_OFFSET_TREE_ID);
    let main_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("main"), tree_id]));

    let mut unique_ids: Vec<u32> = leaf_indices
        .iter()
        .map(|&idx| {
            u32::try_from(idx / SUBTREE_LEAVES as u64).map_err(|_| RlnError::InvalidLeafIndex)
        })
        .collect::<Result<_, _>>()?;
    unique_ids.sort_unstable();
    unique_ids.dedup();

    if unique_ids.len() > MAX_SUBTREES_PER_CALL {
        return Err(RlnError::InvalidLeafIndex);
    }

    let mut plan = MerkleProofsPlan {
        main_account_id,
        subtree_account_ids: [[0u8; 32]; MAX_SUBTREES_PER_CALL],
        subtree_ids: [0u32; MAX_SUBTREES_PER_CALL],
        subtree_count: unique_ids.len() as u32,
    };

    for (i, &subtree_id) in unique_ids.iter().enumerate() {
        plan.subtree_account_ids[i] = derive_pda(
            program_owner,
            &combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)]),
        );
        plan.subtree_ids[i] = subtree_id;
    }

    Ok(plan)
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

/// Phase 2: build all proofs from fetched account data, as typed proof
/// objects (the caller serializes them together with `valid_roots`).
pub fn merkle_proofs_exec(
    main_data: &[u8],
    subtrees: &[(u32, &[u8])],
    leaf_indices: &[u64],
) -> Result<Vec<ProofJson>, RlnError> {
    let mut proofs = Vec::with_capacity(leaf_indices.len());

    for &leaf_index in leaf_indices {
        let subtree_id = u32::try_from(leaf_index / SUBTREE_LEAVES as u64)
            .map_err(|_| RlnError::InvalidLeafIndex)?;

        let subtree_data: &[u8] = subtrees
            .iter()
            .find(|(id, _)| *id == subtree_id)
            .map(|(_, data)| *data)
            .unwrap_or(&[]);

        let proof = build_merkle_proof(main_data, subtree_data, leaf_index)?;

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

/// Plan a registration transaction by deriving all required account IDs.
pub fn register_plan(
    config_data: &[u8],
    tree_main_data: &[u8],
    program_owner: &[u8; 32],
    id_commitment: &[u8; 32],
) -> Result<RlnRegisterPlan, RlnError> {
    if config_data.len() < CONFIG_STATE_MIN_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    if tree_main_data.len() < TreeMainLayout::SIZE {
        return Err(RlnError::DataTooShort);
    }

    let tree_main = TreeMainLayout::parse(tree_main_data);
    let tree_id: &[u8; 32] = &config_field_32(config_data, CONFIG_OFFSET_TREE_ID);

    let config_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("config"), tree_id]));
    let tree_main_account_id =
        derive_pda(program_owner, &combine_seeds(&[&label_seed("main"), tree_id]));

    let next_leaf_index = tree_main.next_index();
    let subtree_id = (next_leaf_index / SUBTREE_LEAVES as u64) as u32;
    let subtree_account_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("subtree"), tree_id, &u32_seed(subtree_id)]),
    );

    let membership_account_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("membership"), tree_id, id_commitment]),
    );

    Ok(RlnRegisterPlan {
        config_account_id,
        tree_main_account_id,
        treasury_account_id: config_field_32(config_data, CONFIG_OFFSET_TREASURY_ACCOUNT_ID),
        subtree_account_id,
        clock_account_id: rln_layouts::CLOCK_50_ACCOUNT_ID_BYTES,
        membership_account_id,
        tree_id: *tree_id,
        subtree_id,
        next_leaf_index,
    })
}

/// Build the `Instruction::Register` payload as risc0-serde u32 words.
pub fn register_build_instruction(
    tree_id: &[u8; 32],
    id_commitment: &[u8; 32],
    rate_limit: u64,
    subtree_id: u32,
) -> Result<Vec<u32>, RlnError> {
    let instruction = rln_layouts::Instruction::Register {
        tree_id: *tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        subtree_id,
    };
    serialize_instruction(&instruction)
}

/// Decode a fetched membership PDA's account data.
pub fn decode_membership(account_data: &[u8]) -> Result<MembershipState, RlnError> {
    if account_data.len() < MEMBERSHIP_STATE_SIZE {
        return Err(RlnError::DataTooShort);
    }
    MembershipState::try_from_slice(&account_data[..MEMBERSHIP_STATE_SIZE])
        .map_err(|_| RlnError::SerializationError)
}

/// Extract the timestamp from fetched CLOCK_50 account data (borsh
/// `ClockAccountData { block_id: u64, timestamp: u64 }` — LE u64 at 8..16).
pub fn decode_clock_timestamp(account_data: &[u8]) -> Result<u64, RlnError> {
    if account_data.len() < 16 {
        return Err(RlnError::DataTooShort);
    }
    Ok(u64::from_le_bytes(
        account_data[8..16].try_into().expect("8-byte clock field"),
    ))
}

/// Registry-visible lifecycle state of a membership at chain time `now`.
/// Registration sets `grace_period_start = now + active_duration`, so before
/// grace_start the membership is active; the guest's own boundary helpers
/// classify the remaining phases (the leaf stays in the tree through
/// grace_period AND expired — expired only means permissionlessly erasable).
///
/// Wire contract: the returned "active"/"grace_period"/"expired" strings are
/// consumed verbatim by the membership module's store ST_ACTIVE / ST_GRACE /
/// ST_EXPIRED consts (logos-rln-module). The two crates are
/// deliberately decoupled — no shared type — and the contract is pinned by
/// that crate's `membership_state_wire_strings` test.
pub fn membership_status(grace_start: u64, grace_duration: u32, now: u64) -> &'static str {
    if rln_layouts::is_expired(grace_start, grace_duration, now) {
        "expired"
    } else if rln_layouts::is_in_grace_period(grace_start, grace_duration, now) {
        "grace_period"
    } else {
        "active"
    }
}

// ============================================================================
// Funding plans (claim / balance)
// ============================================================================

/// Parse a Token-program holding account (borsh `TokenHolding`) → its token
/// definition id and fungible balance. `Err` for NFT holdings or non-holding
/// data. `deserialize` (not try_from_slice) tolerates trailing bytes.
pub fn token_holding_info(data: &[u8]) -> Result<([u8; 32], u128), RlnError> {
    let mut bytes = data;
    let holding = token_core::TokenHolding::deserialize(&mut bytes)
        .map_err(|_| RlnError::SerializationError)?;
    match holding {
        token_core::TokenHolding::Fungible {
            definition_id,
            balance,
        } => Ok((*definition_id.value(), balance)),
        token_core::TokenHolding::NftMaster { .. }
        | token_core::TokenHolding::NftPrintedCopy { .. } => Err(RlnError::InvalidConfig),
    }
}

/// Plan a faucet `ClaimTokens` transaction (faucet-funded deployments: the
/// payment token definition is the registration program's `payment` PDA,
/// program-authorized — no human key).
///
/// `program_owner`: the REGISTRATION program id (the claim tx targets this
/// program). Returns `(payment_def_id, instruction_words)`; the tx account
/// order is `[config, payment_def, dest (signer)]`.
pub fn claim_plan(
    config_data: &[u8],
    program_owner: &[u8; 32],
    amount: u128,
) -> Result<([u8; 32], Vec<u32>), RlnError> {
    if config_data.len() < CONFIG_STATE_MIN_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    let tree_id = config_field_32(config_data, CONFIG_OFFSET_TREE_ID);
    let payment_def_id = derive_pda(
        program_owner,
        &combine_seeds(&[&label_seed("payment"), &tree_id]),
    );
    let instruction = rln_layouts::Instruction::ClaimTokens { tree_id, amount };
    let instr = serialize_instruction(&instruction)?;
    Ok((payment_def_id, instr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rln_layouts::{combine_seeds, label_seed, ConfigState};

    fn make_config_state() -> Vec<u8> {
        let cfg = ConfigState {
            merkle_program_id: [0x11; 32],
            tree_id: [0x42; 32],
            payment_token_id: [0x22; 32],
            receipt_token_id: [0x23; 32],
            // Exceeds u64::MAX so the u128 offset read is proven 16 bytes wide.
            price_per_unit: 77_000_000_000_000_000_000,
            treasury_account_id: [0x33; 32],
            total_registrations: 12_345,
            max_total_rate_limit: 1_000_000,
            current_total_rate_limit: 4_242,
            active_duration_for_new_memberships: 100,
            grace_period_duration_for_new_memberships: 10,
            token_program_id: [0x44; 32],
            authorized_registrar: [0x55; 32],
            free_quota_remaining: 3,
            faucet_claim_cap: 1_000_000,
        };
        borsh::to_vec(&cfg).unwrap()
    }

    // Pins the CONFIG_OFFSET_* consts to rln_layouts::ConfigState's borsh
    // layout: each offset read must recover exactly its field's bytes, and the
    // last offset-read field must end at or before the 240-byte pre-policy floor.
    #[test]
    fn config_offsets_match_shared_layout() {
        let bytes = make_config_state();
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREE_ID), [0x42; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_PAYMENT_TOKEN_ID), [0x22; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREASURY_ACCOUNT_ID), [0x33; 32]);
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TOKEN_PROGRAM_ID), [0x44; 32]);
        assert_eq!(
            config_field_u128(&bytes, CONFIG_OFFSET_PRICE_PER_UNIT),
            77_000_000_000_000_000_000
        );
        assert_eq!(config_field_u64(&bytes, CONFIG_OFFSET_TOTAL_REGISTRATIONS), 12_345);
        assert_eq!(config_field_u64(&bytes, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT), 1_000_000);
        assert_eq!(
            config_field_u64(&bytes, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT),
            4_242
        );
        assert_eq!(config_field_u32(&bytes, CONFIG_OFFSET_ACTIVE_DURATION), 100);
        assert_eq!(config_field_u32(&bytes, CONFIG_OFFSET_GRACE_DURATION), 10);
        assert_eq!(
            CONFIG_OFFSET_TOKEN_PROGRAM_ID + 32,
            CONFIG_STATE_MIN_SIZE,
            "last offset-read field must fit within the pre-policy floor"
        );
        assert!(bytes.len() >= CONFIG_STATE_MIN_SIZE);
    }

    // Pins decode_clock_timestamp to clock_core's borsh ClockAccountData
    // layout: block_id u64 at 0..8, timestamp u64 at 8..16.
    #[test]
    fn clock_timestamp_decodes_and_rejects_short_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u64.to_le_bytes());
        data.extend_from_slice(&1_234_567u64.to_le_bytes());
        assert_eq!(decode_clock_timestamp(&data), Ok(1_234_567));
        assert_eq!(decode_clock_timestamp(&data[..15]), Err(RlnError::DataTooShort));
    }

    // Boundary semantics come from the guest helpers: grace starts AT
    // grace_start (inclusive) and expiry AT grace_start + duration (inclusive).
    #[test]
    fn membership_status_boundaries() {
        assert_eq!(membership_status(1_000, 50, 999), "active");
        assert_eq!(membership_status(1_000, 50, 1_000), "grace_period");
        assert_eq!(membership_status(1_000, 50, 1_049), "grace_period");
        assert_eq!(membership_status(1_000, 50, 1_050), "expired");
    }

    // Pins the Register instruction's word encoding (risc0-serde: variant
    // index 3, one word per u8, u64 as lo/hi words).
    #[test]
    fn register_instruction_words_pin() {
        let words = register_build_instruction(&[0xAB; 32], &[0xCD; 32], 0x1_0000_0002, 7).unwrap();
        assert_eq!(words.len(), 68);
        assert_eq!(words[0], 3, "Register variant index");
        assert_eq!(&words[1..33], &[0xABu32; 32], "tree_id, one word per byte");
        assert_eq!(&words[33..65], &[0xCDu32; 32], "id_commitment");
        assert_eq!(words[65], 2, "rate_limit low word");
        assert_eq!(words[66], 1, "rate_limit high word");
        assert_eq!(words[67], 7, "subtree_id");
    }

    #[test]
    fn plan_derives_correct_ids_with_program_owner() {
        let config_data = make_config_state();
        let program_owner: [u8; 32] = [0xAA; 32];
        let tree_id: [u8; 32] = [0x42; 32];

        let expected_main_id =
            derive_pda(&program_owner, &combine_seeds(&[&label_seed("main"), &tree_id]));

        let plan = merkle_proofs_plan(&config_data, &program_owner, &[0, 1, 1025]).unwrap();
        assert_eq!(expected_main_id, plan.main_account_id);
        assert_eq!(plan.subtree_count, 2);
        assert_eq!(plan.subtree_ids[0], 0);
        assert_eq!(plan.subtree_ids[1], 1);
        for i in 0..plan.subtree_count as usize {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&plan.subtree_ids[i].to_le_bytes());
            let expected = derive_pda(
                &program_owner,
                &combine_seeds(&[&label_seed("subtree"), &tree_id, &seed]),
            );
            assert_eq!(expected, plan.subtree_account_ids[i]);
        }
    }
}
