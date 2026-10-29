//! RLN core logic — register/proof/funding planning and account decoding,
//! called from `lib.rs` as plain Rust (no C ABI).

use borsh::{BorshDeserialize, BorshSerialize};
use rln_layouts::{combine_seeds, label_seed, MembershipState};
use sha2::{Sha256, Digest};

pub use rln_layouts::{MAX_RATE_LIMIT, MIN_RATE_LIMIT};

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
/// measured cycles; neither registers anything.
///
/// There is no tree capacity check any more: the program keeps no tree, and
/// the zone service that builds one from the `Registered` events assigns the
/// slots itself.
pub fn check_register(
    config_data: &[u8],
    id_commitment: &[u8; 32],
    rate_limit: u64,
) -> Result<(), String> {
    if *id_commitment == [0u8; 32] {
        return Err("invalid_commitment: the identity commitment is zero".into());
    }
    if !is_field_element_le(id_commitment) {
        return Err("invalid_commitment: the identity commitment is not a BN254 field element \
                    (as little-endian bytes it is >= the modulus)"
            .into());
    }
    if !(MIN_RATE_LIMIT..=MAX_RATE_LIMIT).contains(&rate_limit) {
        return Err(format!(
            "invalid_rate_limit: {rate_limit} is outside the registry's {MIN_RATE_LIMIT}..={MAX_RATE_LIMIT}"
        ));
    }
    let current = config_field_u64(config_data, CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT);
    let max = config_field_u64(config_data, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT);
    if current.saturating_add(rate_limit) > max {
        return Err(format!(
            "registry_full: {current} of {max} total rate limit is taken, {rate_limit} more does not fit"
        ));
    }
    Ok(())
}

/// Derived account IDs, and the values the `Register` instruction claims,
/// for a registration transaction.
///
/// LEZ v0.3.0 runs a program's plan phase without account data, so every value
/// the guest used to read for itself is now a claim the host makes and the
/// guest asserts in apply. They are read from the chain just before sending;
/// a claim that went stale in between is refused, not misapplied.
pub struct RlnRegisterPlan {
    pub config_account_id: [u8; 32],
    pub treasury_account_id: [u8; 32],
    /// Membership PDA from (registration program, tree_id, id_commitment).
    pub membership_account_id: [u8; 32],
    /// The config's tree_id (`CONFIG_OFFSET_TREE_ID`), carried so callers
    /// building the `Register` instruction never re-slice raw config bytes.
    pub tree_id: [u8; 32],
    /// Claim: the config's price per rate-limit unit.
    pub price_per_unit: u128,
    /// Claims: the config's durations, snapshotted into the membership.
    pub active_duration_sec: u32,
    pub grace_period_duration_sec: u32,
    /// Claim: the config's `next_leaf_index` — the leaf this registration
    /// takes if it lands. A registration that lands first claims the same
    /// index and this one fails with `StaleLeafIndex` (exit 22); the caller
    /// rebuilds the plan from the new config.
    pub leaf_index: u64,
}

/// `rln_layouts::ConfigState` field offsets (borsh: fixed-width fields in
/// declaration order, no prefixes).
///
/// These were once described as append-only and read against a MINIMUM size,
/// so one module could serve a 240-byte and a 296-byte config at the same
/// time. Registration becoming native-only removed six fields from the middle
/// and the layout became 144 bytes, which ends both claims: a field removed
/// from the middle re-points every offset after it. Moving the tree off chain
/// then dropped the leading `merkle_program_id` (112 bytes, every offset
/// moved back 32), and leaf assignment returning on chain appended
/// `next_leaf_index`, so the layout is now 120 bytes.
///
/// `ConfigState` carries no version discriminator, so nothing in the account
/// distinguishes one layout from another — an old config read through these
/// offsets does not fail, it yields a plausible wrong treasury and a plausible
/// wrong price. The length is the only signal, which is why callers assert
/// `CONFIG_STATE_SIZE` exactly rather than a floor.
pub const CONFIG_OFFSET_TREE_ID: usize = 0;
pub const CONFIG_OFFSET_PRICE_PER_UNIT: usize = 32;
pub const CONFIG_OFFSET_TREASURY_ACCOUNT_ID: usize = 48;
pub const CONFIG_OFFSET_TOTAL_REGISTRATIONS: usize = 80;
pub const CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT: usize = 88;
pub const CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT: usize = 96;
pub const CONFIG_OFFSET_ACTIVE_DURATION: usize = 104;
pub const CONFIG_OFFSET_GRACE_DURATION: usize = 108;
pub const CONFIG_OFFSET_NEXT_LEAF_INDEX: usize = 112;

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
    SerializationError,
}

impl core::fmt::Display for RlnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            RlnError::DataTooShort => "account data too short",
            RlnError::InvalidConfig => "invalid config account data",
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

/// Borsh-encode an instruction — the deployed programs' wire format.
///
/// LEZ v0.2.5 decodes a program's instruction with borsh and widened the
/// instruction stream from `u32` words to plain bytes, so this and the guests
/// have to flip together: a risc0-serde payload does not decode, and the
/// mismatch shows up as a failed execution rather than a type error.
fn serialize_instruction<T: BorshSerialize>(instruction: &T) -> Result<Vec<u8>, RlnError> {
    borsh::to_vec(instruction).map_err(|_| RlnError::SerializationError)
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

/// Plan a registration transaction: derive its accounts and read every claim
/// the guest asserts from the config.
pub fn register_plan(
    config_data: &[u8],
    registration_program: &[u8; 32],
    id_commitment: &[u8; 32],
) -> Result<RlnRegisterPlan, RlnError> {
    if config_data.len() != CONFIG_STATE_SIZE {
        return Err(RlnError::InvalidConfig);
    }
    let tree_id: &[u8; 32] = &config_field_32(config_data, CONFIG_OFFSET_TREE_ID);

    let config_account_id =
        derive_pda(registration_program, &combine_seeds(&[&label_seed("config"), tree_id]));
    let membership_account_id = derive_pda(
        registration_program,
        &combine_seeds(&[&label_seed("membership"), tree_id, id_commitment]),
    );

    Ok(RlnRegisterPlan {
        config_account_id,
        treasury_account_id: config_field_32(config_data, CONFIG_OFFSET_TREASURY_ACCOUNT_ID),
        membership_account_id,
        tree_id: *tree_id,
        price_per_unit: config_field_u128(config_data, CONFIG_OFFSET_PRICE_PER_UNIT),
        active_duration_sec: config_field_u32(config_data, CONFIG_OFFSET_ACTIVE_DURATION),
        grace_period_duration_sec: config_field_u32(config_data, CONFIG_OFFSET_GRACE_DURATION),
        leaf_index: config_field_u64(config_data, CONFIG_OFFSET_NEXT_LEAF_INDEX),
    })
}

/// Build the `Instruction::Register` payload as borsh bytes. `now_ms` is the
/// CLOCK_50 timestamp read just before sending — a claim, like the plan's.
pub fn register_build_instruction(
    plan: &RlnRegisterPlan,
    id_commitment: &[u8; 32],
    rate_limit: u64,
    now_ms: u64,
) -> Result<Vec<u8>, RlnError> {
    let instruction = rln_layouts::Instruction::Register {
        tree_id: plan.tree_id,
        id_commitment: *id_commitment,
        rate_limit,
        now_ms,
        price_per_unit: plan.price_per_unit,
        active_duration_sec: plan.active_duration_sec,
        grace_period_duration_sec: plan.grace_period_duration_sec,
        leaf_index: plan.leaf_index,
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
pub fn decode_clock_timestamp_ms(account_data: &[u8]) -> Result<u64, RlnError> {
    if account_data.len() < 16 {
        return Err(RlnError::DataTooShort);
    }
    Ok(u64::from_le_bytes(
        account_data[8..16].try_into().expect("8-byte clock field"),
    ))
}

/// Registry-visible lifecycle state of a membership at chain time `now_ms`.
/// Registration sets `grace_period_start_ms = now_ms + active_duration`, so
/// before grace_start the membership is active; the guest's own boundary
/// helpers classify the remaining phases. Expired means permissionlessly
/// erasable on chain; the zone service drops an expired leaf from its tree on
/// its own clock.
/// The conversion below must match the guest's or this module reports a
/// lifecycle the chain does not enforce.
///
/// Wire contract: the returned "active"/"grace_period"/"expired" strings are
/// consumed verbatim by the membership module's store ST_ACTIVE / ST_GRACE /
/// ST_EXPIRED consts (logos-rln-module). The two crates are
/// deliberately decoupled — no shared type — and the contract is pinned by
/// that crate's `membership_state_wire_strings` test.
pub fn membership_status(grace_start_ms: u64, grace_duration_sec: u32, now_ms: u64) -> &'static str {
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
            tree_id: [0x42; 32],
            // Exceeds u64::MAX so the u128 offset read is proven 16 bytes wide.
            price_per_unit: 77_000_000_000_000_000_000,
            treasury_account_id: [0x33; 32],
            total_registrations: 12_345,
            max_total_rate_limit: 1_000_000,
            current_total_rate_limit: 4_242,
            active_duration_for_new_memberships_sec: 100,
            grace_period_duration_for_new_memberships_sec: 10,
            next_leaf_index: 0x0102_0304_0506,
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
        assert_eq!(config_field_32(&bytes, CONFIG_OFFSET_TREASURY_ACCOUNT_ID), [0x33; 32]);
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
        assert_eq!(config_field_u64(&bytes, CONFIG_OFFSET_NEXT_LEAF_INDEX), 0x0102_0304_0506);
        // The last field ends exactly at the account's length. A floor would
        // let a config from another generation through; only an exact match
        // distinguishes this layout, since nothing in the account names it.
        assert_eq!(
            CONFIG_OFFSET_NEXT_LEAF_INDEX + 8,
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
    /// stranger. The predecessor of this guard was `CONFIG_STATE_MIN_SIZE =
    /// 240`, a floor that admitted exactly that account.
    ///
    /// The sizes below are the real ones: 296 is the config with the payment
    /// and credit tokens, 240 its ancestor before the policy fields, 144
    /// the native-only config that still named a merkle program, and 112 the
    /// off-chain-tree config before leaf indices returned to the chain.
    #[test]
    fn a_config_of_another_generation_is_refused() {
        let owner = [0x55; 32];
        let good = make_config_state();
        assert_eq!(good.len(), CONFIG_STATE_SIZE);

        for stale_len in [112usize, 144, 240, 296] {
            let mut stale = good.clone();
            stale.resize(stale_len, 0);
            assert!(
                matches!(
                    register_plan(&stale, &owner, &[0x77; 32]),
                    Err(RlnError::InvalidConfig)
                ),
                "a {stale_len}-byte config must be refused before registering"
            );
        }

        // And the guard is a length check, not a rejection of everything: the
        // right size gets past it. (What it does next is the other tests'
        // business; only "not InvalidConfig" is claimed here.)
        assert!(register_plan(&good, &owner, &[0x77; 32]).is_ok());
    }

    // Pins decode_clock_timestamp to clock_core's borsh ClockAccountData
    // layout: block_id u64 at 0..8, timestamp u64 at 8..16.
    #[test]
    fn clock_timestamp_decodes_and_rejects_short_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&9u64.to_le_bytes());
        data.extend_from_slice(&1_234_567u64.to_le_bytes());
        assert_eq!(decode_clock_timestamp_ms(&data), Ok(1_234_567));
        assert_eq!(decode_clock_timestamp_ms(&data[..15]), Err(RlnError::DataTooShort));
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

    /// The regression at the scale it was reported: a 30-day membership must
    /// still be active an hour in.
    #[test]
    fn a_thirty_day_membership_is_active_an_hour_in() {
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
        let registered_ms = 1_700_000_000_000u64;
        let start_ms = registered_ms + 30 * DAY_MS;
        let grace_sec = 7 * 24 * 60 * 60;

        assert_eq!(membership_status(start_ms, grace_sec, registered_ms + 3_600_000), "active");
        assert_eq!(membership_status(start_ms, grace_sec, registered_ms + 31 * DAY_MS), "grace_period");
        assert_eq!(membership_status(start_ms, grace_sec, registered_ms + 38 * DAY_MS), "expired");
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
        assert!(!is_field_element_le(&r), "the modulus itself is not an element");
        let mut below = BN254_R_BE;
        below[31] = 0x00;
        below.reverse();
        assert!(is_field_element_le(&below));
    }

    #[test]
    fn check_register_refuses_what_the_guest_would() {
        let config = make_config_state();
        let good = [0x01u8; 32];
        assert!(check_register(&config, &good, MIN_RATE_LIMIT).is_ok());
        let mut bad = [0x01u8; 32];
        bad[31] = 0xff;
        assert!(check_register(&config, &bad, MIN_RATE_LIMIT).unwrap_err().starts_with("invalid_commitment"));
        assert!(check_register(&config, &[0u8; 32], MIN_RATE_LIMIT).unwrap_err().starts_with("invalid_commitment"));
        assert!(check_register(&config, &good, MIN_RATE_LIMIT - 1).unwrap_err().starts_with("invalid_rate_limit"));
        assert!(check_register(&config, &good, MAX_RATE_LIMIT + 1).unwrap_err().starts_with("invalid_rate_limit"));
        let mut full = config.clone();
        let max = config_field_u64(&full, CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT);
        full[CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT..CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT + 8]
            .copy_from_slice(&max.to_le_bytes());
        assert!(check_register(&full, &good, MIN_RATE_LIMIT).unwrap_err().starts_with("registry_full"));
    }

    // Every claim the guest asserts comes from the config.
    #[test]
    fn register_plan_reads_every_claim() {
        let config = make_config_state();
        let program = [0xAA; 32];
        let plan = register_plan(&config, &program, &[0x77; 32]).unwrap();
        assert_eq!(plan.tree_id, [0x42; 32]);
        assert_eq!(plan.treasury_account_id, [0x33; 32]);
        assert_eq!(plan.price_per_unit, 77_000_000_000_000_000_000);
        assert_eq!(plan.active_duration_sec, 100);
        assert_eq!(plan.grace_period_duration_sec, 10);
        assert_eq!(plan.leaf_index, 0x0102_0304_0506);
        let tree_id = [0x42; 32];
        assert_eq!(
            plan.membership_account_id,
            derive_pda(&program, &combine_seeds(&[&label_seed("membership"), &tree_id, &[0x77; 32]]))
        );
        assert_eq!(
            plan.config_account_id,
            derive_pda(&program, &combine_seeds(&[&label_seed("config"), &tree_id]))
        );
    }

    // Pins the Register instruction's byte encoding (borsh: a one-byte variant
    // discriminant, fixed-width arrays inline, integers little-endian). This is
    // consensus wire format shared with the deployed guest: a module encoding
    // against a guest that reads a different layout does not fail to decode,
    // it executes a different instruction — hence literals, not derivations.
    #[test]
    fn register_instruction_bytes_pin() {
        let mut plan = register_plan(&make_config_state(), &[0xAA; 32], &[0xCD; 32]).unwrap();
        plan.tree_id = [0xAB; 32];
        let bytes = register_build_instruction(&plan, &[0xCD; 32], 0x1_0000_0002, 0x0A0B).unwrap();
        assert_eq!(bytes.len(), 1 + 32 + 32 + 8 + 8 + 16 + 4 + 4 + 8);
        assert_eq!(bytes[0], 1, "Register variant discriminant");
        assert_eq!(&bytes[1..33], &[0xABu8; 32], "tree_id");
        assert_eq!(&bytes[33..65], &[0xCDu8; 32], "id_commitment");
        assert_eq!(&bytes[65..73], &[2, 0, 0, 0, 1, 0, 0, 0], "rate_limit u64 LE");
        assert_eq!(&bytes[73..81], &[0x0B, 0x0A, 0, 0, 0, 0, 0, 0], "now_ms u64 LE");
        assert_eq!(
            &bytes[81..97],
            &77_000_000_000_000_000_000u128.to_le_bytes(),
            "price_per_unit u128 LE"
        );
        assert_eq!(&bytes[97..101], &[100, 0, 0, 0], "active_duration_sec");
        assert_eq!(&bytes[101..105], &[10, 0, 0, 0], "grace_period_duration_sec");
        assert_eq!(&bytes[105..113], &[6, 5, 4, 3, 2, 1, 0, 0], "leaf_index u64 LE");
    }

    // The guest decodes what this encodes, so the two must round-trip.
    #[test]
    fn register_instruction_round_trips_through_borsh() {
        let plan = register_plan(&make_config_state(), &[0xAA; 32], &[0xCD; 32]).unwrap();
        let bytes = register_build_instruction(&plan, &[0xCD; 32], 200, 9_999).unwrap();
        let rln_layouts::Instruction::Register {
            tree_id,
            id_commitment,
            rate_limit,
            now_ms,
            price_per_unit,
            active_duration_sec,
            grace_period_duration_sec,
            leaf_index,
        } = rln_layouts::Instruction::try_from_slice(&bytes).expect("decodes")
        else {
            panic!("expected a Register instruction");
        };
        assert_eq!(tree_id, [0x42; 32]);
        assert_eq!(id_commitment, [0xCD; 32]);
        assert_eq!(rate_limit, 200);
        assert_eq!(now_ms, 9_999);
        assert_eq!(price_per_unit, 77_000_000_000_000_000_000);
        assert_eq!(active_duration_sec, 100);
        assert_eq!(grace_period_duration_sec, 10);
        assert_eq!(leaf_index, 0x0102_0304_0506);
    }
}
