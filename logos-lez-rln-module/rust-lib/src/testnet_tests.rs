//! Live-registry integration tests: rln_core's chain-facing logic (layout
//! offsets, PDA derivation, proof construction, chain time, lifecycle state)
//! validated against a DEPLOYED registration program.
//!
//! Read-only and OFF by default — every test no-ops unless
//! `LEZ_RLN_TESTNET_TESTS=1`. Run with:
//!
//! ```sh
//! LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_ -- --nocapture
//! ```
//!
//! The registry under test comes from a logos-lez-rln checkout's deployment
//! records: `<LEZ_RLN_CHECKOUT>/deployments/<name>/deployment.json`
//! (checkout default: `../logos-lez-rln` next to this repo), `<name>` =
//! `LEZ_RLN_TESTNET_DEPLOYMENT` (default `DEFAULT_DEPLOYMENT`, the last
//! hosted-testnet deployment, made on LEZ v0.3: against an rc1 chain name a
//! deployment provisioned there). The sequencer is reached over its public
//! JSON-RPC (`getAccount` — the same read the wallet's `read_account` serves
//! this module at runtime) via a `curl` subprocess, so the tests exercise the
//! RPC shape the wallet library hides.
//!
//! What this catches that unit pins cannot: ConfigState layout drift
//! against the DEPLOYED program (the guest image is pinned by provisioned
//! deployments), PDA-derivation divergence, tree/proof encoding drift, and
//! chain-time unit changes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_chacha::ChaCha20Rng;
use rln::prelude::{
    CanonicalDeserialize, CanonicalSerialize, Fr, Hasher, IdentityKeys, PoseidonHash,
};

use crate::hex_to_bytes32;
use crate::rln_core as native;
use native::bytes_to_hex;

/// 32-byte little-endian canonical form of a field element — the node/leaf
/// wire format the tree accounts store.
fn fr_to_bytes_le(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(bytes.as_mut_slice())
        .expect("Fr canonical form is exactly 32 bytes");
    bytes
}

/// Parses a 32-byte little-endian value as a field element; None if
/// non-canonical (>= the BN254 scalar field modulus).
fn bytes_le_to_fr(bytes: &[u8; 32]) -> Option<Fr> {
    Fr::deserialize_compressed(bytes.as_slice()).ok()
}

struct Deployment {
    sequencer: String,
    config_account: [u8; 32],
    tree_id_hex: String,
    registration_program_id_hex: String,
    merkle_program_id_hex: String,
}

const DEFAULT_DEPLOYMENT: &str = "testnet-faucet-260908";

/// Gate + deployment loader. `None` = skip (gate unset).
fn testnet() -> Option<Deployment> {
    if std::env::var("LEZ_RLN_TESTNET_TESTS").ok().as_deref() != Some("1") {
        eprintln!("testnet test skipped: set LEZ_RLN_TESTNET_TESTS=1 to run against the live registry");
        return None;
    }
    let name = std::env::var("LEZ_RLN_TESTNET_DEPLOYMENT").unwrap_or_else(|_| DEFAULT_DEPLOYMENT.to_string());
    // Deployment descriptors live with the programs in logos-co/logos-lez-rln;
    // LEZ_RLN_CHECKOUT points at that checkout (default: a sibling of this
    // repo).
    let checkout = std::env::var("LEZ_RLN_CHECKOUT").map(PathBuf::from).unwrap_or_else(|_| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../logos-lez-rln")
    });
    let path = checkout.join("deployments").join(&name).join("deployment.json");
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("deployment record {}: {e}", path.display())),
    )
    .expect("deployment.json parses");
    let field = |key: &str| {
        doc.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("deployment.json lacks {key}"))
            .to_string()
    };
    Some(Deployment {
        sequencer: field("sequencer"),
        config_account: b58_decode32(&field("config_account")),
        tree_id_hex: field("tree_id"),
        registration_program_id_hex: field("registration_program_id"),
        merkle_program_id_hex: field("merkle_program_id"),
    })
}

// ------------------------------------------------------------------- base58
//
// The sequencer's getAccount takes base58 account ids (the wallet does this
// conversion at runtime via account_id_from_base58).

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_encode(input: &[u8; 32]) -> String {
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
        out.push(B58[digit] as char);
    }
    out
}

fn b58_decode32(s: &str) -> [u8; 32] {
    let mut bytes: Vec<u8> = vec![];
    for c in s.chars() {
        let value = B58
            .iter()
            .position(|&b| b as char == c)
            .unwrap_or_else(|| panic!("invalid base58 char {c:?}")) as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for c in s.chars() {
        if c == '1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    assert!(bytes.len() <= 32, "base58 value exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

// ------------------------------------------------------------------ JSON-RPC

fn rpc(sequencer: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    })
    .to_string();
    let output = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "60",
            "-X",
            "POST",
            sequencer,
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &body,
        ])
        .output()
        .expect("curl must be installed for testnet tests");
    assert!(
        output.status.success(),
        "curl {method}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("well-formed JSON-RPC reply");
    assert!(
        doc.get("error").is_none(),
        "rpc {method} error: {}",
        doc["error"]
    );
    doc.get("result").cloned().expect("JSON-RPC result")
}

/// An account's actor states as `(program, data)` — empty when the account is
/// absent (`getAccount` answers `null`). An existing one answers
/// `{"nonce", "data": {"actor_states": {"<base58 program>": [bytes…]}}}`: an
/// account's data is kept per program, and the native balance is the native
/// token program's (`[0; 32]`).
fn get_actor_states(sequencer: &str, id: &[u8; 32]) -> Vec<([u8; 32], Vec<u8>)> {
    let result = rpc(sequencer, "getAccount", serde_json::json!([b58_encode(id)]));
    if result.is_null() {
        return Vec::new();
    }
    let states = result["data"]["actor_states"]
        .as_object()
        .expect("an existing account carries data.actor_states");
    states
        .iter()
        .map(|(program, bytes)| {
            let data: Vec<u8> = bytes
                .as_array()
                .expect("actor state byte array")
                .iter()
                .map(|v| v.as_u64().expect("byte") as u8)
                .collect();
            (b58_decode32(program), data)
        })
        .collect()
}

/// One program's state on an account; `None` when absent or empty (the
/// module's FetchOutcome::Absent).
fn get_shard(sequencer: &str, id: &[u8; 32], program: &[u8; 32]) -> Option<Vec<u8>> {
    get_actor_states(sequencer, id)
        .into_iter()
        .find(|(p, data)| p == program && !data.is_empty())
        .map(|(_, data)| data)
}

/// The config state and the program that owns it — the registration program,
/// whose id is the deployer's header account, discoverable only as the key of
/// the config's one program state.
fn fetch_config(dep: &Deployment) -> (Vec<u8>, [u8; 32]) {
    let mut program_shards: Vec<_> = get_actor_states(&dep.sequencer, &dep.config_account)
        .into_iter()
        .filter(|(p, data)| *p != [0u8; 32] && !data.is_empty())
        .collect();
    assert_eq!(program_shards.len(), 1, "the config holds exactly one program's state");
    let (program, data) = program_shards.remove(0);
    (data, program)
}

fn merkle_program(config_data: &[u8]) -> [u8; 32] {
    native::config_field_32(config_data, native::CONFIG_OFFSET_MERKLE_PROGRAM_ID)
}

fn fetch_tree(dep: &Deployment, config_data: &[u8], registration: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let main = native::tree_main_account_id(config_data, registration).unwrap();
    let data = get_shard(&dep.sequencer, &main, &merkle_program(config_data))
        .expect("derived tree-main PDA must hold the merkle program's shard");
    (main, data)
}

/// Chain time the way the module reads it: the head block's timestamp.
fn chain_now_ms(dep: &Deployment) -> u64 {
    crate::fee_state::fetch_head_timestamp(&dep.sequencer)
        .unwrap_or_else(|e| panic!("head block timestamp from {}: {e}", dep.sequencer))
}

// --------------------------------------------------------------------- tests

// The DEPLOYED ConfigState must decode through this module's offset readers:
// identity fields match the deployment record and the policy fields carry
// registration-viable values. Layout drift against the pinned guest image
// fails here first.
#[test]
fn testnet_config_account_matches_deployment_and_bounds_decode() {
    let Some(dep) = testnet() else { return };
    let (data, owner) = fetch_config(&dep);

    // Exact, not a floor: a config of another length belongs to a different
    // program generation, and every offset read below would decode it into
    // plausible nonsense rather than failing.
    assert_eq!(
        data.len(),
        native::CONFIG_STATE_SIZE,
        "config size {} is not this layout",
        data.len()
    );
    assert_eq!(
        bytes_to_hex(&owner),
        dep.registration_program_id_hex,
        "the config's shard is the registration program's"
    );
    assert_eq!(bytes_to_hex(&merkle_program(&data)), dep.merkle_program_id_hex);
    assert_eq!(
        bytes_to_hex(&native::config_field_32(&data, native::CONFIG_OFFSET_TREE_ID)),
        dep.tree_id_hex
    );

    let max_total = native::config_field_u64(&data, native::CONFIG_OFFSET_MAX_TOTAL_RATE_LIMIT);
    let current = native::config_field_u64(&data, native::CONFIG_OFFSET_CURRENT_TOTAL_RATE_LIMIT);
    let price = native::config_field_u128(&data, native::CONFIG_OFFSET_PRICE_PER_UNIT);
    let registrations = native::config_field_u64(&data, native::CONFIG_OFFSET_TOTAL_REGISTRATIONS);
    let active = native::config_field_u32(&data, native::CONFIG_OFFSET_ACTIVE_DURATION);
    let grace = native::config_field_u32(&data, native::CONFIG_OFFSET_GRACE_DURATION);
    let min_rate = native::config_field_u64(&data, native::CONFIG_OFFSET_MIN_RATE_LIMIT);
    let max_rate = native::config_field_u64(&data, native::CONFIG_OFFSET_MAX_RATE_LIMIT);
    assert!(0 < min_rate && min_rate <= max_rate, "registry bounds {min_rate}..={max_rate}");
    assert!(max_total >= min_rate, "capacity fits at least one member");
    assert!(current <= max_total, "used {current} within capacity {max_total}");
    assert!(price > 0, "priced registration");
    assert!(active > 0 && grace > 0, "nonzero lifecycle durations");
    eprintln!(
        "live config: {registrations} registrations, rate {current}/{max_total}, \
         price {price}, active {active}, grace {grace}"
    );
}

// The full account-derivation loop against the DEPLOYED program: the tree
// main PDA derived from (registration program, tree_id) must hold the merkle
// program's shard, and register_plan must re-derive the very config account
// the deployment record names (proving PDA seeds + hashing match the chain).
#[test]
fn testnet_register_plan_derives_the_deployed_accounts() {
    let Some(dep) = testnet() else { return };
    let (config_data, owner) = fetch_config(&dep);
    let (main, tree_main_data) = fetch_tree(&dep, &config_data, &owner);

    let plan =
        native::register_plan(&config_data, &tree_main_data, &owner, &[0x11; 32]).unwrap();
    assert_eq!(
        plan.config_account_id, dep.config_account,
        "config PDA re-derivation must round-trip to the deployed account"
    );
    assert_eq!(plan.tree_main_account_id, main);
    assert_eq!(bytes_to_hex(&plan.merkle_program_id), dep.merkle_program_id_hex);
    assert!(
        plan.next_leaf_index < (1u64 << rln_layouts::TREE_DEPTH),
        "leaf index inside TREE_DEPTH"
    );
    eprintln!("live tree: next_leaf_index {}", plan.next_leaf_index);
}

// The head block's timestamp (the module's ONLY time source for lifecycle
// state) must decode and sit near wall time. Chain time is epoch MILLISECONDS;
// a week of slack tolerates a stalled sequencer while still failing loudly on
// a unit change (seconds would be ~1000x off).
#[test]
fn testnet_head_block_timestamp_is_live_chain_time() {
    let Some(dep) = testnet() else { return };
    let chain_ms = chain_now_ms(&dep);
    let wall_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let drift = wall_ms.abs_diff(chain_ms);
    assert!(
        drift < 7 * 24 * 3600 * 1000,
        "chain clock {chain_ms} vs wall {wall_ms}: unit change or dead sequencer"
    );
    eprintln!("live clock: {chain_ms} (drift {}s)", drift / 1000);
}

#[test]
fn testnet_valid_roots_come_from_the_live_tree() {
    let Some(dep) = testnet() else { return };
    let (config_data, owner) = fetch_config(&dep);
    let (_, tree_main_data) = fetch_tree(&dep, &config_data, &owner);

    let roots = native::get_valid_roots(&tree_main_data).unwrap();
    assert!(!roots.is_empty());
    assert!(roots.len() <= 1 + rln_layouts::ROOT_HISTORY_SIZE);
    assert_ne!(roots[0], [0u8; 32], "current root");
    eprintln!("live roots: {} in window, current {}", roots.len(), bytes_to_hex(&roots[0]));
}

// Full cryptographic round-trip against DEPLOYED tree data: build a proof
// for a live leaf from the fetched merkle shard, then recompute the root from
// (leaf, path) with poseidon and demand it equals both the proof's root and a
// member of the live valid-root window. Works on an empty tree too (leaf 0
// against cached defaults).
#[test]
fn testnet_merkle_proof_recomputes_the_live_root() {
    let Some(dep) = testnet() else { return };
    let (config_data, owner) = fetch_config(&dep);
    let (_, tree_main_data) = fetch_tree(&dep, &config_data, &owner);

    let next = rln_layouts::TreeMainLayout::parse(&tree_main_data).next_index();
    let leaf_index = next.saturating_sub(1);
    let proofs = native::merkle_proofs_exec(&tree_main_data, &[leaf_index]).unwrap();
    assert_eq!(proofs.len(), 1);
    let proof = &proofs[0];
    assert_eq!(proof.leaf_index, leaf_index);
    assert_eq!(proof.depth as usize, proof.path_elements.len());
    assert_eq!(proof.path_elements.len(), proof.path_indices.len());

    let fr_of = |hex: &str| {
        let bytes = hex_to_bytes32(hex).expect("32-byte node hex");
        bytes_le_to_fr(&bytes).expect("field element")
    };
    let mut node = fr_of(&proof.leaf);
    for (sibling_hex, &is_right) in proof.path_elements.iter().zip(&proof.path_indices) {
        let sibling = fr_of(sibling_hex);
        node = if is_right == 1 {
            Hasher::<PoseidonHash>::hash_pair(sibling, node)
        } else {
            Hasher::<PoseidonHash>::hash_pair(node, sibling)
        };
    }
    let recomputed = bytes_to_hex(&fr_to_bytes_le(&node));
    assert_eq!(recomputed, proof.root, "path must hash back to the tree root");

    let roots = native::get_valid_roots(&tree_main_data).unwrap();
    assert!(
        roots.iter().any(|r| bytes_to_hex(r) == proof.root),
        "proof root inside the live valid-root window"
    );
    eprintln!("live proof: leaf {leaf_index} recomputes root {recomputed}");
}

// Membership PDA read for a well-known throwaway identity. Normally absent
// — pinning that never-registered reads as empty (the same signal as
// erased/slashed, which is why the spec's Unknown state exists). If some
// run of the write path ever registers it, the record must decode and its
// lifecycle state must derive against LIVE chain time.
#[test]
fn testnet_membership_read_absent_or_decodes_with_live_state() {
    let Some(dep) = testnet() else { return };
    let (config_data, owner) = fetch_config(&dep);
    let (_, tree_main_data) = fetch_tree(&dep, &config_data, &owner);

    let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(&[0x5A; 32]);
    let id_commitment = fr_to_bytes_le(&identity_keys.id_commitment());
    let plan =
        native::register_plan(&config_data, &tree_main_data, &owner, &id_commitment).unwrap();

    match get_shard(&dep.sequencer, &plan.membership_account_id, &owner) {
        None => eprintln!(
            "live membership: {} absent (never registered / erased)",
            bytes_to_hex(&plan.membership_account_id)
        ),
        Some(data) => {
            let membership = native::decode_membership(&data).unwrap();
            assert_eq!(membership.id_commitment, id_commitment);
            let cfg = &config_data;
            assert!(membership.rate_limit >= native::config_field_u64(cfg, native::CONFIG_OFFSET_MIN_RATE_LIMIT));
            assert!(membership.rate_limit <= native::config_field_u64(cfg, native::CONFIG_OFFSET_MAX_RATE_LIMIT));
            let state = native::membership_status(
                membership.grace_period_start_timestamp_ms,
                membership.grace_period_duration_sec,
                chain_now_ms(&dep),
            );
            let leaf = native::registration_leaf(&membership.id_commitment, membership.rate_limit)
                .and_then(|leaf| native::find_leaf_index(&tree_main_data, &leaf));
            eprintln!(
                "live membership: leaf {leaf:?} rate {} state {state}",
                membership.rate_limit
            );
        }
    }
}

/// get_fee_state's own transport (not curl) against a live sequencer: the
/// testnet from the built-in table, or `LEZ_RLN_TESTNET_FEE_SEQUENCER`. Needs no
/// deployment record, so it gates on LEZ_RLN_TESTNET_TESTS alone.
#[test]
fn testnet_fee_state_is_a_live_quote() {
    if std::env::var("LEZ_RLN_TESTNET_TESTS").ok().as_deref() != Some("1") {
        eprintln!("testnet test skipped: set LEZ_RLN_TESTNET_TESTS=1 to run against the live registry");
        return;
    }
    let sequencer = std::env::var("LEZ_RLN_TESTNET_FEE_SEQUENCER").unwrap_or_else(|_| {
        crate::networks::network("testnet").expect("testnet is in the table").sequencer.clone()
    });
    let raw = crate::fee_state::fetch(&sequencer)
        .unwrap_or_else(|e| panic!("getFeeState against {sequencer}: {e}"));
    let quote: serde_json::Value = serde_json::from_str(&raw).expect("the quote is JSON");
    let field = |key: &str| {
        quote.get(key).and_then(|v| v.as_u64()).unwrap_or_else(|| panic!("{key} missing: {raw}"))
    };
    assert!(field("next_base_fee_exec_ceiling") >= field("next_base_fee_exec_floor"));
    assert!(field("next_base_fee_stor_ceiling") >= field("next_base_fee_stor_floor"));
    assert!(field("height") > 0, "{raw}");
    eprintln!("{sequencer}: {raw}");
}

// Offline self-checks for the helpers this file leans on (always run).
#[test]
fn base58_roundtrip_matches_known_vector() {
    let id: [u8; 32] = core::array::from_fn(|i| i as u8 * 7);
    let encoded = b58_encode(&id);
    assert_eq!(b58_decode32(&encoded), id);
    // A fixed vector, not a live account: it pins the base58 alphabet and
    // the leading-zero handling, and belongs to no deployment record.
    assert_eq!(
        bytes_to_hex(&b58_decode32("Ds9aBzioxnDf6yfUnCHGS7evBnpMnknyJgiMEJcV7uVG")),
        "bf24f9e9f0440d7c7268cfc5ce6edb981feda003104c9d96ca276443ccc0a607"
    );
    let leading_zero = {
        let mut id = [0u8; 32];
        id[31] = 7;
        id
    };
    assert_eq!(b58_decode32(&b58_encode(&leading_zero)), leading_zero);
}
