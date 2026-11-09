//! The tree source: Merkle proofs and valid roots of a registry's tree, the
//! typed shapes they decode to, and their lift to the circuit's depth.

use serde_json::Value;

use crate::error::{ApiError, ErrorKind};
use crate::proof::{depth_bridge, RLN_TREE_DEPTH};
use crate::registry_id::{bytes_to_hex, hex_to_bytes32, CanonicalRegistryId};

/// One leaf's Merkle proof at the registry's own depth (`path_elements.len()`).
pub(crate) struct MerkleProof {
    pub leaf_index: u64,
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    /// 1..=RLN_TREE_DEPTH elements, leaf level first.
    pub path_elements: Vec<[u8; 32]>,
    /// Same length as `path_elements`, each 0 or 1.
    pub path_indices: Vec<u8>,
    /// Some only from a source that reads proof and roots from one snapshot.
    pub valid_roots: Option<Vec<[u8; 32]>>,
}

/// A registry's valid-root window at the registry's own depth.
pub(crate) struct RootSet {
    pub depth: usize,
    pub roots: Vec<[u8; 32]>,
}

/// A proof lifted to the circuit's depth: what `generate_proof` proves with
/// and what the root window holds.
pub(crate) struct Witness {
    pub path_elements_hex: Vec<String>,
    pub path_indices: Vec<u8>,
    pub root: [u8; 32],
    pub window: Option<Vec<[u8; 32]>>,
}

pub(crate) trait TreeSource: Send + Sync {
    fn merkle_proof(
        &self,
        registry: &CanonicalRegistryId,
        leaf_index: u64,
    ) -> Result<MerkleProof, ApiError>;

    fn valid_roots(&self, registry: &CanonicalRegistryId) -> Result<RootSet, ApiError>;
}

fn fault(what: impl Into<String>) -> ApiError {
    ApiError::new(ErrorKind::ProviderFailure, what)
}

fn hex32(v: Option<&Value>, what: &str) -> Result<[u8; 32], ApiError> {
    v.and_then(Value::as_str)
        .and_then(hex_to_bytes32)
        .ok_or_else(|| fault(format!("{what} is not 32-byte hex")))
}

fn hex32_array(v: Option<&Value>, what: &str) -> Result<Vec<[u8; 32]>, ApiError> {
    v.and_then(Value::as_array)
        .ok_or_else(|| fault(format!("{what} is not an array")))?
        .iter()
        .map(|e| hex32(Some(e), what))
        .collect()
}

fn lift_root(root: &[u8; 32], depth: usize) -> [u8; 32] {
    let folded = depth_bridge::fold_root(&bytes_to_hex(root), depth);
    hex_to_bytes32(&folded).unwrap_or(*root)
}

impl MerkleProof {
    pub(crate) fn from_provider_json(v: &Value) -> Result<Self, ApiError> {
        let o = v
            .as_object()
            .ok_or_else(|| fault("merkle proof reply is not an object"))?;
        let path_elements = hex32_array(o.get("path_elements"), "merkle proof path_elements")?;
        let depth = path_elements.len();
        if depth == 0 || depth > RLN_TREE_DEPTH {
            return Err(fault(format!(
                "merkle proof has an impossible depth {depth}"
            )));
        }
        let path_indices: Vec<u8> = o
            .get("path_indices")
            .and_then(Value::as_array)
            .ok_or_else(|| fault("merkle proof path_indices is not an array"))?
            .iter()
            .map(|i| match i.as_u64() {
                Some(b @ (0 | 1)) => Ok(b as u8),
                _ => Err(fault(
                    "merkle proof path_indices holds a value other than 0 or 1",
                )),
            })
            .collect::<Result<_, _>>()?;
        if path_indices.len() != depth {
            return Err(fault(
                "merkle proof path_indices and path_elements differ in length",
            ));
        }
        if let Some(declared) = o.get("depth") {
            if declared.as_u64() != Some(depth as u64) {
                return Err(fault(format!(
                    "merkle proof declares depth {declared} over a {depth}-element path"
                )));
            }
        }
        let leaf_index = o
            .get("leaf_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| fault("merkle proof has no leaf_index"))?;
        let valid_roots = match o.get("valid_roots") {
            None => None,
            Some(r) => Some(hex32_array(Some(r), "merkle proof valid_roots")?),
        };
        Ok(MerkleProof {
            leaf_index,
            leaf: hex32(o.get("leaf"), "merkle proof leaf")?,
            root: hex32(o.get("root"), "merkle proof root")?,
            path_elements,
            path_indices,
            valid_roots,
        })
    }

    /// The wire `get_merkle_proof` object: the lidl's keys in alphabetical
    /// order, `valid_roots` only when the source gave one.
    pub(crate) fn to_wire(&self) -> Value {
        let hexes =
            |v: &[[u8; 32]]| Value::from(v.iter().map(|e| bytes_to_hex(e)).collect::<Vec<_>>());
        let mut o = serde_json::Map::new();
        o.insert("depth".into(), Value::from(self.path_elements.len()));
        o.insert("leaf".into(), Value::from(bytes_to_hex(&self.leaf)));
        o.insert("leaf_index".into(), Value::from(self.leaf_index));
        o.insert("path_elements".into(), hexes(&self.path_elements));
        o.insert("path_indices".into(), Value::from(&self.path_indices[..]));
        o.insert("root".into(), Value::from(bytes_to_hex(&self.root)));
        if let Some(roots) = &self.valid_roots {
            o.insert("valid_roots".into(), hexes(roots));
        }
        Value::Object(o)
    }

    /// Path, root and window lifted together to the circuit's depth.
    pub(crate) fn lifted(&self) -> Witness {
        let depth = self.path_elements.len();
        let mut path_elements_hex: Vec<String> =
            self.path_elements.iter().map(|e| bytes_to_hex(e)).collect();
        // OWNERSHIP: the Witness owns a padded copy; the proof stays readable.
        let mut path_indices = self.path_indices.clone();
        depth_bridge::pad_path(&mut path_elements_hex, &mut path_indices, depth);
        Witness {
            path_elements_hex,
            path_indices,
            root: lift_root(&self.root, depth),
            window: self
                .valid_roots
                .as_ref()
                .map(|roots| roots.iter().map(|r| lift_root(r, depth)).collect()),
        }
    }
}

impl RootSet {
    /// A `{"depth":N,"valid_roots":[…]}` reply; any other shape is a
    /// `ProviderFailure`.
    pub(crate) fn from_provider_json(v: &Value) -> Result<Self, ApiError> {
        let o = v
            .as_object()
            .ok_or_else(|| fault("roots reply is not an object"))?;
        let depth = o
            .get("depth")
            .and_then(Value::as_u64)
            .ok_or_else(|| fault("roots reply has no depth"))? as usize;
        if depth == 0 || depth > RLN_TREE_DEPTH {
            return Err(fault(format!(
                "roots reply declares an impossible depth {depth}"
            )));
        }
        let roots = hex32_array(o.get("valid_roots"), "roots reply valid_roots")?;
        Ok(RootSet { depth, roots })
    }

    /// The roots at the circuit's depth, the shape `generate_proof` lifts
    /// its own root to and `validate_proof` compares against.
    pub(crate) fn lifted(&self) -> Vec<[u8; 32]> {
        self.roots
            .iter()
            .map(|r| lift_root(r, self.depth))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A lez 6.x `get_merkle_proofs` element: `ProofJson` plus the snapshot's
    /// `valid_roots`, as the lez module serializes it.
    fn lez_proof_fixture() -> String {
        format!(
            r#"{{"depth":2,"leaf":"{}","leaf_index":5,"path_elements":["{}","{}"],"path_indices":[1,0],"root":"{}","valid_roots":["{}"]}}"#,
            "aa".repeat(32),
            "cc".repeat(32),
            "dd".repeat(32),
            "bb".repeat(32),
            "ee".repeat(32),
        )
    }

    #[test]
    fn a_lez_proof_round_trips_to_the_same_wire_bytes() {
        let raw = lez_proof_fixture();
        let v: Value = serde_json::from_str(&raw).unwrap();
        let proof = MerkleProof::from_provider_json(&v).expect("lez proof decodes");
        assert_eq!(proof.to_wire().to_string(), raw);
    }

    #[test]
    fn a_proof_without_valid_roots_has_no_window_and_no_wire_key() {
        let mut v: Value = serde_json::from_str(&lez_proof_fixture()).unwrap();
        v.as_object_mut().unwrap().remove("valid_roots");
        let proof = MerkleProof::from_provider_json(&v).expect("zone-shaped proof decodes");
        assert!(proof.valid_roots.is_none());
        assert!(proof.lifted().window.is_none());
        assert_eq!(proof.to_wire(), v);
    }

    #[test]
    fn a_malformed_merkle_proof_is_a_provider_failure() {
        let e = "ab".repeat(32);
        let r = "cd".repeat(32);
        let ok = MerkleProof::from_provider_json(&json!({
            "path_elements": [e], "path_indices": [1], "depth": 1,
            "leaf": r, "root": r, "leaf_index": 0
        }))
        .expect("a well-formed reply decodes");
        assert_eq!(ok.path_indices, vec![1]);
        assert!(ok.valid_roots.is_none());

        for bad in [
            json!({ "path_elements": [e], "path_indices": [256], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [2], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e, 7], "path_indices": [1, 0], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": ["ab"], "path_indices": [1], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [1, 0], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [1], "depth": 2, "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [], "path_indices": [], "leaf": r, "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [1], "root": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [1], "leaf": r, "leaf_index": 0 }),
            json!({ "path_elements": [e], "path_indices": [1], "leaf": r, "root": r }),
            json!({ "path_elements": [e], "path_indices": [1], "leaf": r, "root": r, "leaf_index": 0, "valid_roots": ["ab"] }),
        ] {
            let err = MerkleProof::from_provider_json(&bad)
                .err()
                .unwrap_or_else(|| panic!("accepted {bad}"));
            assert_eq!(err.kind, ErrorKind::ProviderFailure);
        }
    }

    #[test]
    fn a_shallow_proof_lifts_path_root_and_window_together() {
        let v: Value = serde_json::from_str(&lez_proof_fixture()).unwrap();
        let proof = MerkleProof::from_provider_json(&v).unwrap();
        let w = proof.lifted();
        assert_eq!(w.path_elements_hex.len(), RLN_TREE_DEPTH);
        assert_eq!(w.path_indices.len(), RLN_TREE_DEPTH);
        let folded = |h: &str| hex_to_bytes32(&depth_bridge::fold_root(h, 2)).unwrap();
        assert_eq!(w.root, folded(&"bb".repeat(32)));
        assert_eq!(w.window, Some(vec![folded(&"ee".repeat(32))]));
    }

    /// A registry shallower than the circuit must come back LIFTED.
    ///
    /// `generate_proof` lifts its root to the circuit's depth and
    /// `validate_proof` compares against the valid-root window, so the window
    /// must hold lifted roots too, or every proof is invalid.
    #[test]
    fn a_shallow_registry_reports_roots_at_circuit_depth() {
        let root = "11".repeat(32);
        let reply = json!({ "depth": 9, "valid_roots": [root.clone()] });
        let lifted = RootSet::from_provider_json(&reply)
            .expect("depth-9 reply")
            .lifted();
        assert_eq!(lifted.len(), 1);
        let lifted_hex = bytes_to_hex(&lifted[0]);
        assert_ne!(
            lifted_hex, root,
            "a depth-9 root must not pass through unlifted"
        );
        assert_eq!(
            lifted_hex,
            depth_bridge::fold_root(&root, 9),
            "the window must hold exactly what generate_proof folds to"
        );
    }

    /// A registry already at the circuit's depth needs no lift, and must not
    /// get one — folding it again would invent a root nothing can prove.
    #[test]
    fn a_full_depth_registry_passes_through() {
        let root = "22".repeat(32);
        let reply = json!({ "depth": RLN_TREE_DEPTH, "valid_roots": [root.clone()] });
        let lifted = RootSet::from_provider_json(&reply)
            .expect("full-depth reply")
            .lifted();
        assert_eq!(
            lifted.iter().map(|r| bytes_to_hex(r)).collect::<Vec<_>>(),
            vec![root]
        );
    }

    #[test]
    fn a_reply_with_no_depth_or_an_absurd_one_is_refused() {
        let root = "44".repeat(32);
        for bad in [
            json!({ "valid_roots": [root.clone()] }),
            json!({ "depth": 0, "valid_roots": [root.clone()] }),
            json!({ "depth": 99, "valid_roots": [root.clone()] }),
            json!({ "depth": 9, "valid_roots": ["not hex"] }),
            json!({ "depth": 9 }),
            json!("not a reply"),
            json!([root.clone()]),
        ] {
            let err = RootSet::from_provider_json(&bad)
                .err()
                .unwrap_or_else(|| panic!("accepted {bad}"));
            assert_eq!(err.kind, ErrorKind::ProviderFailure);
        }
    }
}
