//! The leaf index each registration this module sent claimed, per membership
//! account, persisted in `leaf_claims.json` beside `payer.json`.
//!
//! The chain numbers registrations (the config's `next_leaf_index`, which
//! `Register` claims and the program refuses as `StaleLeafIndex` when a
//! registration landed first) but no account records a member's index. The
//! sender is the one party that knows it: the watcher re-sends a reverted
//! registration only once it is in a block, so at most one send per
//! membership is ever in flight, and when the membership appears the latest
//! claim is its leaf. `get_membership` answers it from here, which is how the
//! membership module learns the index the zone service is asked about.
//!
//! A membership registered by another sender (or before this file existed)
//! has no entry, and `get_membership` answers no `leaf_index` for it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::wallet;

const CLAIMS_FILE: &str = "leaf_claims.json";

/// Serializes read-modify-write of the file; the map itself is re-read each
/// time, so the file stays the one source of truth.
static FILE_LOCK: Mutex<()> = Mutex::new(());

fn claims_file() -> Option<PathBuf> {
    wallet::persistence_file(CLAIMS_FILE)
}

fn read(path: &PathBuf) -> BTreeMap<String, u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Remember that the registration of `membership_hex` just sent claims
/// `leaf_index`, replacing any earlier claim for it.
pub(crate) fn record(membership_hex: &str, leaf_index: u64) {
    let Some(path) = claims_file() else {
        eprintln!("lez-rln: no persistence dir; leaf {leaf_index} of {membership_hex} is not recorded");
        return;
    };
    let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut claims = read(&path);
    claims.insert(membership_hex.to_ascii_lowercase(), leaf_index);
    let body = serde_json::to_string(&claims).expect("a map of u64 serializes");
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, body).and_then(|()| std::fs::rename(&tmp, &path)) {
        eprintln!("lez-rln: write {}: {e}", path.display());
    }
}

/// The latest claim sent for `membership_hex`, if this module sent one.
pub(crate) fn lookup(membership_hex: &str) -> Option<u64> {
    let path = claims_file()?;
    let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    read(&path).get(&membership_hex.to_ascii_lowercase()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latest_claim_wins_and_survives_a_reread() {
        let dir = std::env::temp_dir().join(format!("lez-rln-claims-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        wallet::set_persistence_for_test(dir.to_str().unwrap());
        let m = "AB".repeat(32);
        assert_eq!(lookup(&m), None);
        record(&m, 4);
        record(&m, 5);
        record(&"cd".repeat(32), 0);
        assert_eq!(lookup(&m.to_ascii_lowercase()), Some(5), "a re-send's claim replaces the first");
        assert_eq!(lookup(&"cd".repeat(32)), Some(0), "leaf 0 is a leaf");
        wallet::set_persistence_for_test("");
        assert_eq!(lookup(&m), None, "no persistence dir, no claims");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
