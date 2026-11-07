//! Scope resolution: registry and rln_identifier parsing, which local records
//! back a scope, and the registry provider serving its namespace.

use crate::error::{ApiError, ErrorKind};
use crate::lifecycle::MembershipRecord;
use crate::provider;
use crate::registry_id;
use crate::sealed_store::store::Store;

/// Parse a 32-byte LE hex field, returning the bytes and their normalized
/// lowercase re-encoding. Invalid → InvalidArgument.
pub(crate) fn parse_hex32(field: &str, hex: &str) -> Result<([u8; 32], String), ApiError> {
    let bytes = registry_id::hex_to_bytes32(hex).ok_or_else(|| {
        ApiError::new(ErrorKind::InvalidArgument, &format!("{field} must be 32-byte hex"))
    })?;
    let hex = registry_id::bytes_to_hex(&bytes);
    Ok((bytes, hex))
}

pub(crate) fn parse_registry(raw: &str) -> Result<registry_id::CanonicalRegistryId, ApiError> {
    registry_id::parse(raw).map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &e))
}

/// The registry's local membership records.
pub(crate) fn records_for_registry(
    store: &Store,
    registry: &registry_id::CanonicalRegistryId,
) -> Vec<MembershipRecord> {
    store.records_for(&registry.canonical)
}

/// Canonicalize the registry_id and parse/normalize the 32-byte
/// rln_identifier. Every call passes its scope explicitly (spec: the
/// Module holds no default); empty args fail invalid_argument.
pub(crate) fn parse_scope(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<(registry_id::CanonicalRegistryId, [u8; 32], String), ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let (bytes, hex) = parse_hex32("rln_identifier", rln_identifier_hex)?;
    Ok((registry, bytes, hex))
}

/// Whether a record backs a scope: registered under the same rln_identifier,
/// or carrying none: a record with no rln_identifier (registry-wide, as
/// `start()` provisions) backs every application on its registry.
pub(crate) fn scope_matches(record: &MembershipRecord, rln_id_hex: &str) -> bool {
    record.identity.rln_identifier == rln_id_hex || record.identity.rln_identifier.is_empty()
}

/// `scope_matches`'s predicate over raw identifiers, for tests that need to
/// contrast it with a check that ignores scope entirely.
#[cfg(test)]
pub(crate) fn scope_matches_for_test(record_rln_id: &str, scope_rln_id: &str) -> bool {
    record_rln_id == scope_rln_id || record_rln_id.is_empty()
}

/// The registry records backing a scope (spec: a membership "MAY back any
/// application whose scope names its registry"), by the same rank the state
/// read uses: the scope's OWN usable records shadow everything else; with
/// none, the registry-wide ones (no rln_identifier); with none of those,
/// every record backs it. A scope whose own membership is active beside a
/// start()-provisioned registry-wide one proves with its own — the state
/// read answers that record, and so must the proof.
pub(crate) fn scope_candidates(
    records: &[MembershipRecord],
    rln_id_hex: &str,
) -> Vec<MembershipRecord> {
    let usable = |r: &&MembershipRecord| !r.quarantined && r.cache.state.is_usable();
    let own: Vec<MembershipRecord> =
        records.iter().filter(usable).filter(|r| r.identity.rln_identifier == rln_id_hex).cloned().collect();
    if !own.is_empty() {
        return own;
    }
    let wide: Vec<MembershipRecord> =
        records.iter().filter(usable).filter(|r| r.identity.rln_identifier.is_empty()).cloned().collect();
    if !wide.is_empty() {
        return wide;
    }
    records.to_vec()
}

/// Which record answers a `get_membership_state(scope)` read.
pub(crate) enum ScopeState {
    One(MembershipRecord),
    Ambiguous(&'static str),
    None,
}

/// Resolve a scope's state by rank over the registry's non-quarantined
/// records: the scope's OWN records first (its one live record; with none
/// live, the latest terminal one — a refused registration reads back as
/// `failed` by its scope, never as the registry's other membership), then
/// the registry-wide records (no rln_identifier, as
/// `start()` provisions them) by the same rule, then any usable membership
/// on the registry (spec: a membership "MAY back any application whose
/// scope names its registry"). More than one live record at the winning
/// rank is ambiguous. Proof-time resolution stays `scope_candidates`'s
/// (usable records only).
pub(crate) fn resolve_scope_state(records: &[MembershipRecord], rln_id_hex: &str) -> ScopeState {
    let own: Vec<&MembershipRecord> = records
        .iter()
        .filter(|r| !r.quarantined && r.identity.rln_identifier == rln_id_hex)
        .collect();
    let wide: Vec<&MembershipRecord> = records
        .iter()
        .filter(|r| !r.quarantined && r.identity.rln_identifier.is_empty())
        .collect();
    for rank in [own, wide] {
        if rank.is_empty() {
            continue;
        }
        let live: Vec<&&MembershipRecord> = rank.iter().filter(|r| r.cache.state.is_live()).collect();
        return match live.len() {
            1 => ScopeState::One((*live[0]).clone()),
            0 => {
                let latest = rank.iter().max_by_key(|r| r.identity.submitted_at).expect("non-empty rank");
                ScopeState::One((*latest).clone())
            }
            _ => ScopeState::Ambiguous(
                "multiple live memberships registered under this scope; use get_memberships / select_membership",
            ),
        };
    }
    let usable: Vec<&MembershipRecord> =
        records.iter().filter(|r| !r.quarantined && r.cache.state.is_usable()).collect();
    match usable.len() {
        0 => ScopeState::None,
        1 => ScopeState::One(usable[0].clone()),
        _ => ScopeState::Ambiguous(
            "multiple memberships back this scope; use get_memberships / select_membership",
        ),
    }
}

/// The registry provider serving the registry's namespace; none is
/// `unknown_registry`.
pub(crate) fn backend_of(
    registry: &registry_id::CanonicalRegistryId,
) -> Result<&'static dyn provider::RegistryProvider, ApiError> {
    provider::provider_for(&registry.namespace).ok_or_else(|| {
        ApiError::new(
            ErrorKind::UnknownRegistry,
            &format!("no registry provider for namespace {}", registry.namespace),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::MembershipState;
    use crate::test_support::{imp_with_store, seed_membership, TEST_GLOBAL_LOCK};

    // A scope's state is its own record's, whatever else the registry holds:
    // a pending or failed scoped registration beside the registry's active
    // membership is NOT ambiguous. Only with no record of its own does a
    // scope fall back to the registry-wide one, then to any usable one.
    #[test]
    fn membership_state_resolves_its_record_by_scope_rank() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-scope-rank-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "5c".repeat(32));
        let (r1, r2, r3) = ("a1".repeat(32), "a2".repeat(32), "a3".repeat(32));
        let state_of = |scope: &str| match resolve_scope_state(&store.records_for(&registry), scope) {
            ScopeState::One(r) => Ok(r.hash.clone()),
            ScopeState::Ambiguous(why) => Err(why.to_string()),
            ScopeState::None => Ok(String::new()),
        };

        // Nothing: unknown. One active R1: it backs every scope.
        assert_eq!(state_of(&r2).unwrap(), "");
        seed_membership(&store, "h1", &registry, &"11".repeat(32), &r1, &"f1".repeat(32), MembershipState::Active, 1, 100);
        assert_eq!(state_of(&r1).unwrap(), "h1");
        assert_eq!(state_of(&r2).unwrap(), "h1", "a lone membership backs any application");

        // A pending R2 beside it: R2's own record answers, R1's still answers R1.
        seed_membership(&store, "h2", &registry, &"22".repeat(32), &r2, &"f2".repeat(32), MembershipState::Pending, 0, 100);
        assert_eq!(state_of(&r2).unwrap(), "h2");
        assert_eq!(state_of(&r1).unwrap(), "h1");
        // A third scope with no record of its own: two usable? No — one usable
        // (h1) and one pending, so h1 backs it.
        assert_eq!(state_of(&r3).unwrap(), "h1");

        // R2 refused by the gifter: its scope reads back the failed record.
        store.update_cache("h2", |m| {
            m.state = MembershipState::Failed;
            m.failed_reason = Some("gifter_failed: credential already used".into());
        }).unwrap();
        assert_eq!(state_of(&r2).unwrap(), "h2", "a failed scoped registration is the scope's answer");
        assert_eq!(state_of(&r1).unwrap(), "h1");

        // A second live R2 record: ambiguous within the rank.
        seed_membership(&store, "h2b", &registry, &"23".repeat(32), &r2, &"f3".repeat(32), MembershipState::Active, 2, 100);
        assert_eq!(state_of(&r2).unwrap(), "h2b", "the live record beats the failed one");
        seed_membership(&store, "h2c", &registry, &"24".repeat(32), &r2, &"f4".repeat(32), MembershipState::Pending, 0, 100);
        assert!(state_of(&r2).unwrap_err().contains("registered under this scope"));
        // R3 has no record: two usable memberships back it — ambiguous.
        assert!(state_of(&r3).unwrap_err().contains("multiple memberships back this scope"));

        // A registry-wide record outranks the any-usable fallback for R3.
        seed_membership(&store, "hw", &registry, &"33".repeat(32), "", &"f5".repeat(32), MembershipState::Active, 3, 100);
        assert_eq!(state_of(&r3).unwrap(), "hw");
        assert_eq!(state_of(&r1).unwrap(), "h1", "an own record still wins over the registry-wide one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Proof-time selection ranks like the state read: an own usable record
    // shadows the registry-wide one, the registry-wide one shadows other
    // scopes', and with neither every record backs the scope.
    #[test]
    fn proof_candidates_rank_own_then_registry_wide_then_any() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-candidates-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "7b".repeat(32));
        let scope = "c1".repeat(32);
        seed_membership(&store, "own", &registry, &"51".repeat(32), &scope, &"e1".repeat(32), MembershipState::Active, 1, 100);
        seed_membership(&store, "wide", &registry, &"52".repeat(32), "", &"e2".repeat(32), MembershipState::Active, 2, 100);
        seed_membership(&store, "other", &registry, &"53".repeat(32), &"c2".repeat(32), &"e3".repeat(32), MembershipState::Active, 3, 100);
        let canonical = registry_id::parse(&registry).unwrap().canonical;
        let records = records_for_registry(&store, &registry_id::parse(&registry).unwrap());
        let names = |v: Vec<MembershipRecord>| { let mut n: Vec<String> = v.into_iter().map(|r| r.hash).collect(); n.sort(); n };
        assert_eq!(names(scope_candidates(&records, &scope)), ["own"]);
        assert_eq!(names(scope_candidates(&records, &"c3".repeat(32))), ["wide"], "no own record: the registry-wide one");
        store.update_cache("wide", |m| m.state = MembershipState::Failed).unwrap();
        let records = records_for_registry(&store, &registry_id::parse(&registry).unwrap());
        assert_eq!(names(scope_candidates(&records, &"c3".repeat(32))), ["other", "own", "wide"], "nothing of its own or wide: every record");
        let _ = canonical;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
