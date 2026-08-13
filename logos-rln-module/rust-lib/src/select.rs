//! Membership selection (spec `select()`): candidate filtering and the
//! Selector strategies, with RoundRobin state kept PER MembershipScope
//! (canonical registry_id × rln_identifier) so applications sharing a
//! registry rotate independently.
//!
//! Candidates are the registry's non-quarantined records in a usable state
//! (`active` or `grace_period`). `expired` is excluded even though the leaf
//! still proves: erasure of an expired membership is permissionless on
//! lez-rln, so it can vanish mid-use. States come from the store's
//! poller-refreshed caches (≤60s stale — the spec's accepted staleness
//! class for candidate sets).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::store::MembershipRecord;
use crate::{lock, ApiError, ErrorKind};

pub(crate) enum Selector {
    None,
    ByHash(String),
    HighestRateLimit,
    RoundRobin,
}

/// `""`/`"{}"` = no selector; `{"by_hash":…}`;
/// `{"strategy":"round_robin"|"highest_rate_limit"}`.
pub(crate) fn parse_selector(selector_json: &str) -> Result<Selector, ApiError> {
    let trimmed = selector_json.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return Ok(Selector::None);
    }
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &format!("selector_json: {e}")))?;
    if let Some(hash) = v.get("by_hash").and_then(|x| x.as_str()) {
        return Ok(Selector::ByHash(hash.to_string()));
    }
    match v.get("strategy").and_then(|x| x.as_str()) {
        Some("round_robin") => Ok(Selector::RoundRobin),
        Some("highest_rate_limit") => Ok(Selector::HighestRateLimit),
        Some(other) => Err(ApiError::new(
            ErrorKind::InvalidArgument,
            &format!("unknown strategy {other:?} (round_robin | highest_rate_limit)"),
        )),
        None => Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "selector_json must carry by_hash or strategy",
        )),
    }
}

/// Last-returned membership_hash per scope. In-memory only: rotation state
/// need not survive a restart (any starting point is fair).
static ROUND_ROBIN: Mutex<Option<HashMap<(String, String), String>>> = Mutex::new(None);

/// Resolve the record to use. `records` is the registry's full local list of
/// [`MembershipRecord`]s; `scope` = (canonical registry_id,
/// lowercase rln_identifier hex).
pub(crate) fn select_hash(
    records: &[MembershipRecord],
    scope: (&str, &str),
    selector: &Selector,
) -> Result<String, ApiError> {
    let mut candidates: Vec<(&str, u64)> = records
        .iter()
        .filter(|r| !r.quarantined && r.meta.state.is_usable())
        .map(|r| (r.hash.as_str(), r.meta.rate_limit))
        .collect();
    // Hash order makes every strategy deterministic and churn-stable.
    candidates.sort_by(|a, b| a.0.cmp(b.0));
    if candidates.is_empty() {
        return Err(ApiError::new(
            ErrorKind::NoUsableMembership,
            "no active or grace_period membership for this registry",
        ));
    }

    match selector {
        Selector::ByHash(wanted) => candidates
            .iter()
            .find(|(hash, _)| hash == wanted)
            .map(|(hash, _)| hash.to_string())
            .ok_or_else(|| {
                ApiError::new(
                    ErrorKind::UnknownMembership,
                    "by_hash matches no usable membership",
                )
            }),
        Selector::None => {
            if candidates.len() == 1 {
                Ok(candidates[0].0.to_string())
            } else {
                Err(ApiError::new(
                    ErrorKind::AmbiguousSelection,
                    "multiple usable memberships; provide a selector",
                ))
            }
        }
        Selector::HighestRateLimit => Ok(candidates
            .iter()
            // Highest rate; ties break to the LOWEST hash (deterministic).
            .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
            .expect("non-empty candidates")
            .0
            .to_string()),
        Selector::RoundRobin => {
            let key = (scope.0.to_string(), scope.1.to_string());
            let mut guard = lock(&ROUND_ROBIN);
            let map = guard.get_or_insert_with(HashMap::new);
            // Next = first candidate strictly after the cursor in hash
            // order, wrapping — stable when the candidate set churns.
            let next = match map.get(&key) {
                Some(last) => candidates
                    .iter()
                    .find(|(hash, _)| *hash > last.as_str())
                    .unwrap_or(&candidates[0])
                    .0,
                None => candidates[0].0,
            };
            map.insert(key, next.to_string());
            Ok(next.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MembershipMeta, MembershipState};

    fn record(hash: &str, state: MembershipState, rate: u64, quarantined: bool) -> MembershipRecord {
        MembershipRecord {
            hash: hash.to_string(),
            meta: MembershipMeta {
                allocations: Vec::new(),
                allocations_mac: None,
                epoch_size_sec: 0,
                failed_reason: None,
                identity_commitment: "11".repeat(32),
                leaf_index: 0,
                prune_floor: 0,
                rate_limit: rate,
                registry_id: "logos:local:aa".to_string(),
                retryable: None,
                rln_identifier: String::new(),
                state,
                state_history: vec![],
                submitted_at: 0,
                tx_result: None,
            },
            quarantined,
        }
    }

    const SCOPE: (&str, &str) = ("logos:local:aa", "deadbeef");

    #[test]
    fn only_usable_states_are_candidates() {
        let records = vec![
            record("a1", MembershipState::Pending, 300, false),
            record("b2", MembershipState::Failed, 300, false),
            record("c3", MembershipState::Expired, 300, false),
            record("d4", MembershipState::Active, 300, true), // quarantined
        ];
        let err = select_hash(&records, SCOPE, &Selector::None).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NoUsableMembership);
    }

    #[test]
    fn sole_candidate_is_returned_multiple_require_selector() {
        let one = vec![record("a1", MembershipState::Active, 300, false)];
        assert_eq!(select_hash(&one, SCOPE, &Selector::None).unwrap(), "a1");

        let two = vec![
            record("a1", MembershipState::Active, 300, false),
            record("b2", MembershipState::GracePeriod, 300, false),
        ];
        let err = select_hash(&two, SCOPE, &Selector::None).unwrap_err();
        assert_eq!(err.kind, ErrorKind::AmbiguousSelection);
    }

    #[test]
    fn by_hash_hits_usable_and_misses_everything_else() {
        let records = vec![
            record("a1", MembershipState::Active, 300, false),
            record("b2", MembershipState::Failed, 300, false),
        ];
        assert_eq!(
            select_hash(&records, SCOPE, &Selector::ByHash("a1".into())).unwrap(),
            "a1"
        );
        let err = select_hash(&records, SCOPE, &Selector::ByHash("b2".into())).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnknownMembership, "failed record is not usable");
    }

    #[test]
    fn highest_rate_limit_with_lowest_hash_tie_break() {
        let records = vec![
            record("c3", MembershipState::Active, 500, false),
            record("a1", MembershipState::Active, 500, false),
            record("b2", MembershipState::Active, 200, false),
        ];
        assert_eq!(
            select_hash(&records, SCOPE, &Selector::HighestRateLimit).unwrap(),
            "a1"
        );
    }

    #[test]
    fn round_robin_rotates_per_scope_and_survives_churn() {
        let records = vec![
            record("a1", MembershipState::Active, 300, false),
            record("b2", MembershipState::Active, 300, false),
            record("c3", MembershipState::Active, 300, false),
        ];
        let scope_x = ("logos:local:aa", "aaaa1111");
        let scope_y = ("logos:local:aa", "bbbb2222");

        assert_eq!(select_hash(&records, scope_x, &Selector::RoundRobin).unwrap(), "a1");
        assert_eq!(select_hash(&records, scope_x, &Selector::RoundRobin).unwrap(), "b2");
        // A different rln_identifier rotates independently.
        assert_eq!(select_hash(&records, scope_y, &Selector::RoundRobin).unwrap(), "a1");
        // Candidate churn: b2 vanishes while the cursor sits on it.
        let churned = vec![
            record("a1", MembershipState::Active, 300, false),
            record("c3", MembershipState::Active, 300, false),
        ];
        assert_eq!(select_hash(&churned, scope_x, &Selector::RoundRobin).unwrap(), "c3");
        assert_eq!(select_hash(&churned, scope_x, &Selector::RoundRobin).unwrap(), "a1");
    }

    #[test]
    fn selector_parsing() {
        assert!(matches!(parse_selector(""), Ok(Selector::None)));
        assert!(matches!(parse_selector(" {} "), Ok(Selector::None)));
        assert!(matches!(
            parse_selector(r#"{"by_hash":"abc"}"#),
            Ok(Selector::ByHash(h)) if h == "abc"
        ));
        assert!(matches!(
            parse_selector(r#"{"strategy":"round_robin"}"#),
            Ok(Selector::RoundRobin)
        ));
        assert!(matches!(
            parse_selector(r#"{"strategy":"highest_rate_limit"}"#),
            Ok(Selector::HighestRateLimit)
        ));
        assert!(parse_selector(r#"{"strategy":"lowest"}"#).is_err());
        assert!(parse_selector(r#"{"foo":1}"#).is_err());
        assert!(parse_selector("not json").is_err());
    }
}
