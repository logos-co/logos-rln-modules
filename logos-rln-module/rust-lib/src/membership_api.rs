//! The membership read and provisioning methods: scope state, selection,
//! the registry's membership list, and `ensure_membership`'s provisioning pass.

use std::sync::Arc;

use crate::ensure;
use crate::error::{ApiError, ErrorKind};
use crate::lifecycle::{self, MembershipRecord, MembershipState};
use crate::ok_json;
use crate::provider;
use crate::register::parse_registry_options;
use crate::scope::{
    backend_of, parse_registry, parse_scope, records_for_registry, resolve_scope_state, ScopeState,
};
use crate::sealed_store::store::Store;
use crate::select;
use crate::util::now_unix;
use crate::views;
use crate::worker;

/// The provisioning task's progress for a registry, shaped for the reply.
pub(crate) fn provisioning_view(registry: &str) -> Option<views::ProvisioningView> {
    ensure::progress(registry).map(|p| {
        let view = views::ProvisioningView::new(p.step.as_str(), p.detail)
            .with_fallback_reason(p.fallback_reason);
        match p.funding {
            Some(f) => view.with_funding(&f.payer, f.required, f.price, f.fee_reserve, f.balance),
            None => view,
        }
    })
}

/// Spec get_membership_state(scope): a live registry read overlaid on the
/// local record answering the scope (`resolve_scope_state`). No record →
/// UNKNOWN; more than one live at the winning rank → AmbiguousSelection.
/// Transitions the merged view implies are persisted.
///
/// Takes NO register claim: this is the module's most-polled read and the
/// claim is exclusive per scope — holding it here would serialize polls (and
/// any register behind them) for a full registry-read budget and tell the
/// loser a registration is in flight that it never issued. The cache write
/// below is a compare-and-set instead.
pub(crate) fn get_membership_state_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_id_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let prov = backend_of(&registry)?;

    // A missing store (no persistence path) degrades to no local records,
    // which the empty-candidates arm below answers as `unknown`.
    let Ok(store) = store else {
        return ok_json(
            views::MembershipStateView::unknown(&registry.canonical)
                .with_provisioning(provisioning_view(&registry.canonical)),
        );
    };
    let records = records_for_registry(&store, &registry);
    let record = match resolve_scope_state(&records, &rln_id_hex) {
        ScopeState::None => {
            return ok_json(
                views::MembershipStateView::unknown(&registry.canonical)
                    .with_provisioning(provisioning_view(&registry.canonical)),
            )
        }
        ScopeState::Ambiguous(why) => return Err(ApiError::new(ErrorKind::AmbiguousSelection, why)),
        // An allocator's refusal while a provisioning pass works this
        // registry is a verdict the pass is already acting on (the funded
        // fallback follows): the pass's own step says what is going on, and a
        // live record replaces this one when it lands. Any other terminal
        // record reads through to the registry — a gift the window gave up
        // on may be there after all, and only this read heals it.
        ScopeState::One(r)
            if !r.cache.state.is_live()
                && r.cache.failed_reason.as_deref().is_some_and(|w| w.starts_with("gifter_failed"))
                && ensure::is_running(&registry.canonical) =>
        {
            return ok_json(
                views::MembershipStateView::unknown(&registry.canonical)
                    .with_provisioning(provisioning_view(&registry.canonical)),
            )
        }
        ScopeState::One(r) => r,
    };
    let record = &record;
    let hash = &record.hash;

    let pm = prov.get_membership(&registry, &record.identity.identity_commitment)?;
    let registry_state = pm.as_ref().map(|p| p.state);
    let merged = lifecycle::merge_state(Some(record), registry_state, now_unix());

    if merged != record.cache.state {
        // Self-healing cache write: the merged view is recomputed on every
        // read, so a failed persist only costs the next reader a recompute.
        // Compare-and-set on the state observed under the store lock —
        // `merged` comes from a snapshot taken before a (potentially ~70s)
        // provider read and must not clobber a fresher writer.
        let snapshot_state = record.cache.state;
        let persist = store.update_cache(hash, |m| {
            if m.state != snapshot_state {
                return; // lost the race to a fresher writer — keep theirs
            }
            m.state = merged;
            if let Some(pm) = &pm {
                // The pending→active re-read (spec MUST).
                m.leaf_index = Some(pm.leaf_index);
                m.rate_limit = Some(pm.rate_limit);
                m.failed_reason = None;
                m.retryable = None;
            } else if merged == MembershipState::Failed {
                m.failed_reason = Some("confirmation_window_elapsed".to_string());
                // Re-registration can be attempted (spec: a failed
                // submission SHALL report whether it is retryable).
                m.retryable = Some(true);
            } else if merged == MembershipState::Erased {
                m.failed_reason = Some("removed_from_registry".to_string());
            }
        });
        match persist {
            Err(e) => eprintln!("membership state persist: {}", e.message),
            // Emit only when this call's CAS actually wrote the transition.
            Ok(prior) if prior == snapshot_state => {
                // After the store write returned: no store lock is held
                // across the event emit.
                lifecycle::emit_transition(hash, record, prior, merged);
            }
            Ok(_) => {} // lost the race — the winner emitted its own event
        }
    }

    let (leaf_index, rate_limit) = match &pm {
        Some(pm) => (pm.leaf_index, pm.rate_limit),
        None => (record.cache.leaf_index.unwrap_or(0), record.cache.rate_limit.unwrap_or(0)),
    };
    let mut view = views::MembershipStateView::resolved(
        hash,
        &registry.canonical,
        merged,
        leaf_index,
        rate_limit,
    );
    if !merged.is_live() {
        // Why, and whether to try again — read back after the write above so
        // a reason this very call recorded is what the caller sees.
        if let Some(now) = store.membership(hash) {
            view = view.with_failure(now.cache.failed_reason.clone(), now.cache.retryable);
        }
    }
    ok_json(view)
}

/// Spec select(): resolve WHICH membership an application should prove with,
/// for scopes that hold more than one. Returns the PUBLIC membership view
/// only — the identity credential is never released. No unlocked keystore
/// is required.
pub(crate) fn select_membership_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    selector_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let (registry, _, rln_identifier_hex) = parse_scope(registry_id_raw, rln_identifier_hex)?;
    let selector = select::parse_selector(selector_json)?;

    let store = store?;
    let records = records_for_registry(&store, &registry);
    let hash = select::select_hash(
        &records,
        (&registry.canonical, &rln_identifier_hex),
        &selector,
    )?;
    let record = records
        .iter()
        .find(|r| r.hash == hash)
        .cloned()
        .ok_or_else(|| ApiError::internal("selected record vanished"))?;
    Ok(views::public_membership(&hash, &record, false, false, false))
}

/// ensure_membership(registry): `start()`'s provisioning for one registry,
/// reachable from a ui_qml app. `start()` answers over the `result` channel,
/// which nulls through the QML bridge, and every scope-taking method refuses
/// the empty (registry-wide) scope that provisioning registers — so a UI that
/// wants "a membership that backs every app on this registry" calls this.
/// The pass it spawns is the one `start()` runs, ended by the next `start()`
/// like any pass, and ending none itself (`ensure::run_alongside`).
///
/// Answers from the local records on purpose. The question is "is this
/// registry provisioned", which any live record answers; the registry read
/// that overlays a stale cache belongs to `get_membership_state`, which the
/// caller polls next anyway, and this call stays clear of a 70 s provider
/// deadline.
pub(crate) fn ensure_membership_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
    options_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let (rate_limit, rest) = parse_registry_options(options_json)?;
    // Refused rather than ignored: a caller passing gifter options here
    // expects a gift, and silently funding a registration instead would spend
    // the payer's balance on the opposite of what was asked.
    if let Some(key) = rest.as_object().and_then(|o| o.keys().next()) {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            &format!(
                "ensure_membership takes only rate_limit; '{key}' selects a scoped \
                 registration, which is register_membership's"
            ),
        ));
    }
    let store = store?;
    let records = records_for_registry(&store, &registry);
    let live: Vec<&MembershipRecord> = records
        .iter()
        .filter(|r| !r.quarantined && r.cache.state.is_live())
        .collect();
    match live.as_slice() {
        [] => {}
        [record] => {
            // A pending record has no leaf yet; 0 is what get_membership_state
            // reports for it too, until the registry read fills it in.
            return ok_json(views::MembershipStateView::resolved(
                &record.hash,
                &registry.canonical,
                record.cache.state,
                record.cache.leaf_index.unwrap_or(0),
                record.cache.rate_limit.unwrap_or(0),
            ));
        }
        _ => {
            return Err(ApiError::new(
                ErrorKind::AmbiguousSelection,
                "multiple live memberships on this registry; use get_memberships / select_membership",
            ))
        }
    }
    if worker::is_stopped() {
        return Err(ApiError::new(ErrorKind::NotReady, "module stopped; start() first"));
    }
    // The claim is the check and the marker in one step: two calls racing
    // each other spawn one pass, and the marker rides into the thread so
    // the registry reads as running from this reply on.
    if let Some(pass) = ensure::ActivePass::claim(&registry.canonical) {
        // Recorded before the spawn so this very reply already shows a step,
        // and a second call racing the thread's first record sees one too.
        ensure::mark_requested(&registry.canonical);
        let canonical = registry.canonical.clone();
        std::thread::Builder::new()
            .name("rln-ensure".to_owned())
            .spawn(move || {
                let _claim = pass;
                // The order start() keeps: the registry's network binds
                // the lez module's wallet before anything reads through it.
                provider::select_networks(std::slice::from_ref(&canonical));
                ensure::run_alongside(canonical, rate_limit);
            })
            .map_err(|e| ApiError::internal(&format!("cannot spawn provisioning: {e}")))?;
    }
    ok_json(
        views::MembershipStateView::unknown(&registry.canonical)
            .with_provisioning(provisioning_view(&registry.canonical)),
    )
}

pub(crate) fn get_memberships_impl(
    store: Result<Arc<Store>, ApiError>,
    registry_id_raw: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let store = store?;
    // No provider needed: listing LOCAL records is meaningful even for a
    // namespace this build can't reach.
    let records = records_for_registry(&store, &registry);
    let memberships: Vec<serde_json::Value> = records
        .iter()
        .map(|r| views::public_membership(&r.hash, r, r.quarantined, false, false))
        .collect();
    Ok(serde_json::json!({ "memberships": memberships }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::LiblogosRlnModule;
    use crate::register::{RegisterClaim, WINDOW_ELAPSED};
    use crate::registry_id;
    use crate::test_support::{imp_with_store, no_store, opts_arr, seed_membership, TEST_GLOBAL_LOCK};
    use crate::proof;
    use crate::sealed_store;
    use crate::proof_api::validate_proof_impl;

    // While a provisioning pass works a registry, a scope whose only record
    // is terminal reads unknown with the pass's step, not the stale verdict.
    #[test]
    fn a_terminal_record_reads_unknown_while_provisioning_runs() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-terminal-while-prov-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "6d".repeat(32));
        let canonical = registry_id::parse(&registry).unwrap().canonical;
        let rid = "b1".repeat(32);
        seed_membership(&store, "hf", &registry, &"44".repeat(32), "", &"f6".repeat(32), MembershipState::Failed, 0, 100);
        store.update_cache("hf", |m| m.failed_reason = Some("gifter_failed: dead allocator".into())).unwrap();
        {
            let _pass = ensure::ActivePass::enter(&canonical);
            ensure::mark_requested(&canonical);
            let out = get_membership_state_impl(imp.store(), &registry, &rid).unwrap();
            assert_eq!(out["state"], serde_json::json!("unknown"), "got: {out}");
            assert!(out.get("provisioning").is_some(), "the pass's step rides along: {out}");
        }
        // With no pass the record itself answers (reaching the registry read,
        // which the test environment cannot serve).
        assert!(get_membership_state_impl(imp.store(), &registry, &rid).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The pass's masking covers the allocator refusal it is acting on, not
    // every terminal record: a gift the window gave up on reads through to
    // the registry (the test environment cannot serve that read).
    #[test]
    fn only_an_allocator_refusal_is_masked_while_provisioning_runs() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-mask-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "6e".repeat(32));
        let canonical = registry_id::parse(&registry).unwrap().canonical;
        let rid = "b2".repeat(32);
        seed_membership(&store, "hw", &registry, &"45".repeat(32), "", &"f7".repeat(32), MembershipState::Failed, 0, 100);
        store.update_cache("hw", |m| m.failed_reason = Some(WINDOW_ELAPSED.into())).unwrap();
        let _pass = ensure::ActivePass::enter(&canonical);
        ensure::mark_requested(&canonical);
        assert!(get_membership_state_impl(imp.store(), &registry, &rid).is_err(), "window-failed: read through");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // After stop() nothing may spawn: ensure_membership says so instead of
    // recording a step no pass will ever advance.
    #[test]
    fn ensure_membership_after_stop_is_not_ready() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ensure-stopped-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, _store) = imp_with_store(dir.clone());
        imp.stop().unwrap();
        let registry = format!("logos:local:{}", "7a".repeat(32));
        let e = ensure_membership_impl(imp.store(), &registry, "").unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotReady, "{}", e.message);
        worker::reset_for_test();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Every call passes its scope explicitly (spec: the Module holds no
    // default) — an empty registry_id or rln_identifier_hex is a plain parse
    // error on every scope-taking method, not a fallback.
    #[test]
    fn empty_scope_args_are_invalid_argument() {
        let registry = format!("logos:local:{}", "dd".repeat(32));
        let rln_id = "ef".repeat(32);

        let err = get_membership_state_impl(no_store(), "", "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = get_membership_state_impl(no_store(), &registry, "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = get_membership_state_impl(no_store(), "", &rln_id).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);

        let err = validate_proof_impl("", "", "00", "0", "{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        let err = validate_proof_impl(&registry, "", "00", "0", "{}").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
    }

    // get_membership_state is a READ and takes no register claim: the UI
    // polls it per card, so overlapping polls of one scope must all answer.
    #[test]
    fn membership_state_reads_take_no_register_claim() {
        let registry = format!("logos:local:{}", "1a".repeat(32));
        let rln_id = "2b".repeat(32);
        let (canonical, _, rln_id_hex) = parse_scope(&registry, &rln_id).unwrap();

        // A register for exactly this scope is in flight, holding the claim.
        let claim = RegisterClaim::take(&canonical.canonical, &rln_id_hex).ok();
        assert!(claim.is_some(), "the first claim must be granted");
        match RegisterClaim::take(&canonical.canonical, &rln_id_hex) {
            Ok(_) => panic!("the register claim must stay exclusive"),
            Err(e) => assert!(e.message.contains("already in flight"), "got: {}", e.message),
        }

        // Reads of that same scope are unaffected, and repeat freely.
        for _ in 0..2 {
            let out = get_membership_state_impl(no_store(), &registry, &rln_id).unwrap();
            assert_eq!(out["state"], serde_json::json!("unknown"), "got: {out}");
        }
        drop(claim);

        let out = get_membership_state_impl(no_store(), &registry, &rln_id).unwrap();
        assert_eq!(out["state"], serde_json::json!("unknown"), "got: {out}");
        assert!(
            RegisterClaim::take(&canonical.canonical, &rln_id_hex).is_ok(),
            "a read must leave no claim behind"
        );
    }

    // ensure_membership is the registry-wide twin of start()'s provisioning
    // and the one path a ui_qml app has to it. What it refuses is anything
    // that would turn it into a scoped — or gifted — registration in
    // disguise, and it refuses before the store is touched.
    #[test]
    fn ensure_membership_validates_before_touching_the_store() {
        let registry = format!("logos:local:{}", "e1".repeat(32));
        let canonical = parse_registry(&registry).unwrap().canonical;

        let err = ensure_membership_impl(no_store(), "", "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);

        let err =
            ensure_membership_impl(no_store(), &registry, &opts_arr(&[("delegated", "true")]))
                .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);
        assert!(err.message.contains("register_membership"), "got: {}", err.message);

        let err = ensure_membership_impl(no_store(), &registry, &opts_arr(&[("rate_limit", "0")]))
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument, "got: {}", err.message);

        // Valid input and no store is the store's own error — and no pass
        // was started on the way to it.
        let err = ensure_membership_impl(no_store(), &registry, "").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Internal, "got: {}", err.message);
        assert!(!ensure::is_running(&canonical));
        assert!(ensure::progress(&canonical).is_none(), "nothing may be recorded for it");
    }

    // A live membership of ANY scope answers "provisioned": the reply is that
    // record, from the cache, and nothing is spawned. Registering a second
    // one is the failure the entry check in ensure.rs exists to prevent.
    #[test]
    fn ensure_membership_reports_a_live_membership_of_any_scope_without_spawning() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ensure-live-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

        let registry = format!("logos:local:{}", "e2".repeat(32));
        let canonical = parse_registry(&registry).unwrap().canonical;
        // Registered under an application scope, not registry-wide.
        let scoped_rln_id = "ef".repeat(32);
        let (commitment_hex, secret_hex) = proof::generate_identity().expect("test identity");
        let commitment =
            registry_id::hex_to_bytes32(&commitment_hex).expect("generated commitment is 32 bytes");
        let hash = registry_id::membership_hash(&registry, &commitment);
        seed_membership(
            &store,
            &hash,
            &registry,
            &commitment_hex,
            &scoped_rln_id,
            &secret_hex,
            MembershipState::Active,
            7,
            300,
        );

        let out = ensure_membership_impl(imp.store(), &registry, "").unwrap();
        assert_eq!(out["state"], serde_json::json!("active"), "got: {out}");
        assert_eq!(out["membership_hash"], serde_json::json!(hash), "got: {out}");
        assert_eq!(out["leaf_index"], serde_json::json!(7), "got: {out}");
        assert_eq!(out["rate_limit"], serde_json::json!(300), "got: {out}");
        assert!(out.get("provisioning").is_none(), "a provisioned registry has no pass: {out}");
        assert!(!ensure::is_running(&canonical));
        assert!(ensure::progress(&canonical).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // No live record: exactly one pass per registry. While one is alive a
    // repeat call reports and does not spawn — observable because the spawn
    // path records a first step before the thread exists, and the held pass
    // below has recorded nothing.
    #[test]
    fn ensure_membership_spawns_one_pass_and_reports_its_step() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ensure-spawn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, _store) = imp_with_store(dir.clone());

        // A pass somebody else is already running for this registry.
        let busy = format!("logos:local:{}", "e3".repeat(32));
        let busy_canonical = parse_registry(&busy).unwrap().canonical;
        {
            let _held = ensure::ActivePass::enter(&busy_canonical);
            let out = ensure_membership_impl(imp.store(), &busy, "").unwrap();
            assert_eq!(out["state"], serde_json::json!("unknown"), "got: {out}");
            assert!(
                out.get("provisioning").is_none(),
                "a running pass is reported as it stands, not re-marked: {out}"
            );
            assert!(ensure::progress(&busy_canonical).is_none());
        }

        // Nobody is: the call starts one and the reply already shows a step.
        let fresh = format!("logos:local:{}", "e4".repeat(32));
        let fresh_canonical = parse_registry(&fresh).unwrap().canonical;
        let out = ensure_membership_impl(imp.store(), &fresh, &opts_arr(&[("rate_limit", "250")]))
            .unwrap();
        assert_eq!(out["state"], serde_json::json!("unknown"), "got: {out}");
        assert_eq!(out["registry_id"], serde_json::json!(fresh_canonical), "got: {out}");
        assert!(
            out["provisioning"]["step"].is_string(),
            "the spawning reply carries the pass's first step: {out}"
        );
        assert!(ensure::progress(&fresh_canonical).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // select_membership returns the PUBLIC membership only — never the
    // secret, and without requiring an unlocked keystore.
    #[test]
    fn select_membership_returns_public_view_without_releasing_secret() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-select-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        // Seeding a credential still needs unlock (writes are encrypted).
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

        let registry = format!("logos:local:{}", "cd".repeat(32));
        let commitment = [0x66u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        seed_membership(
            &store,
            &hash,
            &registry,
            &registry_id::bytes_to_hex(&commitment),
            "",
            &"77".repeat(32),
            MembershipState::Active,
            3,
            300,
        );

        let rln_id = "ef".repeat(32);
        // Even locked, select returns the public view — no secret, no error.
        assert!(imp.lock_keystore().contains(r#""locked":true"#));
        let out = imp.select_membership(registry.clone(), rln_id, String::new());
        assert!(out.contains(&format!(r#""membership_hash":"{hash}""#)), "got: {out}");
        assert!(
            !out.contains("identity_secret_hash"),
            "the identity secret must NEVER be released: {out}"
        );
        assert!(!out.contains(r#""kind":"locked""#), "no unlock required to select: {out}");
        assert!(imp.get_memberships(registry).contains(&hash));

        sealed_store::store::publish(None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
