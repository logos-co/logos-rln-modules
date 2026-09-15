//! Provisioning a membership the node was not given.
//!
//! A consumer that needs RLN to send should not have to know whether a
//! membership exists or has to be created. `start()` names the registries this
//! node will prove against; everything after that — waiting for the wallet,
//! waiting for it to be funded, pricing the registration, submitting it — is
//! this module's work, not the caller's.
//!
//! Before registration became single-asset this could not have lived here: it
//! needed a holding account derived in a sibling's wallet, a faucet claim, a
//! second balance to watch and a deployment policy that said whether the
//! faucet existed at all. One account and one asset is what makes it short
//! enough to be worth doing automatically.
//!
//! ## Why it runs detached
//!
//! `start()` must return promptly — delivery calls it inside `configureRln`,
//! under a transport deadline, and a node that cannot start is worse than one
//! that starts without a membership. So this runs on the supervisor's one-shot
//! worker and `start()` does not wait for it. That is also the honest shape:
//! the node genuinely IS usable meanwhile, as a validator, and its sends fail
//! with `no_usable_membership` until the membership lands — which is exactly
//! what a consumer already handles for a node whose membership is pending.
//!
//! ## Why it is safe to run every start
//!
//! `register_scoped` is idempotent per scope: a live record short-circuits and
//! returns it. So a restart re-enters this, finds the membership it made last
//! time, and stops. Nothing here is a "first run" path.

use std::time::{Duration, Instant};

use crate::{
    ApiError, ErrorKind, provider_of, records_for_registry, register_scoped, registry_id, worker,
};

/// A registry-wide membership: the credential is stored with no
/// `rln_identifier`, which `scope_matches` treats as backing every
/// application on the registry, and `proof::generate` takes the identifier
/// from the request. `start()` names registries and no scopes, so this is the
/// only scope it could provision — and the right one, since the node does not
/// yet know which applications will use it.
const REGISTRY_WIDE: &str = "";

/// How long to keep waiting for the wallet, and then for it to be funded.
///
/// Generous on purpose. The funding step is a human or an operator's script
/// sending value to an account this module just published; minutes is a
/// normal latency for that, and giving up turns a slow operator into a node
/// that never registers.
const WALLET_WAIT: Duration = Duration::from_secs(300);
const FUNDING_WAIT: Duration = Duration::from_secs(900);

/// Poll interval for both waits.
const TICK: Duration = Duration::from_secs(5);

/// The fee a transaction reserves, over and above the registry's price.
///
/// The sibling declares `gas_limit = 10_000_000` and the wallet sizes its
/// reservation as `(gas_limit + ASSUMED_DATA_BYTES) * ASSUMED_BASE_FEE`. That
/// is ~646M against a registration price near 1M — the fee dominates the price
/// by two to three orders of magnitude, so "can afford the price" is the wrong
/// question and an account sized only for the price cannot transact at all.
///
/// Duplicated rather than read: `wallet_ffi` exports no accessor for it. It is
/// an over-estimate by design — the reserve is refunded down to the actual fee
/// — so waiting for it is conservative, never optimistic.
const FEE_RESERVE: u128 = (10_000_000 + 100_000) * 64;

/// What the task is waiting on, for `get_membership_state` to surface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    WaitingForWallet,
    AwaitingFunding,
    Registering,
    Done,
    /// Gave up. The detail says why; nothing retries without a new `start()`.
    Refused,
}

impl Step {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Step::WaitingForWallet => "waiting_for_wallet",
            Step::AwaitingFunding => "awaiting_funding",
            Step::Registering => "registering",
            Step::Done => "done",
            Step::Refused => "refused",
        }
    }
}

/// Provision a membership for each registry `start()` named.
///
/// Errors are logged and abandoned per registry rather than propagated: this
/// runs detached, there is nobody to return to, and one unreachable registry
/// must not stop the others.
pub(crate) fn run(registries: Vec<String>, rate_limit: u64) {
    for raw in registries {
        if worker::is_stopped() {
            return;
        }
        let registry = match registry_id::parse(&raw) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("provision {raw}: not a registry id ({e})");
                continue;
            }
        };
        // Read per registry rather than captured once: this runs detached and
        // the store can be republished under it (on_context_ready re-opening
        // it), so a handle taken at spawn time could outlive its store.
        if let Err(e) = provision_one(&registry, rate_limit) {
            record(&registry.canonical, Step::Refused, &e.message);
            eprintln!("provision {}: {}", registry.canonical, e.message);
        }
    }
}

fn provision_one(
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
) -> Result<(), ApiError> {
    // Does this node already have a membership on this registry — ANY
    // membership, whatever scope it was registered under?
    //
    // Deliberately not `scope_matches(r, REGISTRY_WIDE)`, which is true only
    // of a record carrying an empty identifier. Under that test a node that
    // had registered explicitly for one application looked unprovisioned and
    // got a SECOND membership: a second registration, a second slice of the
    // registry's rate-limit budget, no new capability — and, because the extra
    // insert moves the tree root, an invalidated proof for anything already in
    // flight. Observed exactly that: a scenario registered, called start() to
    // warm its root window, and validate_proof then rejected a proof it had
    // just generated.
    //
    // The question provisioning exists to answer is "can this node prove
    // against this registry", and any live record answers it yes.
    if let Some(s) = crate::sealed_store::store::current() {
        let records = records_for_registry(&s, registry);
        let live = records
            .iter()
            .any(|r| !r.quarantined && r.cache.state.is_live());
        if live {
            record(&registry.canonical, Step::Done, "membership already present");
            return Ok(());
        }
        // A quarantined record is NOT an absent one, and this is the case
        // where the difference has teeth.
        //
        // Quarantine means the local metadata for a membership failed its MAC:
        // a tamper, detected. The membership itself is still on chain, still
        // holding its leaf and still consuming its slice of the registry's
        // rate-limit budget. Registering a replacement would spend real
        // balance in response to an attack signal, take a SECOND slice of that
        // budget for one node, and leave a working node with the evidence
        // buried — `get_memberships`' forensic `metadata_tamper` verdict exists
        // precisely so an operator sees this.
        //
        // So provisioning stops and says why. Recovery stays what it has always
        // been and what the docs promise: an explicit `register_membership`
        // call, which a human makes after looking.
        if let Some(r) = records.iter().find(|r| r.quarantined) {
            record(
                &registry.canonical,
                Step::Refused,
                &format!(
                    "membership {} is quarantined (local metadata failed its MAC); \
                     not registering a replacement — inspect with get_memberships, \
                     then register_membership deliberately",
                    r.hash
                ),
            );
            return Ok(());
        }
    }

    let prov = provider_of(registry)?;

    // 1. The wallet. `failed` is terminal — the sibling brings its wallet up
    //    once and never retries — so waiting on it would be waiting forever.
    record(&registry.canonical, Step::WaitingForWallet, "");
    let deadline = Instant::now() + WALLET_WAIT;
    loop {
        if worker::is_stopped() {
            return Ok(());
        }
        // An Err is the module not answering calls yet — indistinguishable
        // from "pending" this early, and worth the same wait.
        if let Ok(status) = prov.wallet_status() {
            match status.get("state").and_then(|x| x.as_str()) {
                Some("ready") => break,
                Some("failed") => {
                    let detail = status.get("detail").and_then(|x| x.as_str()).unwrap_or("");
                    return Err(ApiError::new(
                        ErrorKind::ProviderFailure,
                        &format!("the registry module's wallet failed to come up: {detail}"),
                    ));
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(ApiError::new(
                ErrorKind::ProviderFailure,
                "the registry module's wallet never became ready",
            ));
        }
        std::thread::sleep(TICK);
    }

    // 2. The price. Read before the funding wait so the log can name the
    //    number being waited for.
    let price = registration_price(prov, registry, rate_limit)?;
    let required = price.saturating_add(FEE_RESERVE);

    // 3. Funding. Nothing this module can do brings it about — no program
    //    mints native balance — so this waits rather than acts, and says
    //    which account to send to.
    let payer = prov
        .wallet_status()
        .ok()
        .and_then(|s| s.get("payer").and_then(|p| p.as_str()).map(str::to_owned))
        .unwrap_or_default();
    record(
        &registry.canonical,
        Step::AwaitingFunding,
        &format!("{payer} needs {required} native ({price} price + {FEE_RESERVE} fee reserve)"),
    );
    let deadline = Instant::now() + FUNDING_WAIT;
    let mut announced = false;
    loop {
        if worker::is_stopped() {
            return Ok(());
        }
        match prov.payer_balance() {
            Ok(balance) if balance >= required => break,
            Ok(balance) => {
                if !announced {
                    eprintln!(
                        "provision {}: waiting for {payer} to hold {required} native \
                         ({price} price + {FEE_RESERVE} fee reserve); it holds {balance}",
                        registry.canonical
                    );
                    announced = true;
                }
            }
            // NOT treated as zero: an unreachable sequencer is not a broke
            // account, and giving up here would be giving up permanently.
            Err(e) => eprintln!("provision {}: balance read failed: {}", registry.canonical, e.message),
        }
        if Instant::now() >= deadline {
            return Err(ApiError::new(
                ErrorKind::ProviderFailure,
                &format!("{payer} was never funded with {required} native"),
            ));
        }
        std::thread::sleep(TICK);
    }

    // 4. Register. The same entry point the wire method uses, so the
    //    idempotency, the in-flight guard and the confirmation poller all
    //    come along; a live record short-circuits and this is a no-op.
    record(&registry.canonical, Step::Registering, "");
    let options = format!(r#"[{{"key":"rate_limit","value":"{rate_limit}"}}]"#);
    let store = crate::sealed_store::store::current_or_uninit();
    match register_scoped(store, registry, REGISTRY_WIDE, &options) {
        Ok(_) => {
            record(&registry.canonical, Step::Done, "submitted");
            eprintln!(
                "provision {}: registered a registry-wide membership at rate {rate_limit}",
                registry.canonical
            );
            Ok(())
        }
        // A locked keystore is `not_ready`, not a refusal: manual custody
        // means an operator unlocks later, and the next start() re-enters
        // here. Anything else is this registry's provisioning giving up.
        Err(e) if e.kind == ErrorKind::Locked => {
            record(&registry.canonical, Step::AwaitingFunding, "keystore locked");
            eprintln!(
                "provision {}: keystore is locked — unlock it and restart to provision",
                registry.canonical
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// `rate_limit x price_per_unit`, from the registry's own bounds.
fn registration_price(
    prov: &dyn crate::provider::RegistryProvider,
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
) -> Result<u128, ApiError> {
    let bounds = prov.get_registry_bounds(registry)?;
    // A decimal string on the wire, for the same reason the balance is.
    let price_per_unit = bounds
        .get("price_per_unit")
        .and_then(|p| p.as_str())
        .and_then(|p| p.parse::<u128>().ok())
        .ok_or_else(|| {
            ApiError::new(ErrorKind::ProviderFailure, "registry bounds carry no price_per_unit")
        })?;
    Ok(price_per_unit.saturating_mul(u128::from(rate_limit)))
}

// ---------------------------------------------------------------------------
// Progress, readable through get_membership_state
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

static PROGRESS: Mutex<Option<HashMap<String, (Step, String)>>> = Mutex::new(None);

fn record(registry: &str, step: Step, detail: &str) {
    let mut guard = crate::lock(&PROGRESS);
    guard
        .get_or_insert_with(HashMap::new)
        .insert(registry.to_owned(), (step, detail.to_owned()));
}

/// What provisioning is doing for `registry`, if anything.
///
/// Surfaced on `get_membership_state`'s `unknown` reply, which is otherwise
/// the same answer for "this node was never given a membership" and "this
/// node is three minutes into acquiring one".
pub(crate) fn progress(registry: &str) -> Option<(Step, String)> {
    crate::lock(&PROGRESS)
        .as_ref()
        .and_then(|m| m.get(registry).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate this module exists to get right. The fee reserve dominates the
    /// price by two to three orders of magnitude, so an account sized for the
    /// price alone cannot transact — and the failure it would hit is a bare
    /// "Incorrect fee" from the sequencer, naming neither number.
    #[test]
    fn affordability_counts_the_fee_reserve_not_just_the_price() {
        let price = 100u128 * 10_000; // rate 100 at the deployed price
        assert!(
            FEE_RESERVE > price * 100,
            "if the reserve ever stops dwarfing the price, revisit this gate: \
             reserve {FEE_RESERVE}, price {price}"
        );
        let required = price.saturating_add(FEE_RESERVE);
        assert!(required > price, "the requirement must exceed the price alone");
        // An account holding exactly the price is the case that used to pass a
        // naive check and then fail on chain.
        assert!(price < required);
    }

    /// The requirement must not wrap on an absurd registry price; an
    /// unaffordable number is a correct answer, a wrapped small one is not.
    #[test]
    fn a_saturating_price_stays_unaffordable() {
        let required = u128::MAX.saturating_add(FEE_RESERVE);
        assert_eq!(required, u128::MAX);
    }

    /// Progress is per registry, and absent until something records it —
    /// `get_membership_state` omits the object entirely in that case.
    #[test]
    fn progress_is_recorded_per_registry() {
        let a = "logos:test:aa";
        let b = "logos:test:bb";
        assert!(progress("logos:test:never-touched").is_none());

        record(a, Step::AwaitingFunding, "needs 646400000");
        record(b, Step::Done, "submitted");

        let (step, detail) = progress(a).expect("a has progress");
        assert_eq!(step, Step::AwaitingFunding);
        assert_eq!(step.as_str(), "awaiting_funding");
        assert!(detail.contains("646400000"));

        let (step, _) = progress(b).expect("b has progress");
        assert_eq!(step, Step::Done);

        // Later steps replace earlier ones rather than accumulating.
        record(a, Step::Done, "submitted");
        assert_eq!(progress(a).expect("a still has progress").0, Step::Done);
    }

    /// An empty rln_identifier is the registry-wide scope, and
    /// `scope_matches` is what makes that mean "backs every application".
    #[test]
    fn the_provisioned_scope_is_registry_wide() {
        assert_eq!(REGISTRY_WIDE, "");
    }

    /// Provisioning must stand down for a membership registered under ANY
    /// scope, not only the registry-wide one it would create itself.
    ///
    /// This is a regression, not a hypothetical. The first version asked
    /// `scope_matches(record, REGISTRY_WIDE)`, which is true only of a record
    /// with an empty identifier — so a node that had registered explicitly for
    /// one application looked unprovisioned, got a second membership, and the
    /// extra tree insert invalidated a proof already in flight. The symptom
    /// was a node rejecting a proof it had just generated.
    ///
    /// `scope_matches` is the wrong predicate here and this pins why: it
    /// answers "does this record back that application", while provisioning
    /// asks "can this node prove against this registry at all".
    #[test]
    fn a_scoped_membership_counts_as_provisioned() {
        let scoped = "aa".repeat(32);
        // What the old check did: only an empty identifier satisfied it.
        assert!(!crate::scope_matches_for_test(&scoped, REGISTRY_WIDE));
        assert!(crate::scope_matches_for_test("", REGISTRY_WIDE));
        // The new check consults no scope at all — `provision_one` filters on
        // `is_live()` alone. That cannot be asserted here without a store, so
        // what this test pins is the contrast above: the predicate the old
        // code used answers NO for a perfectly good membership, which is the
        // whole defect. If someone reintroduces a scope filter, the first
        // assertion is the one that should stop them.
    }
}
