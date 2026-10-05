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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// Past this much waiting on the wallet, say so in the recorded detail. Not a
/// deadline — see the wallet wait in `provision_one` for why there isn't one.
const WALLET_WAIT_NOTICE: Duration = Duration::from_secs(300);

/// Poll interval, and the granularity at which both waits notice they should
/// stop.
const TICK: Duration = Duration::from_secs(5);

/// Which provisioning pass is the current one.
///
/// `worker::start()` spawns a fresh warm task and DETACHES any still in
/// flight — the worker API hands that body no generation of its own, and a
/// repeated `start()` (which is every `configureRln`, so every delivery
/// bring-up) never sets the stopped flag. So a superseded pass has nothing to
/// notice, and since the funding wait lost its deadline it would otherwise
/// poll for the rest of the process's life, one more each time. The deadline
/// used to hide this by killing such a task within fifteen minutes.
///
/// Every pass takes a ticket on entry and both waits check it, so exactly one
/// pass is ever live and the newest wins — which is the right one, because it
/// carries the registries and rate the latest `start()` named.
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Should this pass stop — because the module stopped, or because a later
/// `start()` superseded it?
fn superseded(mine: u64) -> bool {
    worker::is_stopped() || EPOCH.load(Ordering::SeqCst) != mine
}

/// How often to READ the payer's balance, given how long the wait has run.
///
/// Funding arrives either promptly — an operator's script transferring as soon
/// as this module publishes the account — or at human speed, because somebody
/// has to bridge or buy the balance first. Poll tightly for the first minute so
/// the common case is not held up, then relax: a wait measured in hours should
/// cost a read every five minutes, not 720 an hour.
fn read_interval(waited: Duration) -> Duration {
    if waited < Duration::from_secs(60) {
        TICK
    } else if waited < Duration::from_secs(600) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(300)
    }
}

/// The execution gas limit the sibling's wallet declares for a registration:
/// `GAS_LIMIT` in logos-lez-rln-module/rust-lib/src/wallet.rs, written into
/// every home it provisions. A registration costs ~9.1M cycles, so the stock
/// 2,000,000 default cannot be what an adopted home declares either.
const DECLARED_GAS_LIMIT: u128 = 10_000_000;

/// The serialized-size allowance the wallet sizes its `max_fee` against
/// (`ASSUMED_DATA_BYTES` in the LEZ wallet). A Register tx is a few hundred
/// bytes, so this over-reserves storage gas — by ~1% of the whole reserve.
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// Headroom over the quoted ceiling for the base fee rising between the
/// balance check and the block the Register tx lands in.
///
/// The quote's `next_*_ceiling` already bounds the NEXT block (a full one
/// raises the base fee by at most one step, 8 -> 9 on devnet). But the check
/// can be a read interval old by submission, and the wallet waits up to 15
/// blocks for inclusion, so a congested stretch can outrun one step. x2 is six
/// more full-block steps of +12.5% (1.125^6 ~ 2.03); devnet registrations
/// measured 7.4e7-8.3e7 spent against 9.09e7 x2 reserved. Over-reserving
/// costs nothing but a larger funding target — the reserve is refunded down
/// to the actual fee — while under-reserving fails the Register on chain.
const BASE_FEE_HEADROOM: u128 = 2;

/// The reserve when no fee quote can be had — an older sibling without
/// `get_fee_state` (or one before lez 5.0.0 on an https sequencer: its quote
/// read spoke plain http only), a transport error or an unparsable
/// reply: the wallet's own declared cap, `(gas_limit + ASSUMED_DATA_BYTES) x
/// ASSUMED_BASE_FEE (64)`, ~646M. It is what every release before 0.10.0
/// waited for, so an older sibling keeps working exactly as it did.
const FALLBACK_FEE_RESERVE: u128 = (DECLARED_GAS_LIMIT + ASSUMED_DATA_BYTES) * 64;

/// Where a reserve came from, so the log can say when it changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReserveBasis {
    /// Computed from the chain's quote at this height.
    Quote(u64),
    Fallback,
}

/// The fee a Register tx reserves, over and above the registry's price.
///
/// A tx's `max_fee` is only a cap: the chain checks `max_fee >= reserve` and
/// then debits `gas_limit x base_fee_exec + data_bytes x base_fee_stor + tip`
/// at the including block's fee state, refunded down to the actual fee. So
/// the payer has to hold that reserve, not the cap — ~182M at devnet's base
/// fee 8 (ceiling 9) against the cap's 646M. The fee still dominates a price
/// near 1M, so "can afford the price" remains the wrong question.
fn fee_reserve_from(quote: &serde_json::Value) -> Option<u128> {
    let ceiling = |key: &str| quote.get(key).and_then(serde_json::Value::as_u64).map(u128::from);
    let exec = ceiling("next_base_fee_exec_ceiling")?;
    let stor = ceiling("next_base_fee_stor_ceiling")?;
    Some(
        DECLARED_GAS_LIMIT
            .saturating_mul(exec)
            .saturating_add(ASSUMED_DATA_BYTES.saturating_mul(stor))
            .saturating_mul(BASE_FEE_HEADROOM),
    )
}

/// The reserve from the sibling's live quote, or `FALLBACK_FEE_RESERVE`.
fn fee_reserve(quote: Result<serde_json::Value, ApiError>) -> (u128, ReserveBasis) {
    let computed = quote.ok().and_then(|q| {
        let height = q.get("height").and_then(serde_json::Value::as_u64).unwrap_or(0);
        fee_reserve_from(&q).map(|r| (r, ReserveBasis::Quote(height)))
    });
    computed.unwrap_or((FALLBACK_FEE_RESERVE, ReserveBasis::Fallback))
}

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
    let mine = EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
    for raw in registries {
        if superseded(mine) {
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
        if let Err(e) = provision_one(&registry, rate_limit, mine) {
            record(&registry.canonical, Step::Refused, &e.message);
            eprintln!("provision {}: {}", registry.canonical, e.message);
        }
    }
}

fn provision_one(
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
    mine: u64,
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

    // 1. The wallet.
    //
    // This wait has NO deadline either, for the same reason the funding wait
    // below has none. The commonest cause of a wallet that is not ready yet is
    // an unreachable sequencer — opening one is a chain read — and that is an
    // outage, not a verdict: the sibling now retries the open for as long as it
    // takes and stays `pending` while it does. A deadline here could only stop
    // watching, and stopping is permanent, because `run` records Refused and
    // `ensure::run` is entered from `start()` and nowhere else. That is exactly
    // how a node that booted during an outage used to stay dead for the rest of
    // the process's life, long after the chain came back.
    //
    // `failed` stays terminal: the sibling reserves it for the causes where
    // waiting cannot help — no wallet home, no sequencer configured, a payer key
    // it cannot import — and reports an unreachable chain as `pending`.
    record(&registry.canonical, Step::WaitingForWallet, "");
    let began = Instant::now();
    let mut noticed = false;
    loop {
        if superseded(mine) {
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
                Some("pending") => {
                    // Surface the sibling's own reason once the wait stops
                    // looking routine, so `get_membership_state` can say what
                    // is holding the node up rather than only that it waits.
                    let waited = began.elapsed();
                    if waited >= WALLET_WAIT_NOTICE && !noticed {
                        noticed = true;
                        let detail = status.get("detail").and_then(|x| x.as_str()).unwrap_or("");
                        eprintln!(
                            "provision {}: still waiting for the wallet after {}s: {detail}",
                            registry.canonical,
                            waited.as_secs()
                        );
                        record(
                            &registry.canonical,
                            Step::WaitingForWallet,
                            &format!("{}s: {detail}", waited.as_secs()),
                        );
                    }
                }
                _ => {}
            }
        }
        // Sleeps at TICK granularity whatever the interval, so `stop()`'s grace
        // join is never held open — the same discipline as the funding wait.
        let waited = began.elapsed();
        let due = waited + read_interval(waited);
        while began.elapsed() < due {
            if superseded(mine) {
                return Ok(());
            }
            std::thread::sleep(TICK);
        }
    }

    // 2. The price and the fee reserve. Read before the funding wait so the
    //    log can name the number being waited for.
    let price = registration_price(prov, registry, rate_limit)?;
    let (mut reserve, mut basis) = fee_reserve(prov.fee_state());
    log_basis(&registry.canonical, reserve, basis);
    let mut required = price.saturating_add(reserve);

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
        &format!("{payer} needs {required} native ({price} price + {reserve} fee reserve)"),
    );
    // This wait has NO deadline, and that is the point of it.
    //
    // Nothing this module can do brings the money about — no program mints
    // native balance — so a deadline cannot make funding happen sooner. All it
    // can do is stop watching for it, and stopping is permanent: `run` records
    // Refused, and `ensure::run` is entered from `start()` and nowhere else, so
    // a node that timed out never registers again until something calls start()
    // — which for a desktop app means relaunching it. Acquiring native balance
    // is a bridge or an exchange, so the fifteen-minute deadline this replaces
    // failed the ORDINARY case, not an edge one: fund at minute sixteen and the
    // node was dead with no sign of it but a log line.
    //
    // What the deadline did buy was a bound on polling, so that is what backs
    // off instead. The SLEEP stays at TICK whatever the read schedule says:
    // `stop()` joins these workers on a short grace, and a thread parked for
    // five minutes would hold shutdown open for five minutes.
    let mut waited = Duration::ZERO;
    let mut due = Duration::ZERO;
    let mut announced: Option<(u128, u128)> = None;
    loop {
        if superseded(mine) {
            return Ok(());
        }
        if waited >= due {
            // The base fee moves while a wait runs for hours, so the reserve
            // is re-quoted with every balance read but the first, which the
            // quote above just served.
            if waited > Duration::ZERO {
                let (r, b) = fee_reserve(prov.fee_state());
                if std::mem::discriminant(&b) != std::mem::discriminant(&basis) {
                    log_basis(&registry.canonical, r, b);
                }
                (reserve, basis) = (r, b);
                required = price.saturating_add(reserve);
            }
            match prov.payer_balance() {
                Ok(balance) if balance >= required => break,
                Ok(balance) => {
                    // Announce only when a number MOVES. A wait of hours then
                    // costs a handful of lines rather than one per read, and a
                    // partial transfer — the case where somebody sent the price
                    // and not the fee reserve — still shows up.
                    if announced != Some((balance, required)) {
                        eprintln!(
                            "provision {}: waiting for {payer} to hold {required} native \
                             ({price} price + {reserve} fee reserve); it holds {balance}",
                            registry.canonical
                        );
                        announced = Some((balance, required));
                    }
                    // Refresh the detail too: get_membership_state is the only
                    // channel that can tell a user their node is waiting on an
                    // account, and how far off it is.
                    record(
                        &registry.canonical,
                        Step::AwaitingFunding,
                        &format!(
                            "{payer} needs {required} native \
                             ({price} price + {reserve} fee reserve); it holds {balance}"
                        ),
                    );
                }
                // NOT treated as zero: an unreachable sequencer is not a broke
                // account, and it must not look like one.
                Err(e) => eprintln!("provision {}: balance read failed: {}", registry.canonical, e.message),
            }
            due = waited + read_interval(waited);
        }
        std::thread::sleep(TICK);
        waited = waited.saturating_add(TICK);
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

fn log_basis(registry: &str, reserve: u128, basis: ReserveBasis) {
    match basis {
        ReserveBasis::Quote(height) => eprintln!(
            "provision {registry}: fee reserve {reserve} from the chain's fee quote at height \
             {height}"
        ),
        ReserveBasis::Fallback => eprintln!(
            "provision {registry}: no fee quote from the registry module; reserving the fixed \
             {reserve}"
        ),
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

    /// Only one provisioning pass may be live. `start()` detaches a warm task
    /// still in flight and the worker API gives that body no generation to
    /// check, so without this a parked pass would poll for the life of the
    /// process — and every configureRln, which is every delivery bring-up,
    /// would add one more.
    #[test]
    fn a_later_pass_supersedes_the_one_still_waiting() {
        let first = EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(!superseded(first), "the only pass must not think itself stale");

        let second = EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(
            superseded(first),
            "the earlier pass must stand down once a later start() takes a ticket"
        );
        assert!(!superseded(second), "the newest pass is the one that runs");

        // And the newest is the right one to keep: it carries the registries
        // and rate the latest start() named, which an older pass never sees.
        assert!(second > first);
    }

    /// The funding wait has no deadline, so the read schedule is the only thing
    /// bounding what an indefinite wait costs. Two properties matter and
    /// neither is obvious from the arithmetic.
    #[test]
    fn the_funding_read_schedule_relaxes_and_never_spins() {
        let probes = [0, 5, 59, 60, 120, 599, 600, 3600, 86_400];
        let mut previous = Duration::ZERO;
        for secs in probes {
            let interval = read_interval(Duration::from_secs(secs));
            // Never zero: a zero interval turns the TICK loop into a read every
            // five seconds forever, which is the cost the backoff exists to
            // avoid once a wait is measured in hours.
            assert!(
                interval >= TICK,
                "at {secs}s the schedule returned {interval:?}, below one tick"
            );
            // Monotonic: waiting longer must never poll HARDER. A schedule that
            // tightened again would make the cheap case the long one.
            assert!(
                interval >= previous,
                "at {secs}s the schedule tightened from {previous:?} to {interval:?}"
            );
            previous = interval;
        }
        // The first minute stays tight so an operator's script — which
        // transfers as soon as this module publishes the account — is not held
        // up by a backoff meant for human latency.
        assert_eq!(read_interval(Duration::ZERO), TICK);
        // And a day in, it is reading twelve times an hour, not 720.
        assert_eq!(
            read_interval(Duration::from_secs(86_400)),
            Duration::from_secs(300)
        );
    }

    /// A devnet `getFeeState` quote (base fee 8, next-block ceiling 9).
    fn devnet_quote() -> serde_json::Value {
        serde_json::json!({
            "height": 15082, "base_fee_exec": 8, "base_fee_stor": 8,
            "next_base_fee_exec_floor": 8, "next_base_fee_exec_ceiling": 9,
            "next_base_fee_stor_floor": 8, "next_base_fee_stor_ceiling": 9,
            "max_gas_exec": 10_000_000, "max_gas_stor": 1_000_000,
        })
    }

    /// The reserve is the chain's own formula at the quoted ceiling, times the
    /// headroom — not the wallet's cap, which is 3.5x more at this base fee.
    #[test]
    fn the_reserve_is_sized_from_the_quoted_ceiling() {
        let (reserve, basis) = fee_reserve(Ok(devnet_quote()));
        assert_eq!(basis, ReserveBasis::Quote(15082));
        // (10M gas x 9 + 100k bytes x 9) x 2.
        assert_eq!(reserve, 181_800_000);
        assert!(reserve < FALLBACK_FEE_RESERVE);
    }

    /// The headroom is applied once, to the whole reserve, and a rise in the
    /// quoted ceiling moves the reserve in step.
    #[test]
    fn the_headroom_multiplies_the_quoted_reserve() {
        let unmargined = DECLARED_GAS_LIMIT * 9 + ASSUMED_DATA_BYTES * 9;
        assert_eq!(fee_reserve_from(&devnet_quote()), Some(unmargined * BASE_FEE_HEADROOM));
        let mut dearer = devnet_quote();
        dearer["next_base_fee_exec_ceiling"] = 18.into();
        dearer["next_base_fee_stor_ceiling"] = 18.into();
        assert_eq!(fee_reserve_from(&dearer), Some(unmargined * 2 * BASE_FEE_HEADROOM));
    }

    /// No quote — an older sibling without get_fee_state, "", a transport
    /// error, a reply that is not a quote — is the pre-0.10.0 behaviour
    /// exactly: the wallet's fixed 646.4M cap.
    #[test]
    fn no_quote_falls_back_to_the_fixed_reserve() {
        assert_eq!(FALLBACK_FEE_RESERVE, 646_400_000);
        let fallback = (FALLBACK_FEE_RESERVE, ReserveBasis::Fallback);
        let failure = ApiError::new(ErrorKind::ProviderFailure, "get_fee_state failed");
        assert_eq!(fee_reserve(Err(failure)), fallback);
        assert_eq!(fee_reserve(Ok(serde_json::json!("garbage"))), fallback);
        assert_eq!(fee_reserve(Ok(serde_json::json!({}))), fallback);
        let mut partial = devnet_quote();
        partial.as_object_mut().unwrap().remove("next_base_fee_stor_ceiling");
        assert_eq!(fee_reserve(Ok(partial)), fallback);
        let mut stringly = devnet_quote();
        stringly["next_base_fee_exec_ceiling"] = "9".into();
        assert_eq!(fee_reserve(Ok(stringly)), fallback);
    }

    /// The gate this module exists to get right. The fee reserve dominates the
    /// price by two orders of magnitude or more, whichever way it is sized, so
    /// an account sized for the price alone cannot transact — and the failure
    /// it would hit is a bare "Incorrect fee" from the sequencer, naming
    /// neither number.
    #[test]
    fn affordability_counts_the_fee_reserve_not_just_the_price() {
        let price = 100u128 * 10_000; // rate 100 at the deployed price
        let (quoted, _) = fee_reserve(Ok(devnet_quote()));
        for reserve in [quoted, FALLBACK_FEE_RESERVE] {
            assert!(
                reserve > price * 100,
                "if the reserve ever stops dwarfing the price, revisit this gate: \
                 reserve {reserve}, price {price}"
            );
            // An account holding exactly the price is the case that used to
            // pass a naive check and then fail on chain.
            assert!(price < price.saturating_add(reserve));
        }
    }

    /// Neither an absurd quote nor an absurd registry price may wrap; an
    /// unaffordable number is a correct answer, a wrapped small one is not.
    #[test]
    fn a_saturating_price_or_quote_stays_unaffordable() {
        let mut absurd = devnet_quote();
        absurd["next_base_fee_exec_ceiling"] = u64::MAX.into();
        absurd["next_base_fee_stor_ceiling"] = u64::MAX.into();
        let (reserve, _) = fee_reserve(Ok(absurd));
        assert!(reserve > FALLBACK_FEE_RESERVE);
        assert_eq!(u128::MAX.saturating_add(reserve), u128::MAX);
        assert_eq!(u128::MAX.saturating_add(FALLBACK_FEE_RESERVE), u128::MAX);
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
