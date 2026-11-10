//! Provisioning a membership the node was not given.
//!
//! A consumer that needs RLN to send should not have to know whether a
//! membership exists or has to be created. `start()` names the registries this
//! node will prove against; everything after that — waiting for the wallet,
//! waiting for it to be funded, pricing the registration, submitting it — is
//! this module's work, not the caller's.
//!
//! One account and one asset keeps this short enough to do automatically: no
//! derived holding account, faucet claim, second balance or deployment policy.
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

use crate::delegated::DelegatedOptions;
use crate::error::{ApiError, ErrorKind};
use crate::lifecycle::{granted_by, MembershipState};
use crate::register::{discovery_can_retry, register_scoped};
use crate::registry_id;
use crate::scope::{backend_of, records_for_registry};
use crate::worker;

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

/// How long the pass holds for one registry's submitted registration to leave
/// `pending` before it submits the next registry's. A bound, not a deadline:
/// past it the pass moves on and the next submit takes its chances.
const CONFIRM_HOLD: Duration = Duration::from_secs(900);

/// Slack `DELEGATE_HOLD` keeps past a delegated record's confirmation
/// deadline, so the poller fails an unseen record before the pass stops
/// waiting for it.
const DELEGATE_HOLD_MARGIN: Duration = Duration::from_secs(80);

/// How long a delegated registration may stay `pending` before the pass
/// falls back to a funded one. Longer than a delegated record's own
/// confirmation deadline (the gifter client's whole budget plus the
/// confirmation window), so a live poller has already settled the record
/// when it expires; it bounds the wait only if the poller is not running.
/// A still-pending record short-circuits the funded register (one live
/// record per scope).
const DELEGATE_HOLD: Duration = crate::provider::GIFTER_REQUEST_TIMEOUT
    .saturating_add(Duration::from_secs(
        crate::lifecycle::CONFIRMATION_WINDOW_SECS,
    ))
    .saturating_add(DELEGATE_HOLD_MARGIN);
/// How long a granted gift waits for the allocator's reply to name the
/// granter after the registry already confirmed it.
const ATTRIBUTION_HOLD: Duration = Duration::from_secs(20);

/// Seconds between asks of the allocator after a discovery miss (no
/// allocator advertising the registry yet, no peer to search through).
pub(crate) static DISCOVERY_RETRY_SECS: AtomicU64 = AtomicU64::new(60);

fn discovery_retry_every() -> Duration {
    Duration::from_secs(DISCOVERY_RETRY_SECS.load(Ordering::SeqCst))
}

/// One registry's provisioning order: its allocator first, when `start()`
/// configured one, then the funded registration.
#[derive(Clone, Debug)]
pub(crate) struct Provision {
    pub(crate) registry: String,
    pub(crate) rate_limit: u64,
    pub(crate) allocator: Option<DelegatedOptions>,
}

/// Which provisioning pass is the current one.
///
/// `worker::start()` spawns a fresh warm task and DETACHES any still in
/// flight — the worker API hands that body no generation of its own, and a
/// repeated `start()` (which is every `configureRln`, so every delivery
/// bring-up) never sets the stopped flag. So a superseded pass has nothing to
/// notice, and, the funding wait having no deadline, it would otherwise
/// poll for the rest of the process's life, one more each time.
///
/// Every pass takes a ticket on entry and both waits check it, so exactly one
/// pass is ever live and the newest wins — which is the right one, because it
/// carries every registry in force after the latest `start()`, at the rate
/// each was configured with.
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Should this pass stop — because the module stopped, or because a later
/// `start()` or `stop()` superseded it?
pub(crate) fn superseded(mine: u64) -> bool {
    worker::is_stopped() || EPOCH.load(Ordering::SeqCst) != mine
}

/// Take the next ticket: every pass in flight is superseded from here on.
/// `start()` and `stop()` both call it, whether or not a pass follows — a
/// pass parked across a stop and a `start({"provision":false})` must end too.
pub(crate) fn supersede() -> u64 {
    EPOCH.fetch_add(1, Ordering::SeqCst) + 1
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

/// The execution gas limit the lez module's wallet declares for a registration:
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

/// The reserve when the lez module gives no fee quote (no `get_fee_state`,
/// unreachable, malformed reply): the wallet's own declared cap,
/// `(gas_limit + ASSUMED_DATA_BYTES) x ASSUMED_BASE_FEE (64)`, ~646M.
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
    let ceiling = |key: &str| {
        quote
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .map(u128::from)
    };
    let exec = ceiling("next_base_fee_exec_ceiling")?;
    let stor = ceiling("next_base_fee_stor_ceiling")?;
    Some(
        DECLARED_GAS_LIMIT
            .saturating_mul(exec)
            .saturating_add(ASSUMED_DATA_BYTES.saturating_mul(stor))
            .saturating_mul(BASE_FEE_HEADROOM),
    )
}

/// The reserve from the lez module's live quote, or `FALLBACK_FEE_RESERVE`.
fn fee_reserve(quote: Result<serde_json::Value, ApiError>) -> (u128, ReserveBasis) {
    let computed = quote.ok().and_then(|q| {
        let height = q
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        fee_reserve_from(&q).map(|r| (r, ReserveBasis::Quote(height)))
    });
    computed.unwrap_or((FALLBACK_FEE_RESERVE, ReserveBasis::Fallback))
}

/// How a delegated registration ended, for the pass to act on.
enum Delegated {
    /// The allocator's membership is live on the registry; the pass is done.
    Granted,
    /// The keystore is locked: no credential can be minted for a gift or a
    /// funded registration alike, so the funded fallback would only wait for
    /// a payer to be funded for nothing.
    Locked(String),
    /// Nothing was granted; `provision_one` falls back to a funded registration.
    Refused(String),
    Superseded,
}

/// Ask the registry's allocator for a membership through the wire method's
/// own delegated path (`register_scoped`: the in-flight guard, the poller and
/// the registry cross-check come along), then hold until the record settles:
/// `Active` via the poller's registry read-back, `Failed` via the gifter
/// client's reply (`gifter_failed: …`) or the confirmation window.
fn delegate_one(
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
    allocator: &DelegatedOptions,
    mine: u64,
) -> Delegated {
    let who = allocator_who(registry, allocator);
    record(
        &registry.canonical,
        Step::Delegating,
        format!("asking {who}"),
    );
    let store = crate::sealed_store::store::current_or_uninit();
    let mut reply =
        match register_scoped(store, registry, REGISTRY_WIDE, rate_limit, Some(allocator)) {
            Ok(v) => v,
            Err(e) if e.kind == ErrorKind::Locked => {
                return Delegated::Locked(format!("{who}: {}", e.message))
            }
            // Not sent: the gifter module missing, options the registry refuses.
            Err(e) => return Delegated::Refused(format!("{who}: {}", e.message)),
        };
    let hash = match reply
        .get_mut("membership_hash")
        .map(serde_json::Value::take)
    {
        Some(serde_json::Value::String(h)) => h,
        _ => String::new(),
    };
    let started = Instant::now();
    let mut attribution_wait = Duration::ZERO;
    loop {
        if superseded(mine) {
            return Delegated::Superseded;
        }
        let record_now = crate::sealed_store::store::current().and_then(|s| {
            s.membership(&hash)
                .filter(|r| r.identity.registry_id == registry.canonical)
        });
        match record_now {
            Some(r) if r.cache.state.is_usable() => {
                // The registry can confirm the gift before the allocator's
                // reply names who granted it: give that reply a few ticks.
                let by = match granted_by(&hash) {
                    Some(peer) => format!("allocator {peer}"),
                    None if attribution_wait < ATTRIBUTION_HOLD => {
                        attribution_wait += TICK;
                        std::thread::sleep(TICK);
                        continue;
                    }
                    None => "an allocator".to_string(),
                };
                record(
                    &registry.canonical,
                    Step::Done,
                    format!("gifted by {by} at leaf {}", r.cache.leaf_index.unwrap_or(0)),
                );
                eprintln!(
                    "provision {}: {by} registered a registry-wide membership at rate {rate_limit}",
                    registry.canonical
                );
                return Delegated::Granted;
            }
            Some(r) if r.cache.state == MembershipState::Pending => {}
            Some(r) => {
                return Delegated::Refused(match r.cache.failed_reason.as_deref() {
                    Some(why) => format!("{who}: {why}"),
                    None => format!("{who}: record went {:?}", r.cache.state),
                });
            }
            // The store was republished under the pass; keep looking until the hold ends.
            None => {}
        }
        if started.elapsed() >= DELEGATE_HOLD {
            return Delegated::Refused(format!(
                "{who}: no answer within {}s",
                DELEGATE_HOLD.as_secs()
            ));
        }
        std::thread::sleep(TICK);
    }
}

/// The allocator a pass asks, as its log lines and fallback reasons name it.
fn allocator_who(
    registry: &registry_id::CanonicalRegistryId,
    allocator: &DelegatedOptions,
) -> String {
    match (allocator.discover, allocator.gifter_peer_id.is_empty()) {
        (true, true) => format!("a discovered allocator for {}", registry.canonical),
        (true, false) => format!(
            "a discovered allocator for {}, else allocator {} at {}",
            registry.canonical, allocator.gifter_peer_id, allocator.gifter_multiaddr
        ),
        (false, _) => format!(
            "allocator {} at {}",
            allocator.gifter_peer_id, allocator.gifter_multiaddr
        ),
    }
}

/// What the task is waiting on, for `get_membership_state` to surface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Step {
    /// Asking the registry's allocator (the RLN Membership Allocation
    /// Protocol) for a gifted membership.
    Delegating,
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
            Step::Delegating => "delegating",
            Step::WaitingForWallet => "waiting_for_wallet",
            Step::AwaitingFunding => "awaiting_funding",
            Step::Registering => "registering",
            Step::Done => "done",
            Step::Refused => "refused",
        }
    }
}

/// Provision a membership for each registry in force after `start()`, at
/// that registry's rate.
///
/// Errors are logged and abandoned per registry rather than propagated: this
/// runs detached, there is nobody to return to, and one unreachable registry
/// must not stop the others.
///
/// Runs under a ticket `start()` already took (`supersede`), so the pass
/// is the one that call started and nothing between the two superseded it.
pub(crate) fn run_with(registries: Vec<Provision>, ticket: u64) {
    run_as(registries, ticket)
}

/// `run_with` for one registry asked for OUTSIDE `start()` — `ensure_membership`
/// from a UI. It runs under `ticket`, the one its `ActivePass::claim` marker
/// was taken under, instead of taking a new one, so it supersedes nothing: a
/// `start()` pass parked on another registry's funding keeps waiting. The next
/// `start()` after the claim ends it like any other pass, and `is_running`
/// keeps two from working the same registry at once.
pub(crate) fn run_alongside(registry: String, rate_limit: u64, ticket: u64) {
    let allocator = crate::config::allocator_for(&registry);
    run_as(
        vec![Provision {
            registry,
            rate_limit,
            allocator,
        }],
        ticket,
    )
}

fn run_as(registries: Vec<Provision>, mine: u64) {
    for Provision {
        registry: raw,
        rate_limit,
        allocator,
    } in registries
    {
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
        let _active = ActivePass::enter_with(&registry.canonical, mine);
        // Read per registry rather than captured once: this runs detached and
        // the store can be republished under it (on_context_ready re-opening
        // it), so a handle taken at spawn time could outlive its store.
        match provision_one(&registry, rate_limit, allocator.as_ref(), mine) {
            Ok(()) => wait_confirmed(&registry, mine),
            Err(e) => {
                eprintln!("provision {}: {}", registry.canonical, e.message);
                record(&registry.canonical, Step::Refused, e.message);
            }
        }
    }
}

/// Does this node hold a registration on this registry that the chain has
/// not confirmed yet?
pub(crate) fn pending_membership_present(registry: &registry_id::CanonicalRegistryId) -> bool {
    crate::sealed_store::store::current()
        .map(|s| {
            s.any_for_registry(&registry.canonical, |r| {
                !r.quarantined && r.cache.state == crate::lifecycle::MembershipState::Pending
            })
        })
        .unwrap_or(false)
}

/// One payer, one nonce: a registration submitted while the previous one is
/// still pending is signed with the nonce that one has yet to consume, and
/// the sequencer drops it without a word — the second registry's membership
/// then stays `pending` for good. So the pass holds after each submit until
/// the registry's membership has left pending, the pass is superseded, or
/// `CONFIRM_HOLD` runs out.
pub(crate) fn wait_confirmed(registry: &registry_id::CanonicalRegistryId, mine: u64) {
    let started = Instant::now();
    while pending_membership_present(registry) {
        if superseded(mine) || started.elapsed() >= CONFIRM_HOLD {
            return;
        }
        std::thread::sleep(TICK);
    }
}

/// Whether any registry holds a registration the chain has not confirmed:
/// every pass submits from the one payer, so one pass's pending registration
/// is every other pass's nonce.
pub(crate) fn any_pending_membership() -> bool {
    crate::sealed_store::store::current()
        .map(|s| s.has_pending())
        .unwrap_or(false)
}

/// `wait_confirmed` across every registry, before a submit: an
/// `ensure_membership` pass beside a `start()` pass must not sign with the
/// nonce the other one's registration has yet to consume.
fn wait_confirmed_any(mine: u64) {
    let started = Instant::now();
    while any_pending_membership() {
        if superseded(mine) || started.elapsed() >= CONFIRM_HOLD {
            return;
        }
        std::thread::sleep(TICK);
    }
}

/// The pass ticket in force — what a pass started now would hold.
#[cfg(test)]
pub(crate) fn ticket_in_force() -> u64 {
    EPOCH.load(Ordering::SeqCst)
}

/// Does this node already have a membership on this registry — ANY
/// membership, whatever scope it was registered under?
///
/// Any live record counts, whatever its scope (not
/// `scope_matches(r, REGISTRY_WIDE)`): a second registration splits the
/// registry's rate budget and moves the tree root, invalidating proofs in
/// flight.
///
/// Re-asked on every balance read and before registering, since a hand
/// registration (`register_membership` from a UI) can land during the
/// funding wait.
pub(crate) fn live_membership_present(registry: &registry_id::CanonicalRegistryId) -> bool {
    crate::sealed_store::store::current()
        .map(|s| {
            s.any_for_registry(&registry.canonical, |r| {
                !r.quarantined && r.cache.state.is_live()
            })
        })
        .unwrap_or(false)
}

/// What a pass finds on a registry it is about to provision.
enum Live {
    /// A usable membership: nothing to do.
    Usable,
    /// A registration still pending past `DELEGATE_HOLD`: left to the poller.
    StillPending,
    /// The pending registration the pass waited on failed: provision anew,
    /// with its reason as the fallback reason.
    Failed(String),
    Superseded,
    None,
}

/// A pending registration on the registry is an earlier pass's work (a start
/// superseded mid-gift, a register_membership call): wait for its verdict
/// instead of calling the registry provisioned — a gift the allocator then
/// refuses would otherwise leave the node with nothing and the step "done".
fn settle_live(registry: &registry_id::CanonicalRegistryId, mine: u64) -> Live {
    let started = Instant::now();
    let mut saw_pending = false;
    loop {
        let Some(store) = crate::sealed_store::store::current() else {
            return Live::None;
        };
        let records: Vec<_> = records_for_registry(&store, registry)
            .into_iter()
            .filter(|r| !r.quarantined)
            .collect();
        if records.iter().any(|r| r.cache.state.is_usable()) {
            return Live::Usable;
        }
        if !records
            .iter()
            .any(|r| r.cache.state == MembershipState::Pending)
        {
            if !saw_pending {
                return Live::None;
            }
            let why = records
                .iter()
                .filter(|r| r.cache.state == MembershipState::Failed)
                .max_by_key(|r| r.identity.submitted_at)
                .and_then(|r| r.cache.failed_reason.clone())
                .unwrap_or_else(|| "the pending registration failed".to_string());
            return Live::Failed(why);
        }
        if !saw_pending {
            saw_pending = true;
            record(
                &registry.canonical,
                Step::Delegating,
                "waiting for an earlier registration to settle",
            );
        }
        if superseded(mine) {
            return Live::Superseded;
        }
        if started.elapsed() >= DELEGATE_HOLD {
            return Live::StillPending;
        }
        std::thread::sleep(TICK);
    }
}

/// The allocator asked once more after a discovery miss: true when the pass
/// ends here (a grant, a locked keystore, a newer pass).
///
/// Discovery is probed first and the request — which mints a credential and
/// leaves a record — is sent only when an allocator is listed. A probe that
/// finds none becomes the fallback reason; `discovery unavailable` ends the
/// asking; a probe that could not be made is tried next interval. A refusal
/// that is still a discovery miss becomes the fallback reason; any other
/// refusal ends the asking and leaves the fallback reason as it was.
fn ask_again(
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
    retry: &mut Option<&DelegatedOptions>,
    mine: u64,
) -> bool {
    let Some(a) = *retry else { return false };
    let who = allocator_who(registry, a);
    let next = discovery_retry_every().as_secs();
    let miss = match crate::provider::gifter_discover_async(registry, a.auth_type.as_deref()) {
        Err(e) => {
            eprintln!(
                "provision {}: discover failed: {}; probing again in {next}s",
                registry.canonical, e.message
            );
            return false;
        }
        Ok(found) => match (found.error, found.joined, found.candidates) {
            (Some(e), _, _) if e.contains("discovery unavailable") => {
                eprintln!(
                    "provision {}: {who}: {e}; no further allocator asks this pass",
                    registry.canonical
                );
                *retry = None;
                return false;
            }
            (Some(e), _, _) if discovery_can_retry(&e) => Some(e),
            (Some(e), _, _) => {
                eprintln!(
                    "provision {}: discover failed: {e}; probing again in {next}s",
                    registry.canonical
                );
                return false;
            }
            (None, Some(false), _) => Some(format!(
                "discovery not joined ({} peers)",
                found.peers.unwrap_or(0)
            )),
            (None, _, 0) => Some(match found.peers {
                Some(n) => format!("discovery: no allocator yet ({n} peers)"),
                None => "discovery: no allocator yet".to_string(),
            }),
            (None, _, _) => None,
        },
    };
    if let Some(why) = miss {
        let why = format!("{who}: {why}");
        eprintln!(
            "provision {}: {why}; probing again in {next}s",
            registry.canonical
        );
        set_fallback(&registry.canonical, why);
        return false;
    }
    match delegate_one(registry, rate_limit, a, mine) {
        Delegated::Granted => {
            clear_fallback(&registry.canonical);
            true
        }
        Delegated::Superseded => true,
        Delegated::Locked(why) => {
            record(
                &registry.canonical,
                Step::AwaitingFunding,
                "keystore locked",
            );
            eprintln!(
                "provision {}: {why} — unlock the keystore and restart (or ensure_membership) to provision",
                registry.canonical
            );
            true
        }
        Delegated::Refused(why) if discovery_can_retry(&why) => {
            eprintln!(
                "provision {}: {why}; probing again in {next}s",
                registry.canonical
            );
            set_fallback(&registry.canonical, why);
            false
        }
        Delegated::Refused(why) => {
            eprintln!(
                "provision {}: {why}; no further allocator asks this pass",
                registry.canonical
            );
            *retry = None;
            false
        }
    }
}

fn provision_one(
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
    allocator: Option<&DelegatedOptions>,
    mine: u64,
) -> Result<(), ApiError> {
    let entered = Instant::now();
    clear_fallback(&registry.canonical);
    match settle_live(registry, mine) {
        Live::Usable => {
            record(
                &registry.canonical,
                Step::Done,
                "membership already present",
            );
            return Ok(());
        }
        Live::StillPending => {
            record(&registry.canonical, Step::Done, "membership pending");
            return Ok(());
        }
        Live::Superseded => return Ok(()),
        Live::Failed(why) => {
            eprintln!(
                "provision {}: earlier registration failed ({why}); provisioning anew",
                registry.canonical
            );
            set_fallback(&registry.canonical, why);
        }
        Live::None => {}
    }
    if let Some(s) = crate::sealed_store::store::current() {
        let records = records_for_registry(&s, registry);
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
                format!(
                    "membership {} is quarantined (local metadata failed its MAC); \
                     not registering a replacement — inspect with get_memberships, \
                     then register_membership deliberately",
                    r.hash
                ),
            );
            return Ok(());
        }
    }

    // 0. The allocator, when one is configured: a gift costs this node
    //    nothing and needs no wallet, so it is asked first; whatever stops it
    //    — the gifter module not loaded, the allocator unreachable, its
    //    refusal — is recorded as the fallback reason and the funded steps
    //    below run as they always have. A discovery miss of a discovering
    //    allocator keeps it in `retry`: probed again every
    //    `DISCOVERY_RETRY_SECS` while the payer is unfunded, and once before
    //    paying when the funding wait probed nothing (`ask_again`). A pinned
    //    pair alone has nothing to probe.
    let mut retry: Option<&DelegatedOptions> = None;
    if let Some(a) = allocator {
        match delegate_one(registry, rate_limit, a, mine) {
            Delegated::Granted | Delegated::Superseded => return Ok(()),
            Delegated::Locked(why) => {
                record(
                    &registry.canonical,
                    Step::AwaitingFunding,
                    "keystore locked",
                );
                eprintln!(
                    "provision {}: {why} — unlock the keystore and restart (or ensure_membership) to provision",
                    registry.canonical
                );
                return Ok(());
            }
            Delegated::Refused(why) => {
                eprintln!(
                    "provision {}: {why}; falling back to a funded registration",
                    registry.canonical
                );
                if a.discover && discovery_can_retry(&why) {
                    retry = Some(a);
                }
                set_fallback(&registry.canonical, why);
            }
        }
    }

    let backend = backend_of(registry)?;

    // 1. The wallet.
    //
    // No deadline, for the same reason as the funding wait. An unreachable
    // sequencer is an outage, not a verdict: the lez module stays `pending` and
    // retries the open, and stopping is permanent (`ensure::run_with` is
    // entered from `start()` and nowhere else).
    //
    // `failed` is reserved for causes waiting cannot fix: no wallet home, no
    // sequencer configured, an unimportable payer key.
    record(&registry.canonical, Step::WaitingForWallet, "");
    let began = Instant::now();
    let mut noticed = false;
    loop {
        if superseded(mine) {
            return Ok(());
        }
        // An Err is the module not answering calls yet — indistinguishable
        // from "pending" this early, and worth the same wait.
        if let Ok(status) = backend.payer.wallet_status() {
            match status.get("state").and_then(|x| x.as_str()) {
                Some("ready") => break,
                Some("failed") => {
                    let detail = status.get("detail").and_then(|x| x.as_str()).unwrap_or("");
                    return Err(ApiError::new(
                        ErrorKind::ProviderFailure,
                        format!("the registry module's wallet failed to come up: {detail}"),
                    ));
                }
                Some("pending") => {
                    // Surface the lez module's own reason once the wait stops
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
                            format!("{}s: {detail}", waited.as_secs()),
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

    // A registry that is not on this chain cannot be provisioned however long
    // the funding wait runs: a reset network, a registry from another program
    // version. Say so now, instead of failing later on an empty read or
    // waiting for funds that would buy nothing.
    if let Some(msg) = crate::provider::registry_problem(backend.registry, registry) {
        return Err(ApiError::new(ErrorKind::UnknownRegistry, msg));
    }

    // 2. The price and the fee reserve. Read before the funding wait so the
    //    log can name the number being waited for.
    let price = registration_price(backend.registry, registry, rate_limit)?;
    let (mut reserve, mut basis) = fee_reserve(backend.payer.fee_state());
    log_basis(&registry.canonical, reserve, basis);
    let mut required = price.saturating_add(reserve);

    // 3. Funding. Nothing this module can do brings it about — no program
    //    mints native balance — so this waits rather than acts, and says
    //    which account to send to.
    let payer = backend
        .payer
        .wallet_status()
        .ok()
        .and_then(|s| s.get("payer").and_then(|p| p.as_str()).map(str::to_owned))
        .unwrap_or_default();
    record_funding(
        &registry.canonical,
        format!("{payer} needs {required} native ({price} price + {reserve} fee reserve)"),
        Funding {
            // OWNERSHIP: the snapshot owns a copy; the wait keeps reporting `payer`.
            payer: payer.clone(),
            required,
            price,
            fee_reserve: reserve,
            balance: None,
        },
    );
    // No deadline: acquiring native balance (a bridge, an exchange) takes
    // arbitrary time, and giving up is permanent (`ensure::run_with` is entered
    // from `start()` and nowhere else). Polling backs off instead; the SLEEP
    // stays at TICK whatever the read schedule says, since `stop()` joins
    // workers on a short grace.
    let mut waited = Duration::ZERO;
    let mut due = Duration::ZERO;
    let mut announced: Option<(u128, u128)> = None;
    let mut asked_while_waiting: Option<Instant> = None;
    loop {
        if superseded(mine) {
            return Ok(());
        }
        if retry.is_some()
            && asked_while_waiting.unwrap_or(entered).elapsed() >= discovery_retry_every()
        {
            if ask_again(registry, rate_limit, &mut retry, mine) {
                return Ok(());
            }
            asked_while_waiting = Some(Instant::now());
            // A request replaces the funding snapshot; a balance read restores it.
            due = waited;
        }
        if waited >= due {
            // A membership that arrived by another route — register_membership
            // from a UI, a gift — ends the wait: funding one more would be the
            // second registration the entry check exists to prevent.
            if live_membership_present(registry) {
                record(
                    &registry.canonical,
                    Step::Done,
                    "membership already present",
                );
                return Ok(());
            }
            // The base fee moves while a wait runs for hours, so the reserve
            // is re-quoted with every balance read but the first, which the
            // quote above just served.
            if waited > Duration::ZERO {
                let (r, b) = fee_reserve(backend.payer.fee_state());
                if std::mem::discriminant(&b) != std::mem::discriminant(&basis) {
                    log_basis(&registry.canonical, r, b);
                }
                (reserve, basis) = (r, b);
                required = price.saturating_add(reserve);
            }
            match backend.payer.payer_balance() {
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
                    // Refresh the snapshot too: get_membership_state is the
                    // only channel that can tell a user their node is waiting
                    // on an account, and how far off it is.
                    record_funding(
                        &registry.canonical,
                        format!(
                            "{payer} needs {required} native \
                             ({price} price + {reserve} fee reserve); it holds {balance}"
                        ),
                        Funding {
                            // OWNERSHIP: the snapshot owns a copy; the wait keeps reporting
                            // `payer`.
                            payer: payer.clone(),
                            required,
                            price,
                            fee_reserve: reserve,
                            balance: Some(balance),
                        },
                    );
                }
                // NOT treated as zero: an unreachable sequencer is not a broke
                // account, and it must not look like one.
                Err(e) => eprintln!(
                    "provision {}: balance read failed: {}",
                    registry.canonical, e.message
                ),
            }
            due = waited + read_interval(waited);
        }
        std::thread::sleep(TICK);
        waited = waited.saturating_add(TICK);
    }

    // 4. Register. The same entry point the wire method uses, so the
    //    idempotency, the in-flight guard and the confirmation poller all
    //    come along. `register_scoped`'s own short-circuit only sees records
    //    of ITS scope, so the any-scope check runs once more here. A pass
    //    superseded during the funding wait (a stop, a later start) submits
    //    nothing: the registry is the newer pass's, or nobody's.
    if superseded(mine) {
        return Ok(());
    }
    // A pass funded before its first retry probes once more, no sooner than
    // `DISCOVERY_RETRY_SECS` after it began, before paying.
    if retry.is_some() && asked_while_waiting.is_none() {
        while entered.elapsed() < discovery_retry_every() {
            if superseded(mine) {
                return Ok(());
            }
            std::thread::sleep(TICK.min(discovery_retry_every().saturating_sub(entered.elapsed())));
        }
        if ask_again(registry, rate_limit, &mut retry, mine) {
            return Ok(());
        }
    }
    wait_confirmed_any(mine);
    if superseded(mine) {
        return Ok(());
    }
    if live_membership_present(registry) {
        record(
            &registry.canonical,
            Step::Done,
            "membership already present",
        );
        return Ok(());
    }
    record(&registry.canonical, Step::Registering, "");
    let store = crate::sealed_store::store::current_or_uninit();
    match register_scoped(store, registry, REGISTRY_WIDE, rate_limit, None) {
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
            record(
                &registry.canonical,
                Step::AwaitingFunding,
                "keystore locked",
            );
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
    registry_source: &dyn crate::provider::Registry,
    registry: &registry_id::CanonicalRegistryId,
    rate_limit: u64,
) -> Result<u128, ApiError> {
    let bounds = registry_source.get_registry_bounds(registry)?;
    // A decimal string on the wire, for the same reason the balance is.
    let price_per_unit = bounds
        .get("price_per_unit")
        .and_then(|p| p.as_str())
        .and_then(|p| p.parse::<u128>().ok())
        .ok_or_else(|| {
            ApiError::new(
                ErrorKind::ProviderFailure,
                "registry bounds carry no price_per_unit",
            )
        })?;
    Ok(price_per_unit.saturating_mul(u128::from(rate_limit)))
}

// ---------------------------------------------------------------------------
// Progress, readable through get_membership_state
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

/// The numbers behind an `awaiting_funding` step, as fields rather than only
/// as the sentence `detail` renders them: a UI that wants to show "send
/// `required` to `payer`" — or hand that pair to a wallet app — must not have
/// to parse prose. `balance` is absent until the first balance read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Funding {
    pub(crate) payer: String,
    pub(crate) required: u128,
    pub(crate) price: u128,
    pub(crate) fee_reserve: u128,
    pub(crate) balance: Option<u128>,
}

/// What the provisioning task last reported for a registry.
#[derive(Clone, Debug)]
pub(crate) struct Progress {
    pub(crate) step: Step,
    pub(crate) detail: String,
    /// Only ever set with `Step::AwaitingFunding`.
    pub(crate) funding: Option<Funding>,
    /// Why the registry's allocator did not deliver — set once the pass has
    /// fallen back to the funded steps, kept across the steps recorded after
    /// it, cleared when a new pass begins.
    pub(crate) fallback_reason: Option<String>,
}

/// Per registry: the last step reported and the fallback reason in force.
/// An entry, once recorded, is replaced step by step and never removed.
// OWNERSHIP: written by the passes' threads, read by the state handlers.
static PROGRESS: Mutex<Option<HashMap<String, Progress>>> = Mutex::new(None);

/// Every caller has recorded a step for `registry` earlier in its pass
/// (`delegate_one` records `Delegating` first; `settle_live` records its wait
/// before it can answer `Failed`), so the entry exists.
fn set_fallback(registry: &str, why: impl Into<String>) {
    if let Some(p) = crate::util::lock(&PROGRESS)
        .as_mut()
        .and_then(|m| m.get_mut(registry))
    {
        p.fallback_reason = Some(why.into());
    }
}

fn clear_fallback(registry: &str) {
    if let Some(p) = crate::util::lock(&PROGRESS)
        .as_mut()
        .and_then(|m| m.get_mut(registry))
    {
        p.fallback_reason = None;
    }
}

/// Record a step; the entry's fallback reason stays as it was.
fn record_progress(registry: &str, step: Step, detail: String, funding: Option<Funding>) {
    let mut guard = crate::util::lock(&PROGRESS);
    let map = guard.get_or_insert_with(HashMap::new);
    match map.get_mut(registry) {
        Some(p) => {
            p.step = step;
            p.detail = detail;
            p.funding = funding;
        }
        None => {
            map.insert(
                // OWNERSHIP: the map owns its key, copied on a first step only.
                registry.to_owned(),
                Progress {
                    step,
                    detail,
                    funding,
                    fallback_reason: None,
                },
            );
        }
    }
}

fn record(registry: &str, step: Step, detail: impl Into<String>) {
    record_progress(registry, step, detail.into(), None);
}

fn record_funding(registry: &str, detail: impl Into<String>, funding: Funding) {
    record_progress(
        registry,
        Step::AwaitingFunding,
        detail.into(),
        Some(funding),
    );
}

/// Note that a pass has been asked for, before its thread has recorded
/// anything, so the reply that spawned it already shows a step instead of
/// nothing. The pass overwrites this with its first real step.
pub(crate) fn mark_requested(registry: &str) {
    record(registry, Step::WaitingForWallet, "");
}

/// What provisioning is doing for `registry`, if anything.
///
/// Surfaced on `get_membership_state`'s `unknown` reply, which is otherwise
/// the same answer for "this node was never given a membership" and "this
/// node is three minutes into acquiring one".
pub(crate) fn progress(registry: &str) -> Option<Progress> {
    crate::util::lock(&PROGRESS)
        .as_ref()
        // OWNERSHIP: the reader gets a copy taken under the lock.
        .and_then(|m| m.get(registry).cloned())
}

// ---------------------------------------------------------------------------
// Which registries have a pass in flight right now
// ---------------------------------------------------------------------------
//
// Distinct from PROGRESS on purpose: a superseded or finished pass leaves its
// last step behind for `get_membership_state` to show, so "awaiting_funding"
// in PROGRESS does not mean anyone is still watching the balance. A caller
// that wants to START a pass (ensure_membership) needs the live answer.

/// Registry → the ticket of the pass working it. A newer pass takes the
/// entry over; the older one's marker, dropped later, finds another ticket
/// there and leaves it: a superseded pass must not make the live one look
/// finished.
// OWNERSHIP: entered by the passes' threads and the `ensure_membership` handler.
static ACTIVE: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// RAII marker for a registry's pass; dropped on every exit path of `run_with`'s
/// per-registry body, including a panic unwinding through it.
pub(crate) struct ActivePass(String, u64);

impl ActivePass {
    /// A marker under the ticket in force.
    #[cfg(test)]
    pub(crate) fn enter(registry: &str) -> Self {
        Self::enter_with(registry, EPOCH.load(Ordering::SeqCst))
    }

    pub(crate) fn enter_with(registry: &str, ticket: u64) -> Self {
        // OWNERSHIP: the map and the marker (its Drop looks the entry up) each own the key.
        crate::util::lock(&ACTIVE)
            .get_or_insert_with(HashMap::new)
            .insert(registry.to_owned(), ticket);
        ActivePass(registry.to_owned(), ticket)
    }

    /// The marker, if no pass holds the registry: the check and the entry
    /// under one lock, for a caller about to spawn a pass.
    pub(crate) fn claim(registry: &str) -> Option<Self> {
        let ticket = EPOCH.load(Ordering::SeqCst);
        let mut guard = crate::util::lock(&ACTIVE);
        let map = guard.get_or_insert_with(HashMap::new);
        if map.contains_key(registry) {
            return None;
        }
        // OWNERSHIP: the map and the marker (its Drop looks the entry up) each own the key.
        map.insert(registry.to_owned(), ticket);
        Some(ActivePass(registry.to_owned(), ticket))
    }

    /// The ticket the marker was taken under; the pass it rides with runs under it.
    pub(crate) fn ticket(&self) -> u64 {
        self.1
    }
}

impl Drop for ActivePass {
    fn drop(&mut self) {
        if let Some(map) = crate::util::lock(&ACTIVE).as_mut() {
            if map.get(&self.0) == Some(&self.1) {
                map.remove(&self.0);
            }
        }
    }
}

/// Whether a provisioning pass is currently working on `registry`.
pub(crate) fn is_running(registry: &str) -> bool {
    crate::util::lock(&ACTIVE)
        .as_ref()
        .map(|map| map.contains_key(registry))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ensure;
    use crate::generated::LiblogosRlnModule;
    use crate::test_support::{imp_with_store, seed_membership, TEST_GLOBAL_LOCK};

    #[test]
    fn delegate_hold_outlasts_a_delegated_records_confirmation_deadline() {
        let submitted_at = 1_700_000_000;
        let deadline = crate::register::delegated_confirm_deadline(submitted_at) - submitted_at;
        assert!(DELEGATE_HOLD.as_secs() > deadline);
    }

    /// Only one provisioning pass may be live. `start()` detaches a warm task
    /// still in flight and the worker API gives that body no generation to
    /// check, so without this a parked pass would poll for the life of the
    /// process — and every configureRln, which is every delivery bring-up,
    /// would add one more.
    #[test]
    fn a_later_pass_supersedes_the_one_still_waiting() {
        let first = EPOCH.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(
            !superseded(first),
            "the only pass must not think itself stale"
        );

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
        assert_eq!(
            fee_reserve_from(&devnet_quote()),
            Some(unmargined * BASE_FEE_HEADROOM)
        );
        let mut dearer = devnet_quote();
        dearer["next_base_fee_exec_ceiling"] = 18.into();
        dearer["next_base_fee_stor_ceiling"] = 18.into();
        assert_eq!(
            fee_reserve_from(&dearer),
            Some(unmargined * 2 * BASE_FEE_HEADROOM)
        );
    }

    /// No quote (no get_fee_state, "", a transport error, a reply that is not
    /// a quote) reserves the wallet's fixed 646.4M cap.
    #[test]
    fn no_quote_falls_back_to_the_fixed_reserve() {
        assert_eq!(FALLBACK_FEE_RESERVE, 646_400_000);
        let fallback = (FALLBACK_FEE_RESERVE, ReserveBasis::Fallback);
        let failure = ApiError::new(ErrorKind::ProviderFailure, "get_fee_state failed");
        assert_eq!(fee_reserve(Err(failure)), fallback);
        assert_eq!(fee_reserve(Ok(serde_json::json!("garbage"))), fallback);
        assert_eq!(fee_reserve(Ok(serde_json::json!({}))), fallback);
        let mut partial = devnet_quote();
        partial
            .as_object_mut()
            .unwrap()
            .remove("next_base_fee_stor_ceiling");
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
            // An account holding exactly the price cannot pay the fee.
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

        let p = progress(a).expect("a has progress");
        assert_eq!(p.step, Step::AwaitingFunding);
        assert_eq!(p.step.as_str(), "awaiting_funding");
        assert!(p.detail.contains("646400000"));
        assert!(p.funding.is_none(), "a plain record carries no snapshot");

        assert_eq!(progress(b).expect("b has progress").step, Step::Done);

        // Later steps replace earlier ones rather than accumulating.
        record(a, Step::Done, "submitted");
        assert_eq!(progress(a).expect("a still has progress").step, Step::Done);
    }

    /// The allocator's failure rides on every step the funded fallback
    /// records after it, and a new pass starts clean.
    #[test]
    fn the_fallback_reason_outlives_the_steps_of_its_pass_only() {
        let r = "logos:test:fallback-reason";
        record(r, Step::Delegating, "asking allocator p at /m");
        assert_eq!(progress(r).unwrap().step.as_str(), "delegating");
        assert!(progress(r).unwrap().fallback_reason.is_none());
        set_fallback(
            r,
            "allocator p at /m: gifter_failed: credential already used",
        );
        record(r, Step::WaitingForWallet, "");
        assert_eq!(
            progress(r).unwrap().fallback_reason.as_deref(),
            Some("allocator p at /m: gifter_failed: credential already used")
        );
        record_funding(
            r,
            "x needs 1",
            Funding {
                payer: "x".into(),
                required: 1,
                price: 1,
                fee_reserve: 0,
                balance: None,
            },
        );
        assert!(
            progress(r).unwrap().fallback_reason.is_some(),
            "the funding step keeps it"
        );
        clear_fallback(r);
        assert!(
            progress(r).unwrap().fallback_reason.is_none(),
            "a new pass starts clean"
        );
    }

    /// The funding step carries its numbers as fields, and a later step
    /// drops them: a `done` reply must not keep advertising an amount to
    /// send.
    #[test]
    fn the_funding_snapshot_is_structured_and_does_not_outlive_its_step() {
        let r = "logos:test:funding-snapshot";
        let first = Funding {
            payer: "ab".repeat(32),
            required: 1_000_000 + 182_000_000,
            price: 1_000_000,
            fee_reserve: 182_000_000,
            balance: None,
        };
        record_funding(r, "ab… needs 183000000 native", first.clone());
        let p = progress(r).expect("recorded");
        assert_eq!(p.step, Step::AwaitingFunding);
        assert_eq!(p.funding.as_ref(), Some(&first));

        // A balance read refreshes the snapshot in place.
        let read = Funding {
            balance: Some(1_000_000),
            ..first
        };
        record_funding(r, "…; it holds 1000000", read.clone());
        assert_eq!(progress(r).expect("refreshed").funding, Some(read));

        record(r, Step::Registering, "");
        let p = progress(r).expect("moved on");
        assert_eq!(p.step, Step::Registering);
        assert!(
            p.funding.is_none(),
            "a non-funding step must not carry the snapshot"
        );
    }

    /// `is_running` answers for the pass itself, not for what it last wrote:
    /// a finished pass leaves its step in PROGRESS for readers but must not
    /// look live to a caller deciding whether to start another.
    // A newer pass on the same registry owns the marker: the superseded
    // pass's drop leaves it, and only the owner's drop ends it. A claim is
    // the check and the entry in one step.
    #[test]
    fn a_superseded_pass_cannot_end_the_newer_one() {
        let r = "logos:test:two-passes";
        let older = ActivePass::enter_with(r, 1);
        let newer = ActivePass::enter_with(r, 2);
        drop(older);
        assert!(
            is_running(r),
            "the older marker's drop must not end the newer pass"
        );
        assert!(
            ActivePass::claim(r).is_none(),
            "a running pass refuses a claim"
        );
        drop(newer);
        assert!(!is_running(r));
        let claimed = ActivePass::claim(r).expect("free registry");
        assert!(is_running(r));
        drop(claimed);
        assert!(!is_running(r));
    }

    #[test]
    fn a_pass_is_running_only_while_its_marker_lives() {
        let r = "logos:test:active-marker";
        assert!(!is_running(r));
        {
            let _pass = ActivePass::enter(r);
            assert!(is_running(r));
            record(r, Step::AwaitingFunding, "parked");
        }
        assert!(!is_running(r), "dropping the marker ends the pass");
        assert_eq!(
            progress(r).expect("the last step stays readable").step,
            Step::AwaitingFunding
        );
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
    /// Provisioning counts a live record of any scope. `scope_matches` answers
    /// a different question: does the record back that application.
    #[test]
    fn a_scoped_membership_counts_as_provisioned() {
        let scoped = "aa".repeat(32);
        // A scoped record is not registry-wide; `provision_one` filters on
        // `is_live()` alone and never consults the scope.
        assert!(!crate::scope::scope_matches_for_test(
            &scoped,
            REGISTRY_WIDE
        ));
        assert!(crate::scope::scope_matches_for_test("", REGISTRY_WIDE));
    }

    // A locked keystore with an allocator: the pass says so and stops, instead
    // of waiting for the funded path's wallet and funding for a gift that
    // would have been free once unlocked.
    #[test]
    fn a_locked_keystore_stops_the_pass_before_the_funding_wait() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir =
            std::env::temp_dir().join(format!("rln-locked-allocator-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, _store) = imp_with_store(dir.clone());
        let registry = format!("logos:local:{}", "7d".repeat(32));
        let canonical = registry_id::parse(&registry).unwrap().canonical;
        let allocator = DelegatedOptions::from_allocator_block(
            Some(&serde_json::json!({ "peer_id": "p", "multiaddr": "/m", "discover": false })),
            "x",
        )
        .unwrap();
        ensure::run_with(
            vec![ensure::Provision {
                registry: canonical.clone(),
                rate_limit: 100,
                allocator,
            }],
            ensure::supersede(),
        );
        let step = ensure::progress(&canonical).expect("a step is recorded");
        assert_eq!(step.step, ensure::Step::AwaitingFunding);
        assert_eq!(step.detail, "keystore locked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A start() landing between ensure_membership's claim and its pass body
    // ends that pass: the body runs under the claim's ticket, not the one in
    // force when it gets going.
    #[test]
    fn an_ensure_pass_claimed_before_a_start_is_ended_by_it() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        crate::worker::reset_for_test();
        let dir =
            std::env::temp_dir().join(format!("rln-ensure-claim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        let registry = format!("logos:local:{}", "7f".repeat(32));
        let canonical = registry_id::parse(&registry).unwrap().canonical;
        // A live membership: a pass that runs at all records `Done` at once.
        seed_membership(
            &store,
            "pc",
            &canonical,
            &"57".repeat(32),
            "",
            &"e7".repeat(32),
            MembershipState::Active,
            3,
            100,
        );

        let pass = ActivePass::claim(&canonical).expect("no pass holds the registry");
        ensure::mark_requested(&canonical);
        ensure::supersede();
        ensure::run_alongside(canonical.clone(), 100, pass.ticket());
        let step = ensure::progress(&canonical).expect("a step is recorded");
        assert_eq!(step.step, ensure::Step::WaitingForWallet);
        assert_eq!(step.detail, "");
        drop(pass);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gifter's reply to a request whose allocator was not discovered.
    fn missed(text: &str) -> Result<String, ApiError> {
        Ok(serde_json::json!({ "error": format!("no allocator granted and none is configured: {text}") }).to_string())
    }

    /// A `discover` reply listing `n` allocators.
    fn listed(n: usize) -> Result<String, ApiError> {
        let candidates: Vec<_> = (0..n)
            .map(|i| serde_json::json!({ "peerId": format!("p{i}"), "addrs": ["/m"] }))
            .collect();
        Ok(serde_json::json!({ "serviceId": "s", "candidates": candidates, "joined": true, "peers": 3 }).to_string())
    }

    /// A discovered allocator's grant, with the registry's read-back already
    /// in: every pending record goes active at leaf 5.
    fn granted(args: &serde_json::Value) -> Result<String, ApiError> {
        let store = crate::sealed_store::store::current().expect("a published store");
        for r in store.pending_records() {
            store
                .update_cache(&r.hash, |m| {
                    m.state = MembershipState::Active;
                    m.leaf_index = Some(5);
                })
                .unwrap();
        }
        Ok(serde_json::json!({ "leaf_index": 5, "gifterPeerId": "p", "discovered": true, "config_account": args["config"] }).to_string())
    }

    type Answers =
        dyn Fn(&str, usize, &serde_json::Value, &str) -> Result<String, ApiError> + Send + Sync;

    /// A pass over the fake backend, its payer holding `balance`; the gifter
    /// answers the `n`th call (from 0) of `method` with
    /// `answers(method, n, args, registry)`. Undoes the installed gifter, the
    /// retry interval and the store on drop.
    struct DiscoveryPass {
        dir: std::path::PathBuf,
        _imp: crate::test_support::TestImp,
        registry: String,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DiscoveryPass {
        fn new(name: &str, balance: u128, answers: Box<Answers>) -> Self {
            use crate::provider::fake::{self, FakePayer, FakeRegistry, FakeTree};
            use std::sync::{atomic::AtomicUsize, Arc};
            let dir =
                std::env::temp_dir().join(format!("rln-discovery-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let (imp, _store) = imp_with_store(dir.clone());
            assert!(imp
                .unlock_keystore("pw".into())
                .contains(r#""unlocked":true"#));
            let registry = registry_id::parse(&format!("fakens:local:{name}"))
                .unwrap()
                .canonical;
            crate::test_support::install_backend(fake::backend(
                FakeTree::default(),
                FakeRegistry {
                    membership: None,
                    bounds: Some(
                        serde_json::json!({ "price_per_unit": "1", "min_rate_limit": 1, "max_rate_limit": 1000 }),
                    ),
                },
                FakePayer {
                    balance: Some(balance),
                },
            ));
            crate::provider::fake::REGISTER_CALLS.store(0, Ordering::SeqCst);
            let (requests, probes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let (r, p, at) = (requests.clone(), probes.clone(), registry.clone());
            crate::test_support::install_gifter(Box::new(move |method, args| {
                let n = if method == "request" { &r } else { &p }.fetch_add(1, Ordering::SeqCst);
                answers(method, n, args, &at)
            }));
            DiscoveryPass {
                dir,
                _imp: imp,
                registry,
                requests,
                probes,
            }
        }

        fn run(&self, allocator: &serde_json::Value) {
            let allocator = DelegatedOptions::from_allocator_block(Some(allocator), "x").unwrap();
            ensure::run_with(
                vec![ensure::Provision {
                    registry: self.registry.clone(),
                    rate_limit: 100,
                    allocator,
                }],
                ensure::supersede(),
            );
        }

        fn counts(&self) -> (usize, usize, usize, usize) {
            let records = crate::sealed_store::store::current()
                .unwrap()
                .records_for(&self.registry)
                .len();
            (
                self.requests.load(Ordering::SeqCst),
                self.probes.load(Ordering::SeqCst),
                crate::provider::fake::REGISTER_CALLS.load(Ordering::SeqCst),
                records,
            )
        }
    }

    impl Drop for DiscoveryPass {
        fn drop(&mut self) {
            *crate::lock(&crate::test_support::INSTALLED_GIFTER) = None;
            DISCOVERY_RETRY_SECS.store(60, Ordering::SeqCst);
            crate::sealed_store::store::publish(None);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // A funded payer still waits out the retry interval and probes once more
    // before paying: an allocator listed by then is asked and grants.
    #[test]
    fn a_funded_pass_probes_a_missed_allocator_once_more_before_paying() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        DISCOVERY_RETRY_SECS.store(2, Ordering::SeqCst);
        let pass = DiscoveryPass::new(
            "funded-grace",
            1_000_000_000_000,
            Box::new(|method, n, args, _| match (method, n) {
                ("request", 0) => missed("no allocator advertises R/peer-any"),
                ("request", _) => granted(args),
                _ => listed(1),
            }),
        );
        let began = std::time::Instant::now();
        pass.run(&serde_json::json!({}));
        let step = ensure::progress(&pass.registry).expect("a step is recorded");
        assert_eq!(step.step, ensure::Step::Done, "{}", step.detail);
        assert!(step.detail.contains("(discovered)"), "{}", step.detail);
        assert!(step.fallback_reason.is_none());
        // (requests, probes, funded submits, records): the refusal and the grant.
        assert_eq!(pass.counts(), (2, 1, 0, 2));
        assert!(
            began.elapsed() >= std::time::Duration::from_secs(2),
            "the probe waits out the interval"
        );
    }

    // An unfunded payer keeps probing every interval, each miss replacing the
    // fallback reason without a request, until an allocator is listed and
    // grants.
    #[test]
    fn an_unfunded_pass_keeps_probing_a_missed_allocator() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        DISCOVERY_RETRY_SECS.store(1, Ordering::SeqCst);
        let seen = std::sync::Arc::new(Mutex::new(None));
        let saw = seen.clone();
        let pass = DiscoveryPass::new(
            "unfunded",
            0,
            Box::new(move |method, n, args, registry| match (method, n) {
                ("request", 0) => missed("discovery not joined: no connected peer after 20s"),
                ("request", _) => {
                    *crate::lock(&saw) = ensure::progress(registry).and_then(|p| p.fallback_reason);
                    granted(args)
                }
                (_, 0) => listed(0),
                _ => listed(1),
            }),
        );
        pass.run(&serde_json::json!({}));
        let step = ensure::progress(&pass.registry).expect("a step is recorded");
        assert_eq!(step.step, ensure::Step::Done, "{}", step.detail);
        assert!(step.detail.contains("(discovered)"), "{}", step.detail);
        assert!(step.fallback_reason.is_none());
        assert_eq!(
            pass.counts(),
            (2, 2, 0, 2),
            "no request, and no record, for the empty probe"
        );
        let seen = crate::lock(&seen).clone();
        assert!(
            seen.as_deref()
                .is_some_and(|r| r.contains("discovery: no allocator yet (3 peers)")),
            "{seen:?}"
        );
    }

    // A node that cannot discover at all is neither probed nor asked again;
    // the funded path runs.
    #[test]
    fn discovery_unavailable_is_asked_once_and_paid_for() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        DISCOVERY_RETRY_SECS.store(1, Ordering::SeqCst);
        let pass = DiscoveryPass::new(
            "unavailable",
            1_000_000_000_000,
            Box::new(|method, _, _, _| match method {
                "request" => missed("discovery unavailable: no service discovery on this node"),
                _ => listed(1),
            }),
        );
        pass.run(&serde_json::json!({}));
        let step = ensure::progress(&pass.registry).expect("a step is recorded");
        assert_eq!(pass.counts(), (1, 0, 1, 2), "the funded submit was reached");
        assert_eq!(
            step.step,
            ensure::Step::Refused,
            "the fake registry refuses every submit"
        );
        assert!(
            step.fallback_reason
                .as_deref()
                .is_some_and(|r| r.contains("discovery unavailable")),
            "{:?}",
            step.fallback_reason
        );
    }

    // A pinned pair alone has nothing to probe: its refusal goes straight to
    // the funded path.
    #[test]
    fn a_pinned_pair_is_not_probed() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        DISCOVERY_RETRY_SECS.store(1, Ordering::SeqCst);
        let pass = DiscoveryPass::new(
            "pinned",
            1_000_000_000_000,
            Box::new(|method, _, _, _| match method {
                "request" => missed("no allocator advertises R/peer-any"),
                _ => listed(1),
            }),
        );
        pass.run(&serde_json::json!({ "peer_id": "p", "multiaddr": "/m", "discover": false }));
        assert_eq!(pass.counts(), (1, 0, 1, 2));
    }

    // Any registry's pending registration is every pass's nonce.
    #[test]
    fn a_pending_registration_anywhere_holds_the_next_submit() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-any-pending-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_imp, store) = imp_with_store(dir.clone());
        store.unlock("pw").unwrap();
        assert!(!ensure::any_pending_membership());
        let registry = format!("logos:local:{}", "7e".repeat(32));
        seed_membership(
            &store,
            "pb",
            &registry,
            &"56".repeat(32),
            "",
            &"e6".repeat(32),
            MembershipState::Pending,
            0,
            100,
        );
        assert!(ensure::any_pending_membership());
        store
            .update_cache("pb", |m| m.state = MembershipState::Active)
            .unwrap();
        assert!(!ensure::any_pending_membership());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // One payer, one nonce: the provisioning pass holds after a submit while
    // the registry's registration is pending, and stands down at once when a
    // later start() supersedes it.
    #[test]
    fn provisioning_holds_while_its_registration_is_pending() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-hold-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (imp, store) = imp_with_store(dir.clone());
        assert!(imp
            .unlock_keystore("pw".into())
            .contains(r#""unlocked":true"#));
        let registry = format!("logos:local:{}", "7a".repeat(32));
        let parsed = registry_id::parse(&registry).unwrap();
        let hash = "hold-pending";
        seed_membership(
            &store,
            hash,
            &registry,
            &"11".repeat(32),
            "",
            &"22".repeat(32),
            MembershipState::Pending,
            0,
            100,
        );
        assert!(ensure::pending_membership_present(&parsed));

        // A superseded pass does not wait on it.
        let t0 = std::time::Instant::now();
        ensure::wait_confirmed(&parsed, u64::MAX);
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "a superseded pass must return at once"
        );

        // Confirmed: nothing to hold for, superseded or not.
        store
            .update_cache(hash, |m| m.state = MembershipState::Active)
            .unwrap();
        assert!(!ensure::pending_membership_present(&parsed));
        let t0 = std::time::Instant::now();
        ensure::wait_confirmed(&parsed, ensure::ticket_in_force());
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        drop(imp);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
