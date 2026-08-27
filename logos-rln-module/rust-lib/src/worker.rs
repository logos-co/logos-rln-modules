//! Worker supervisor: the maintenance threads' single owner — spawn
//! permission, interruptible ticks, and `stop()`'s bounded join/detach.
//!
//! Three workers run under it: the confirmation poller (15s tick), the
//! valid-root refresher (10s tick), and `start()`'s one-shot warm pass. Their
//! loops sleep in [`wait_tick`] — a Condvar wait — so `stop()` wakes a
//! sleeping worker in microseconds rather than one sleep interval. A worker
//! blocked in a single in-flight registry read (the provider's un-sliced
//! async wait, up to ~80s) cannot be interrupted: `stop()` waits a short
//! grace for voluntary exits, joins those, and DETACHES the rest — the
//! generation counter guarantees a detached straggler notices it is from a
//! superseded run after that one read and exits without ever duplicating a
//! respawned worker.
//!
//! Spawn permission: a worker may be spawned iff the supervisor is not
//! `Stopped`. Registration polling and root tracking legitimately start
//! workers before any `start()` (`NeverStarted` permits it), but nothing may
//! resurrect maintenance after `stop()` — interest recorded while stopped
//! (a tracked registry, a pending record) is picked up by the next
//! `start()`'s respawn and warm pass.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long `stop()` waits for workers to exit voluntarily before detaching
/// the stragglers. Sleeping workers wake and exit in microseconds; only a
/// worker mid-provider-read outlives this and is detached.
const GRACE: Duration = Duration::from_millis(200);

/// Whether maintenance may run — the lock-free gate the tick bodies (and
/// their per-item bail points) read, kept in lockstep with the supervisor
/// state so an abandoned in-flight worker also observes it.
static STOPPED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    /// No start() yet — on-demand spawn (register, track) is allowed.
    NeverStarted,
    Running,
    /// stop() ran and no start() since — nothing may spawn.
    Stopped,
}

/// A slot's handle plus the worker's own "I have returned" flag, so `stop()`
/// can tell an instant join from a blocked worker without ever blocking.
type Slot = Option<(JoinHandle<()>, Arc<AtomicBool>)>;

struct Supervisor {
    state: WorkerState,
    /// Bumped by stop() (and by a start() that follows one): a worker whose
    /// captured generation no longer matches is from a superseded run and
    /// exits at its next check — the mechanism that makes detaching safe.
    generation: u64,
    /// Bumped by nudge(): asks every sleeping tick loop for one immediate
    /// out-of-band tick (e.g. a root-window miss on the verification path
    /// wants the refresher NOW, not in up to one refresh interval). An
    /// early poller tick is a harmless idempotent re-poll.
    nudges: u64,
    /// Live (spawned, not yet returned) workers — stop()'s join condition
    /// and the tests' observability seam.
    running: usize,
    poller: Slot,
    refresher: Slot,
    warm: Slot,
}

static SUP: Mutex<Supervisor> = Mutex::new(Supervisor {
    state: WorkerState::NeverStarted,
    generation: 0,
    nudges: 0,
    running: 0,
    poller: None,
    refresher: None,
    warm: None,
});
static CVAR: Condvar = Condvar::new();

/// Whether maintenance is stopped (`stop()` with no later `start()`).
pub(crate) fn is_stopped() -> bool {
    STOPPED.load(Ordering::SeqCst)
}

/// Interruptible tick sleep. Returns `true` when the worker should run its
/// tick body, `false` when it should exit (stopped, or superseded by a newer
/// generation). A `stop()` or restart wakes the wait immediately.
pub(crate) fn wait_tick(my_gen: u64, dur: Duration) -> bool {
    let guard = crate::lock(&SUP);
    let entry_nudges = guard.nudges;
    let (sup, timeout) = CVAR
        .wait_timeout_while(guard, dur, |s| {
            s.generation == my_gen && s.state != WorkerState::Stopped && s.nudges == entry_nudges
        })
        .unwrap_or_else(|p| p.into_inner());
    (timeout.timed_out() || sup.nudges != entry_nudges)
        && sup.generation == my_gen
        && sup.state != WorkerState::Stopped
}

/// Wake every sleeping tick loop for one immediate tick. Callers rate-limit
/// themselves (see roots::nudge) — this is the raw wake.
pub(crate) fn nudge() {
    crate::lock(&SUP).nudges += 1;
    CVAR.notify_all();
}

#[cfg(test)]
pub(crate) fn nudges_for_test() -> u64 {
    crate::lock(&SUP).nudges
}

#[cfg(test)]
pub(crate) fn generation_for_test() -> u64 {
    crate::lock(&SUP).generation
}

/// Spawn `body(generation)` into `slot` if permitted and not already alive.
/// A slot whose previous worker has returned is reaped (instant join) and
/// respawned; a live worker makes this a no-op.
fn ensure(slot: fn(&mut Supervisor) -> &mut Slot, name: &'static str, body: fn(u64)) {
    let mut sup = crate::lock(&SUP);
    if sup.state == WorkerState::Stopped {
        return;
    }
    let alive = matches!(slot(&mut sup), Some((_, done)) if !done.load(Ordering::SeqCst));
    if alive {
        return;
    }
    if let Some((handle, _)) = slot(&mut sup).take() {
        let _ = handle.join();
    }
    let gen = sup.generation;
    *slot(&mut sup) = Some(spawn_into(name, gen, move || body(gen)));
    sup.running += 1;
}

/// Spawn a named worker of generation `gen`, wrapped in the exit epilogue
/// (generation-scoped `running` decrement + done flag + wake). The decrement
/// is skipped for a worker whose generation is no longer current: a
/// `stop()`/reset bumps the generation only once its workers are already
/// accounted for, so a superseded straggler exiting later must not disturb
/// the count a fresh run is now keeping.
///
/// The `done` flag is set LAST — only after the worker has released SUP — so a
/// reaper that joins a `done` slot WHILE HOLDING SUP can never block on the
/// worker still trying to acquire SUP. (Setting it before the SUP-locked tail
/// deadlocks: the reaper holds SUP and joins; the worker parks on SUP.)
fn spawn_into(
    name: &'static str,
    gen: u64,
    body: impl FnOnce() + Send + 'static,
) -> (JoinHandle<()>, Arc<AtomicBool>) {
    let done = Arc::new(AtomicBool::new(false));
    let done_in = done.clone();
    let handle = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            body();
            {
                let mut sup = crate::lock(&SUP);
                if sup.generation == gen {
                    sup.running = sup.running.saturating_sub(1);
                }
            }
            // Past the SUP section: the flag now truthfully means "instant
            // join" for a reaper holding SUP. Only the wake — which needs no
            // lock — and the thread's own teardown remain.
            done_in.store(true, Ordering::SeqCst);
            CVAR.notify_all();
        })
        .expect("spawn worker thread");
    (handle, done)
}

/// Idempotently spawn the confirmation poller (no-op while stopped).
pub(crate) fn ensure_poller() {
    ensure(|s| &mut s.poller, "rln-poller", crate::poller::run_loop);
}

/// Idempotently spawn the valid-root refresher (no-op while stopped).
pub(crate) fn ensure_refresher() {
    ensure(|s| &mut s.refresher, "rln-roots", crate::roots::run_loop);
}

/// start(): permit + spawn maintenance, and run `warm` once in the
/// background. A start after stop() bumps the generation (fresh workers,
/// stale stragglers die); a repeated start is idempotent — live workers are
/// kept, only the warm pass respawns.
pub(crate) fn start(warm: impl FnOnce() + Send + 'static) {
    {
        let mut sup = crate::lock(&SUP);
        if sup.state == WorkerState::Stopped {
            sup.generation += 1;
        }
        sup.state = WorkerState::Running;
        STOPPED.store(false, Ordering::SeqCst);
    }
    CVAR.notify_all();
    ensure_poller();
    ensure_refresher();
    let mut sup = crate::lock(&SUP);
    if let Some((handle, done)) = sup.warm.take() {
        // A previous warm pass that finished is reaped; one still in flight
        // is detached — its body bails on the stopped/generation checks.
        if done.load(Ordering::SeqCst) {
            let _ = handle.join();
        }
    }
    let gen = sup.generation;
    sup.warm = Some(spawn_into("rln-warm", gen, warm));
    sup.running += 1;
}

/// stop(): forbid spawning, wake every sleeping worker, wait up to [`GRACE`]
/// for voluntary exits, then join the exited and detach the rest (a worker
/// blocked in one in-flight registry read; it self-exits after it).
///
/// The generation is bumped and `running` zeroed only AFTER the detach loop:
/// during the grace wait the workers are still the current generation, so a
/// woken sleeper decrements `running` (letting the wait return early on the
/// fast path); closing the generation afterwards makes every remaining
/// straggler superseded, so it self-exits without touching the count the
/// next run keeps — no leak, no double-count on restart.
pub(crate) fn stop() {
    {
        let mut sup = crate::lock(&SUP);
        sup.state = WorkerState::Stopped;
        STOPPED.store(true, Ordering::SeqCst);
    }
    CVAR.notify_all();
    let guard = crate::lock(&SUP);
    let (mut sup, _) = CVAR
        .wait_timeout_while(guard, GRACE, |s| s.running > 0)
        .unwrap_or_else(|p| p.into_inner());
    let sup: &mut Supervisor = &mut sup;
    for slot in [&mut sup.poller, &mut sup.refresher, &mut sup.warm] {
        if let Some((handle, done)) = slot.take() {
            if done.load(Ordering::SeqCst) {
                let _ = handle.join();
            }
            // else: detached by dropping the handle; the generation close
            // below makes it exit (superseded) after its in-flight read.
        }
    }
    sup.generation += 1;
    sup.running = 0;
}

#[cfg(test)]
pub(crate) fn live_worker_count() -> usize {
    crate::lock(&SUP).running
}

#[cfg(test)]
pub(crate) fn generation() -> u64 {
    crate::lock(&SUP).generation
}

/// Reset to a fresh NeverStarted supervisor; the generation bump makes any
/// straggling worker from a previous test exit at its next check. Callers
/// hold the crate's global-state test lock.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut sup = crate::lock(&SUP);
    sup.state = WorkerState::NeverStarted;
    sup.generation += 1;
    sup.poller = None;
    sup.refresher = None;
    sup.warm = None;
    sup.running = 0;
    STOPPED.store(false, Ordering::SeqCst);
    drop(sup);
    CVAR.notify_all();
}

/// Occupy the poller slot with a worker that ignores ticks and parks on
/// `gate` — a stand-in for a worker stuck in a long provider read, for the
/// stop()-detaches test. `exited` is set when the worker finally returns, so
/// the test observes its self-exit directly (a detached straggler is
/// superseded and never touches `running`).
#[cfg(test)]
pub(crate) fn spawn_blocking_for_test(gate: Arc<(Mutex<bool>, Condvar)>, exited: Arc<AtomicBool>) {
    let mut sup = crate::lock(&SUP);
    let gen = sup.generation;
    sup.poller = Some(spawn_into("rln-test-blocker", gen, move || {
        let (m, cv) = &*gate;
        let mut released = m.lock().unwrap_or_else(|p| p.into_inner());
        while !*released {
            released = cv.wait(released).unwrap_or_else(|p| p.into_inner());
        }
        exited.store(true, Ordering::SeqCst);
    }));
    sup.running += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // The supervisor is process-global; every test here serializes on the
    // crate's designated global-state lock and starts from a clean reset.

    #[test]
    fn nudge_wakes_wait_tick_early_as_a_due_tick() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        let gen = generation_for_test();
        let woke = Arc::new(AtomicBool::new(false));
        let woke2 = woke.clone();
        let h = std::thread::spawn(move || {
            // Far longer than the assertion bound: only a nudge (not the
            // timeout) can return this within the test's lifetime.
            woke2.store(wait_tick(gen, Duration::from_secs(60)), Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(100)); // let it park
        let began = Instant::now();
        nudge();
        h.join().unwrap();
        assert!(woke.load(Ordering::SeqCst), "a nudge must count as a DUE tick, not a spurious wake");
        assert!(began.elapsed() < Duration::from_secs(5), "nudge wake took {:?}", began.elapsed());
        reset_for_test();
    }

    #[test]
    fn stop_joins_workers_quickly() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        ensure_poller();
        ensure_refresher();
        assert_eq!(live_worker_count(), 2);
        let began = Instant::now();
        stop();
        assert_eq!(live_worker_count(), 0);
        // Design target is milliseconds (workers sleep in wait_tick); the
        // bound is generous for a loaded CI box.
        assert!(began.elapsed() < Duration::from_secs(2), "stop took {:?}", began.elapsed());
        reset_for_test();
    }

    #[test]
    fn start_after_stop_respawns_with_new_generation() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        start(|| {});
        let g1 = generation();
        assert!(live_worker_count() >= 2);
        stop();
        assert_eq!(live_worker_count(), 0);
        assert!(is_stopped());
        start(|| {});
        assert!(generation() > g1);
        assert!(!is_stopped());
        assert!(live_worker_count() >= 2);
        stop();
        reset_for_test();
    }

    #[test]
    fn spawn_is_forbidden_while_stopped_but_interest_is_recorded() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        stop();
        crate::poller::ensure_running();
        let registry =
            crate::registry_id::parse(&format!("logos:local:{}", "fe".repeat(32))).unwrap();
        crate::roots::track(&registry);
        assert_eq!(live_worker_count(), 0, "nothing may spawn while stopped");
        assert!(
            crate::roots::tracked_contains(&registry.canonical),
            "interest is still recorded for the next start()"
        );
        reset_for_test();
    }

    #[test]
    fn on_demand_spawn_before_start_is_idempotent() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        crate::poller::ensure_running();
        assert_eq!(live_worker_count(), 1);
        crate::poller::ensure_running();
        assert_eq!(live_worker_count(), 1);
        stop();
        reset_for_test();
    }

    #[test]
    fn stop_detaches_blocked_worker_without_duplicating_it() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_for_test();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let exited = Arc::new(AtomicBool::new(false));
        spawn_blocking_for_test(gate.clone(), exited.clone());

        // stop() must NOT wait for the blocked worker's ~80s read — it
        // detaches after the grace and returns promptly.
        let began = Instant::now();
        stop();
        assert!(began.elapsed() < Duration::from_secs(2), "stop took {:?}", began.elapsed());
        assert!(!exited.load(Ordering::SeqCst), "the blocked worker is still parked, i.e. detached");

        // Release the "provider read"; the detached straggler self-exits
        // (observed via its own flag — superseded, it never touches `running`).
        {
            let (m, cv) = &*gate;
            *m.lock().unwrap() = true;
            cv.notify_all();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !exited.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(exited.load(Ordering::SeqCst), "released straggler must self-exit");

        // A restart spawns exactly the fresh set — stop() closed the
        // generation and zeroed the count, so the detached straggler never
        // double-counts against the new run.
        start(|| {});
        assert_eq!(live_worker_count(), 3);
        stop();
        reset_for_test();
    }
}
