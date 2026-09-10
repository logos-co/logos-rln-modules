// Deterministic state-machine tests for the onboarding flow, driven by a
// scripted mock bridge injected through the inspector's `evaluate` command
// (framework.mjs doesn't wrap it; the server supports it). No daemon, no
// faucet: the mock replies with the same parseReply-visible shapes as the
// real wire (liblogos_rln_module.lidl at wire 0.7.0 — register_membership,
// the LIP MembershipStatus vocabulary, {class,kind,message} error envelopes —
// liblogos_lez_rln_module.lidl 2.0.0, plus the wallet module's int64 and
// raw-string returns). One deliberate simplification: register_membership
// here always mints a NEW membership, where the real module short-circuits
// to the scope's live one — the multi-pill list scenarios need the former.
//
// The seam: Main.qml `bridgeOverride` re-threads the whole tree to the mock;
// OnboardingView `flowController` exposes the flow's phase properties and
// methods; test-tunable poll intervals let the claim/register timers fire in
// milliseconds; Qt.callLater keeps mock dispatch async (no re-entrancy).
//
// One app process (mkPluginTest invokes each tests/*.mjs separately) is
// shared across the scenarios; each fully resets flow state and installs a
// fresh mock.
import { resolve } from "node:path";

process.env.QML_INSPECTOR_PORT = process.env.QML_INSPECTOR_PORT || "13769";
const root = process.env.LOGOS_QT_MCP || new URL("../result-mcp", import.meta.url).pathname;
const { test, run } = await import(resolve(root, "test-framework/framework.mjs"));

// ---- inspector helpers ------------------------------------------------------

async function evalExpr(app, expression) {
  const r = await app.inspector.send("evaluate", { expression });
  if (r.ok !== true || r.error)
    throw new Error(`evaluate failed for <${expression}>: ${JSON.stringify(r)}`);
  return r.result;
}
const phase = (app, prop) => evalExpr(app, `onboardingView.flowController.${prop}`);
const mode = (app) => evalExpr(app, "root.mode");
async function callLog(app) {
  return JSON.parse(await evalExpr(app, "JSON.stringify(root.bridgeOverride.callLog)"));
}

async function waitFor(app, fn, description, timeout = 8000) {
  await app.waitFor(fn, { timeout, interval: 100, description });
}
async function waitPhase(app, prop, value, timeout = 8000) {
  await waitFor(app, async () => {
    const v = await phase(app, prop);
    if (v !== value) throw new Error(`${prop}=${v}, want ${value}`);
  }, `${prop} → ${value}`, timeout);
}
async function waitMode(app, value, timeout = 8000) {
  await waitFor(app, async () => {
    const v = await mode(app);
    if (v !== value) throw new Error(`mode=${v}, want ${value}`);
  }, `mode → ${value}`, timeout);
}

// ---- the mock ---------------------------------------------------------------
// Returns a QML-JS expression string that builds the mock and assigns it to
// root.bridgeOverride. cfg is embedded verbatim.
function mockExpr(cfg) {
  const c = JSON.stringify({
    autoUnlock: cfg.autoUnlock ?? "created",
    autoUnlockKind: cfg.autoUnlockKind ?? "keychain_unavailable",
    memberships: cfg.memberships ?? [],
    syncHead: cfg.syncHead ?? 1005,
    syncFail: cfg.syncFail ?? false,
    claimFunds: cfg.claimFunds ?? true,
    registerState: cfg.registerState ?? "active",
    registerFailReason: cfg.registerFailReason ?? "insufficient funds",
    unlockOk: cfg.unlockOk ?? true,
    // Map of method -> { kind, times }: return that transient error kind for
    // the first `times` calls of the method, then succeed.
    transientOnce: cfg.transientOnce ?? {},
  });
  return `(function () {
    var cfg = ${c};
    var st = { synced: 0, acctSeq: 0, claimedAccount: "", failMemberships: false, memberships: cfg.memberships.slice(), transientLeft: {}, force: {}, regSeq: 0 };
    for (var k in cfg.transientOnce) st.transientLeft[k] = cfg.transientOnce[k].times;
    var log = [];
    // First registration keeps the golden "aa" commitment; a second run (the
    // ghost / New-membership path) gets a distinct one so the list holds two
    // separate pills.
    var COMMIT = "aa".repeat(32), COMMIT2 = "dd".repeat(32);
    // The raw register_member wire reply the module records as MembershipMeta
    // .tx_result and get_memberships echoes back — double-encoded exactly as
    // live (inner tx_result is itself a JSON string). qml/membership.js
    // parseTxResult / MembershipCard's Registration section consume this.
    var TXHASH = "12".repeat(32);
    var TXRESULT = JSON.stringify({ leaf_index: 5, payment_definition: "dd".repeat(32), tx_result: JSON.stringify({ error: "", secrets: [], success: true, tx_hash: TXHASH }) });
    // The wire's error envelope: class is the coarse RlnErrorKind the UI
    // switches on, kind refines it (the module's docs/wire-binding.md "Error envelope").
    var CLASS_OF = { bridge_failure: "transient", empty_reply: "transient", bad_reply: "transient", timeout: "transient", provider_failure: "transient", not_ready: "not_ready", locked: "not_ready", budget_exhausted: "budget_exhausted" };
    function err(kind, message) {
      return { error: { "class": CLASS_OF[kind] || "permanent", kind: kind, message: message } };
    }
    // Scope resolution the way the module does it (lidl get_membership_state):
    // records registered under this rln_identifier, or legacy rows carrying
    // none, back the scope; the newest such record wins here (the module
    // would answer ambiguous_selection for several — see the header note).
    function findScoped(registryId, rlnId) {
      for (var i = st.memberships.length - 1; i >= 0; i--) {
        var m = st.memberships[i];
        if (m.registry_id !== undefined && m.registry_id !== registryId) continue;
        if (m.rln_identifier === undefined || m.rln_identifier === rlnId) return m;
      }
      return null;
    }
    function reply(method, args) {
      log.push(method);
      // Runtime-settable: force a method to always return a transient error
      // (set root.bridgeOverride.state.force.<method> = "<kind>").
      if (st.force[method])
        return err(st.force[method], "mock: forced " + method);
      if (st.transientLeft[method] > 0) {
        st.transientLeft[method] -= 1;
        return err(cfg.transientOnce[method].kind, "mock: transient " + method);
      }
      switch (method) {
        case "get_memberships":
          if (st.failMemberships) return err("provider_failure", "mock: memberships unavailable");
          return { memberships: st.memberships };
        case "unlock_keystore_auto":
          if (cfg.autoUnlock === "error") return err(cfg.autoUnlockKind, "mock: auto-unlock failed");
          if (cfg.autoUnlock === "created")
            return { membership_count: st.memberships.length, secret: "sec-created", source: "created", unlocked: true };
          return { membership_count: st.memberships.length, source: cfg.autoUnlock, unlocked: true };
        case "unlock_keystore":
          if (!cfg.unlockOk) return err("bad_password", "mock: wrong password");
          return { membership_count: st.memberships.length, unlocked: true };
        case "remember_keystore_password": return { remembered: true };
        case "provision_wallet_home":
          return { config_existed: false, config_path: "/mock/wallet-home/wallet_config.json", storage_exists: false, storage_path: "/mock/wallet-home/storage.json" };
        case "create_new": return "mock recovery phrase shown only once ok";
        case "open": return 0;
        case "save": return 0;
        case "get_current_block_height":
          if (cfg.syncFail) return err("empty_reply", "mock: no head");
          return cfg.syncHead;
        case "get_last_synced_block": return st.synced;
        case "sync_to_block": st.synced = Math.min(args[0], cfg.syncHead); return 0;
        case "get_registry_bounds": return { max_rate_limit: 600, min_rate_limit: 100, price_per_unit: "10000", total_registrations: 1 };
        case "create_account_public":
          st.acctSeq += 1;
          return (st.acctSeq.toString(16).padStart(2, "0")).repeat(32).slice(0, 64);
        case "get_token_balance":
          // Only the account a claim funded reads back a balance; freshly
          // derived accounts read exists:false so the derive loop advances.
          if (cfg.claimFunds && args[0] === st.claimedAccount)
            return { exists: true, balance: "6000000", definition: "dd".repeat(32) };
          return { exists: false, balance: "0" };
        case "claim_tokens": st.claimedAccount = args[1]; return { payment_definition: "dd".repeat(32), pending: true, tx_result: "{}" };
        case "register":
          // The pre-0.7.0 spelling. The wire renamed it (register is a C/C++
          // keyword — generated clients could not carry the spec name), so a
          // call-site regression fails loudly here.
          return err("invalid_argument", "mock: no method 'register' on wire 0.7.0 — call register_membership");
        case "register_membership": {
          // Deliberately strict so a call-site regression fails here: the
          // scope pair, then the RegistryOptions array with a decimal-string
          // rate_limit (the module rejects non-string values / non-arrays).
          if (args.length !== 3)
            return err("invalid_argument", "mock: register_membership takes 3 args (registry_id, rln_identifier_hex, options_json), got " + args.length);
          if (!/^(0x)?[0-9a-f]{64}$/.test(String(args[1])))
            return err("invalid_argument", "mock: rln_identifier_hex must be 32-byte hex, got " + args[1]);
          var opts;
          try { opts = JSON.parse(args[2]); } catch (e) { opts = null; }
          if (!Array.isArray(opts) || opts.some(function (o) { return !o || typeof o.key !== "string" || !o.key || typeof o.value !== "string"; }))
            return err("invalid_argument", "mock: options_json must be a RegistryOptions array of {key,value} string pairs");
          var rate = 0;
          for (var oi = 0; oi < opts.length; oi++) if (opts[oi].key === "rate_limit") rate = parseInt(opts[oi].value, 10);
          if (!(rate > 0))
            return err("invalid_argument", "mock: rate_limit must be a positive decimal string");
          // The credential is minted in-module and only its commitment is
          // ever released. First registration keeps the golden "aa"
          // commitment; a later one (the ghost / New-membership path) gets a
          // distinct one so the list holds two separate pills.
          st.regSeq += 1;
          var commit = st.regSeq === 1 ? COMMIT : COMMIT2;
          var view = { credential: { identity_commitment: commit }, leaf_index: 5, membership_hash: "ee".repeat(32), rate_limit: rate, registry_id: args[0], rln_identifier: args[1], state: "pending", submitted_at: 1700000000 };
          var row = JSON.parse(JSON.stringify(view));
          row.tx_result = TXRESULT;
          st.memberships.push(row);
          return view;
        }
        case "get_membership_state": {
          if (args.length !== 2)
            return err("invalid_argument", "mock: get_membership_state takes 2 args (registry_id, rln_identifier_hex), got " + args.length);
          var m = findScoped(args[0], args[1]);
          if (!m) return { registry_id: args[0], state: "unknown" };
          if (cfg.registerState === "failed") { m.state = "failed"; m.failed_reason = cfg.registerFailReason; m.retryable = true; return { registry_id: args[0], state: "failed" }; }
          m.state = cfg.registerState;
          return { leaf_index: m.leaf_index, membership_hash: m.membership_hash, rate_limit: m.rate_limit, registry_id: args[0], state: cfg.registerState };
        }
        case "get_membership":
          return { clock_timestamp: 1700003000, grace_period_duration: 600, grace_period_start_timestamp: 1700005580, leaf_index: 5, rate_limit: 300, registered: true, state: cfg.registerState };
        default: return err("internal", "mock: unhandled " + method);
      }
    }
    root.bridgeOverride = {
      callLog: log, state: st,
      callModuleAsync: function (module, method, args, cb, t) { var r = reply(method, args); Qt.callLater(function () { cb(JSON.stringify(r)); }); },
    };
    return true;
  })()`;
}

// Fully reset Main + flow state so scenarios are isolated, then install the
// mock. registryId is preserved unless a scenario edits it via AdvancedView.
function resetExpr(cfg) {
  return `(function () {
    var f = onboardingView.flowController;
    f.walletPhase = "idle"; f.walletError = ""; f.mnemonic = ""; f.walletCreated = false;
    f.syncPhase = "idle"; f.syncError = ""; f.syncStart = 0; f.lastSynced = -1; f.syncTarget = 0; f.syncAttempts = 0; f.syncChunkTarget = 0; f.syncToppedUp = false;
    f.unlockPhase = "idle"; f.unlockError = "";
    f.autoUnlockPhase = "idle"; f.autoUnlockKind = ""; f.started = false;
    f.fundPhase = "idle"; f.fundError = ""; f.pricePerUnit = ""; f.claimAmount = 0; f.holdingHex = ""; f.claimPolls = 0;
    f.regPhase = "idle"; f.regError = ""; f.regState = ""; f.commitment = ""; f.rateLimitMismatch = false; f.password = "";
    f.registrationMode = "wallet"; f.gifterPhase = "idle"; f.gifterStage = ""; f.gifterError = "";
    f.claimPollMs = 20; f.statePollMs = 20; f.claimPollBudget = ${cfg.claimBudget ?? 36};
    f.transientRetryMs = 15; f.transientRetryMax = 3;
    onboardingView.currentStep = 0; onboardingView.priorNotice = ""; root.preAdvancedMode = ""; root.mode = "probe";
    membershipView.celebrate = false; membershipView.completionRefresh = false;
    ${mockExpr(cfg)};
    return true;
  })()`;
}

async function setup(app, cfg) {
  await evalExpr(app, resetExpr(cfg));
  await evalExpr(app, "root.probe()");
}

// ---- scenarios --------------------------------------------------------------

// 1. Golden path: auto-unlock → wallet → chunked sync → fund → register →
//    active; completion lands on the refreshed list, the first membership
//    celebrates, and tapping the pill opens detail.
test("flow: golden path lands the first membership in a celebrating list", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await waitPhase(app, "autoUnlockPhase", "done");
  if (await phase(app, "password") !== "sec-created") throw new Error("secret not adopted as password");
  const skipped = await evalExpr(app, "onboardingView.passwordSkipped");
  if (skipped !== true) throw new Error("password screen not skipped after auto-unlock");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  // The 0.7.0 wire: registration goes through register_membership with the
  // (registry_id, rln_identifier_hex, options_json) scope; the old spelling
  // must never be dialled.
  const glog = await callLog(app);
  if (!glog.includes("register_membership") || glog.includes("register"))
    throw new Error(`registration did not use register_membership: ${glog.join(",")}`);
  await waitMode(app, "status");
  if (await evalExpr(app, "membershipView.celebrate") !== true)
    throw new Error("first membership did not celebrate");
  const pet = await evalExpr(app, `M.petname("${"aa".repeat(32)}")`);
  if (!/^[a-z]+-[a-z]+-[a-z]+$/.test(pet)) throw new Error(`bad petname: ${pet}`);
  await app.expectTexts(["You're in!", pet, "300 msg/epoch", "+ New Membership"]);
  await app.click(pet);
  await waitMode(app, "detail");
  await app.expectTexts([pet, "Rate limit", "Leaf index", "Membership id", "Back"]);
  if (/undefined/.test(await evalExpr(app, "detailCard.leaf + '|' + detailCard.rate")))
    throw new Error("detail shows undefined leaf/rate");
  // The double-encoded tx_result recorded at register surfaces in the
  // detail's Registration section.
  if (await evalExpr(app, "detailCard.hasTx") !== true)
    throw new Error("registration tx section not shown");
  const txHash = "12".repeat(32);
  if (await evalExpr(app, "detailCard.txHash") !== txHash)
    throw new Error(`tx hash not parsed: ${await evalExpr(app, "detailCard.txHash")}`);
  const shownHash = await evalExpr(app, `M.truncateHex("${txHash}", 10, 8)`);
  await app.expectTexts(["Registration", "Confirmed", shownHash, "Copy"]);
});

// 2. Fallback + remember: auto-unlock errors → password screen → manual unlock
//    → remember_keystore_password fires → flow proceeds to active.
test("flow: keychain fallback shows the password screen and remembers on unlock", async (app) => {
  await setup(app, { autoUnlock: "error", autoUnlockKind: "keychain_unavailable", unlockOk: true, registerState: "active" });
  await waitPhase(app, "autoUnlockPhase", "fallback");
  await app.click("Get started");
  await app.expectTexts(["Choose a password"]);
  // No text-input API: set flow.password directly and drive the real
  // checkPassword().
  await evalExpr(app, "onboardingView.flowController.password = 'pw-manual'");
  await evalExpr(app, "onboardingView.flowController.checkPassword()");
  await waitPhase(app, "unlockPhase", "done");
  const log = await callLog(app);
  if (!log.includes("remember_keystore_password"))
    throw new Error("remember_keystore_password not fired on fallback unlock");
  await waitPhase(app, "regPhase", "done", 12000);
});

// 3. Advanced round-trip regression: a transient exit re-probe error must
//    restore the pre-advanced mode, not bounce to onboarding; a clean exit
//    routes by reality.
test("flow: exit-advanced restores mode on a transient error, routes on success", async (app) => {
  await setup(app, { memberships: [{ credential: { identity_commitment: "aa".repeat(32) }, membership_hash: "ee".repeat(32), leaf_index: 5, rate_limit: 300, state: "active", submitted_at: 1 }] });
  await waitMode(app, "status");
  await app.click("Advanced", { exact: true });   // card's Advanced link
  await waitMode(app, "advanced");
  if (await evalExpr(app, "root.preAdvancedMode") !== "status") throw new Error("preAdvancedMode not captured");
  await evalExpr(app, "root.bridgeOverride.state.failMemberships = true");
  await app.click("Exit advanced");
  await waitMode(app, "status");   // restored, NOT bounced to onboarding
  // Clean exit re-probe routes by reality.
  await evalExpr(app, "root.bridgeOverride.state.failMemberships = false");
  await app.click("Advanced", { exact: true });
  await waitMode(app, "advanced");
  await app.click("Exit advanced");
  await waitMode(app, "status");
});

// 4. Registry poisoning regression: a garbled edit must not reach
//    root.registryId; a valid CAIP-10 edit is adopted.
test("flow: advanced registry edits reject garbage, accept valid CAIP-10", async (app) => {
  await setup(app, { autoUnlock: "created" });
  await waitMode(app, "onboarding");
  const good = await evalExpr(app, "root.registryId");
  if (await evalExpr(app, `M.registryConfigHex(root.registryId) !== ""`) !== true)
    throw new Error("baseline registryId not a valid CAIP-10");
  await app.click("Advanced setup");
  await waitMode(app, "advanced");
  await evalExpr(app, "advancedView.registryEdited('')");
  await evalExpr(app, "advancedView.registryEdited('not a caip10 id')");
  if (await evalExpr(app, "root.registryId") !== good)
    throw new Error("garbage edit poisoned registryId");
  if (await evalExpr(app, `M.registryConfigHex(root.registryId) !== ""`) !== true)
    throw new Error("funding path would be poisoned (registryConfigHex empty)");
  const other = "logos:testnet:" + "ab".repeat(32);
  await evalExpr(app, `advancedView.registryEdited(${JSON.stringify(other)})`);
  if (await evalExpr(app, "root.registryId") !== other)
    throw new Error("valid registry edit not adopted");
});

// 5. New membership via the ghost: a completed run leaves syncPhase done; the
//    "+ New Membership" ghost resets it so the re-run re-enters sync (else
//    startSync would early-return) and reaches active.
test("flow: the New Membership ghost re-runs the flow with a sync reset", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  if (await phase(app, "syncPhase") !== "done") throw new Error("precondition: syncPhase done after a run");
  await app.expectTexts(["+ New Membership"]);
  const before = (await callLog(app)).filter((m) => m === "get_current_block_height").length;
  // Not app.click: MembershipView's always-instantiated (invisible) ghost
  // shares the text and the click BFS would match it. Drive the ghost's
  // handler (onNewMembershipRequested → restart) directly.
  await evalExpr(app, "onboardingView.restart()");
  // Re-entering sync proves syncPhase was reset (a stale "done" would make
  // startSync early-return and never re-read the head).
  await waitFor(app, async () => {
    const n = (await callLog(app)).filter((m) => m === "get_current_block_height").length;
    if (n <= before) throw new Error(`no re-sync: head reads ${n} <= ${before}`);
  }, "re-sync to begin", 8000);
  await waitPhase(app, "regPhase", "done", 12000);
});

// 5b. A second membership never celebrates: the 0->1 one-shot is not re-armed
//     for a 1->2 completion; both pills land under "Your Memberships".
test("flow: a second membership lands in the list without celebrating", async (app) => {
  const cOld = "cc".repeat(32);
  await setup(app, { autoUnlock: "created", registerState: "active",
    memberships: [{ credential: { identity_commitment: cOld }, membership_hash: "ff".repeat(32), leaf_index: 2, rate_limit: 200, state: "active", submitted_at: 1 }] });
  // A usable membership routes straight to the list — a relaunch, so no celebration.
  await waitMode(app, "status");
  const petOld = await evalExpr(app, `M.petname("${cOld}")`);
  await app.expectTexts(["Your Memberships", petOld]);
  if (await evalExpr(app, "membershipView.celebrate") !== false)
    throw new Error("relaunch into the list must not celebrate");
  await evalExpr(app, "root.startNewMembership()");
  await waitMode(app, "onboarding");
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  await waitMode(app, "status");
  const petNew = await evalExpr(app, `M.petname("${"aa".repeat(32)}")`);
  if (petNew === petOld) throw new Error("test fixtures collided on a petname");
  await app.expectTexts(["Your Memberships", petOld, petNew, "+ New Membership"]);
  if (await evalExpr(app, "membershipView.celebrate") !== false)
    throw new Error("a second membership must not celebrate");
});

// 5c. A relaunch with one membership reads "Your Memberships": celebration is
//     tied to the completion event, not the launch count.
test("flow: a relaunch with one membership reads 'Your Memberships', never celebrates", async (app) => {
  const c = "aa".repeat(32);
  await setup(app, { memberships: [{ credential: { identity_commitment: c }, membership_hash: "ee".repeat(32), leaf_index: 5, rate_limit: 300, state: "active", submitted_at: 1 }] });
  await waitMode(app, "status");
  const pet = await evalExpr(app, `M.petname("${c}")`);
  await app.expectTexts(["Your Memberships", pet, "300 msg/epoch", "+ New Membership"]);
  if (await evalExpr(app, "membershipView.celebrate") !== false)
    throw new Error("a relaunch (not a completion) must never celebrate");
});

// 5d. The LIP vocabulary: a terminal state the logos namespace never emits
//     today (slashed) must still route like any settled-unusable state —
//     onboarding with the "no longer active" notice — and its detail card
//     offers Re-register; a state outside the vocabulary entirely degrades to
//     the neutral badge rather than crashing the list.
test("flow: LIP terminal and unknown states degrade gracefully", async (app) => {
  const c = "aa".repeat(32), c2 = "cc".repeat(32);
  await setup(app, { autoUnlock: "created", memberships: [
    { credential: { identity_commitment: c }, membership_hash: "ee".repeat(32), leaf_index: 5, rate_limit: 300, state: "slashed", submitted_at: 1 },
    { credential: { identity_commitment: c2 }, membership_hash: "ff".repeat(32), leaf_index: 6, rate_limit: 100, state: "state_from_the_future", submitted_at: 1 }] });
  await waitMode(app, "onboarding");
  if (await evalExpr(app, "onboardingView.priorNotice") === "")
    throw new Error("a slashed membership must trigger the 'no longer active' notice");
  await evalExpr(app, `root.showDetail("${c}")`);
  await waitMode(app, "detail");
  await waitFor(app, async () => {
    if (await evalExpr(app, "detailCard.found") !== true) throw new Error("card not loaded");
  }, "detail card to load");
  if (await evalExpr(app, "detailCard.renewable") !== true) throw new Error("slashed must be renewable");
  if (await evalExpr(app, "detailCard.liveState") !== "slashed") throw new Error("state not shown verbatim");
  await evalExpr(app, `root.showDetail("${c2}")`);
  await waitFor(app, async () => {
    if (await evalExpr(app, "detailCard.liveState") !== "state_from_the_future") throw new Error("card not reloaded");
  }, "unknown-state card to load");
  if (await evalExpr(app, "M.stateRank('state_from_the_future') > M.stateRank('slashed')") !== true)
    throw new Error("unknown states must sort after every known one");
  if (await evalExpr(app, "M.isKnownState('erased_awaits_withdrawal') && !M.isKnownState('state_from_the_future')") !== true)
    throw new Error("vocabulary check wrong");
});

// 6. Error branches: sync fail, claim timeout, register failed.
test("flow: sync failure surfaces an error with retry", async (app) => {
  await setup(app, { autoUnlock: "created", syncFail: true });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "syncPhase", "error", 12000);
  await app.expectTexts(["Setup failed", "Retry"]);
});

test("flow: claim timeout names both causes", async (app) => {
  await setup(app, { autoUnlock: "created", claimFunds: false, claimBudget: 3 });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "fundPhase", "error", 12000);
  const err = await phase(app, "fundError");
  if (!/never funded within 180s/.test(err) || !/unsynced/.test(err))
    throw new Error(`claim-timeout message missing a cause: ${err}`);
});

test("flow: register failure shows the reason and try-again", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "failed", registerFailReason: "insufficient funds" });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "error", 12000);
  await app.expectTexts(["Registration failed", "Try again"]);
  const err = await phase(app, "regError");
  if (!/insufficient funds/.test(err)) throw new Error(`failed_reason missing: ${err}`);
});

// 7. Auto-retry recovery: transient bridge_failure errors on the first
//    get_registry_bounds calls self-heal — the flow reaches active without
//    surfacing the error.
test("flow: transient error on a critical read auto-recovers", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active",
    transientOnce: { get_registry_bounds: { kind: "bridge_failure", times: 2 } } });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  if (await phase(app, "fundPhase") !== "done") throw new Error("fund phase did not recover");
  if (await phase(app, "fundError") !== "") throw new Error("transient error leaked to the user");
  const log = await callLog(app);
  const bounds = log.filter((m) => m === "get_registry_bounds").length;
  if (bounds < 3) throw new Error(`expected retries, saw ${bounds} get_registry_bounds calls`);
});

// 8. Non-transient errors are NOT retried and surface immediately: a
//    bad_password on the manual unlock path fails on the first attempt.
test("flow: non-transient error (bad_password) is not retried", async (app) => {
  await setup(app, { autoUnlock: "error", autoUnlockKind: "keychain_unavailable", unlockOk: false });
  await waitPhase(app, "autoUnlockPhase", "fallback");
  await app.click("Get started");
  await app.expectTexts(["Choose a password"]);
  await evalExpr(app, "onboardingView.flowController.password = 'wrong'");
  await evalExpr(app, "onboardingView.flowController.checkPassword()");
  await waitPhase(app, "unlockPhase", "error");
  const log = await callLog(app);
  const unlocks = log.filter((m) => m === "unlock_keystore").length;
  if (unlocks !== 1) throw new Error(`bad_password was retried: ${unlocks} unlock_keystore calls`);
  if (!/bad_password|wrong password|Check your password/i.test(await phase(app, "unlockError")))
    throw new Error(`unexpected unlock error: ${await phase(app, "unlockError")}`);
});

// 9. Petname determinism, evaluated against the real M.petname.
test("petname is stable per commitment and varies across commitments", async (app) => {
  const a = "aa".repeat(32), b = "bb".repeat(32);
  const pa1 = await evalExpr(app, `M.petname("${a}")`);
  const pa2 = await evalExpr(app, `M.petname("${a}")`);
  const pb = await evalExpr(app, `M.petname("${b}")`);
  if (!/^[a-z]+-[a-z]+-[a-z]+$/.test(pa1)) throw new Error(`bad petname shape: ${pa1}`);
  if (pa1 !== pa2) throw new Error(`petname not stable: ${pa1} vs ${pa2}`);
  if (pa1 === pb) throw new Error(`distinct commitments share a petname: ${pa1}`);
  if (await evalExpr(app, `M.petname("")`) !== "") throw new Error("empty commitment should yield ''");
});

// 10. Regression: detail "Refresh status" under a flaky transport must not
//     stack overlapping refresh cycles — a burst collapses to one cycle, the
//     view stays interactive, and the guard releases for a later refresh.
test("detail refresh is guarded — bursts don't stack retry chains", async (app) => {
  const c = "aa".repeat(32);
  await setup(app, { memberships: [{ credential: { identity_commitment: c }, membership_hash: "ee".repeat(32), leaf_index: 5, rate_limit: 300, state: "active", submitted_at: 1 }] });
  await waitMode(app, "status");
  await evalExpr(app, `root.showDetail("${c}")`);
  await waitMode(app, "detail");
  // Force the detail reads to always fail transiently so auto-retry engages
  // (worst case for stacking).
  await evalExpr(app, `root.bridgeOverride.state.force.get_membership_state = "empty_reply"`);
  await evalExpr(app, `root.bridgeOverride.state.force.get_membership = "empty_reply"`);
  const mem0 = (await callLog(app)).filter((m) => m === "get_memberships").length;
  // 20 synchronous refresh() calls in one tick — the guard must admit ONE.
  await evalExpr(app, "for (var i = 0; i < 20; i++) detailCard.refresh()");
  await waitFor(app, async () => {
    if (await evalExpr(app, "detailCard.refreshing") !== false) throw new Error("still refreshing");
  }, "refresh cycle to settle", 8000);
  const memBurst = (await callLog(app)).filter((m) => m === "get_memberships").length - mem0;
  const gmsBurst = (await callLog(app)).filter((m) => m === "get_membership_state").length;
  // One admitted cycle: ~1 get_memberships plus one bounded retry chain;
  // unguarded, both counts scale linearly with the burst size.
  if (memBurst > 2) throw new Error(`burst stacked ${memBurst} get_memberships (guard failed)`);
  if (gmsBurst > 6) throw new Error(`burst stacked ${gmsBurst} get_membership_state (guard failed)`);
  if (await mode(app) !== "detail") throw new Error("view left detail mode");
  await evalExpr(app, "detailCard.refresh()");
  await waitFor(app, async () => {
    const n = (await callLog(app)).filter((m) => m === "get_memberships").length - mem0;
    if (n <= memBurst) throw new Error("guard did not release for a later refresh");
  }, "later refresh admitted", 8000);
});

run();
