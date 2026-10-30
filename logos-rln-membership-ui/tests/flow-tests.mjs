// Deterministic state-machine tests for the onboarding flow, driven by a
// scripted mock bridge injected through the inspector's `evaluate` command
// (framework.mjs doesn't wrap it; the server supports it). No daemon, no
// chain: the mock replies with the same parseReply-visible shapes as the
// real wire (liblogos_rln_module.lidl 0.12.0 — 0.15.0's leaf_pending included
// — ensure_membership with the
// structured provisioning object, register_membership with the delegated
// RegistryOptions, the LIP MembershipStatus vocabulary, {class,kind,message}
// error envelopes — liblogos_lez_rln_module.lidl 7.0.0's wallet_status /
// get_native_balance, rln_gifter_module.libp2p_call, and the two producer
// modules' card_status / address). Methods the wire dropped (lez_core, the
// faucet) answer an ERROR, so a call-site regression fails loudly. One
// deliberate simplification: register_membership here always mints a NEW
// membership, where the real module short-circuits to the scope's live one —
// the multi-pill list scenarios need the former.
//
// The seam: Main.qml `bridgeOverride` re-threads the whole tree to the mock;
// OnboardingView `flowController` exposes the flow's phase properties and
// methods; test-tunable poll intervals let the register timers fire in
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
async function lastRegisterOptions(app) {
  return JSON.parse(await evalExpr(app, "JSON.stringify(root.bridgeOverride.state.lastRegisterOptions)"));
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

const DEAD_METHODS = ["claim_tokens", "get_token_balance", "create_holding_account", "open",
  "create_new", "save", "sync_to_block", "get_last_synced_block", "get_current_block_height",
  "create_account_public", "provision_wallet_home", "register"];

// ---- the mock ---------------------------------------------------------------
// Returns a QML-JS expression string that builds the mock and assigns it to
// root.bridgeOverride. cfg is embedded verbatim.
function mockExpr(cfg) {
  const c = JSON.stringify({
    autoUnlock: cfg.autoUnlock ?? "created",
    autoUnlockKind: cfg.autoUnlockKind ?? "keychain_unavailable",
    memberships: cfg.memberships ?? [],
    registerState: cfg.registerState ?? "active",
    registerFailReason: cfg.registerFailReason ?? "insufficient funds",
    unlockOk: cfg.unlockOk ?? true,
    // The network wallet_status reports (prefills the registry via
    // M.KNOWN_REGISTRIES); "" = unbound.
    network: cfg.network ?? "testnet",
    // The funded path's provisioning pass: "pass" walks
    // waiting_for_wallet -> awaiting_funding -> registering -> (record) ->
    // done, one step per get_membership_state poll; "refused" stops at
    // refused. provisioningHold names a step the pass parks at until
    // state.release is set (so a screen can be asserted mid-pass).
    provisioning: cfg.provisioning ?? "pass",
    provisioningHold: cfg.provisioningHold ?? "",
    // Producer modules.
    cardPresent: cfg.cardPresent ?? true,
    ethAddress: cfg.ethAddress ?? "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025",
    // Map of method -> { kind, times }: return that transient error kind for
    // the first `times` calls of the method, then succeed.
    transientOnce: cfg.transientOnce ?? {},
  });
  return `(function () {
    var cfg = ${c};
    var st = { failMemberships: false, memberships: cfg.memberships.slice(), transientLeft: {}, force: {}, regSeq: 0,
               pass: null, release: false, cardPresent: cfg.cardPresent, lastRegisterOptions: null };
    for (var k in cfg.transientOnce) st.transientLeft[k] = cfg.transientOnce[k].times;
    var log = [];
    // First registration keeps the golden "aa" commitment; a second run (the
    // ghost / New-membership path) gets a distinct one so the list holds two
    // separate pills.
    var COMMIT = "aa".repeat(32), COMMIT2 = "dd".repeat(32);
    var PAYER = "ab".repeat(32);
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
    var DEAD = ${JSON.stringify(DEAD_METHODS)};
    // Scope resolution the way the module does it (lidl get_membership_state):
    // records registered under this rln_identifier, or legacy rows carrying
    // none, back the scope. One candidate answers; several answer the single
    // LIVE one, else "ambiguous" (the module's ambiguous_selection).
    function isLive(m) { return m.state === "pending" || m.state === "active" || m.state === "grace_period"; }
    function findScoped(registryId, rlnId) {
      var cands = [];
      for (var i = st.memberships.length - 1; i >= 0; i--) {
        var m = st.memberships[i];
        if (m.registry_id !== undefined && m.registry_id !== registryId) continue;
        if (m.rln_identifier === undefined || m.rln_identifier === rlnId) cands.push(m);
      }
      if (cands.length <= 1) return cands[0] || null;
      var live = cands.filter(isLive);
      return live.length === 1 ? live[0] : "ambiguous";
    }
    function liveOnRegistry(registryId) {
      for (var i = st.memberships.length - 1; i >= 0; i--) {
        var m = st.memberships[i];
        if (m.registry_id !== undefined && m.registry_id !== registryId) continue;
        if (m.state === "pending" || m.state === "active" || m.state === "grace_period") return m;
      }
      return null;
    }
    function mint(registryId, rlnId, rate) {
      // The credential is minted in-module and only its commitment is ever
      // released. First registration keeps the golden "aa" commitment; a
      // later one (the ghost / New-membership path) gets a distinct one so
      // the list holds two separate pills.
      st.regSeq += 1;
      var commit = st.regSeq === 1 ? COMMIT : COMMIT2;
      var view = { credential: { identity_commitment: commit }, leaf_index: 5, membership_hash: "ee".repeat(32), rate_limit: rate, registry_id: registryId, rln_identifier: rlnId, state: "pending", submitted_at: 1700000000 };
      var row = JSON.parse(JSON.stringify(view));
      row.tx_result = TXRESULT;
      st.memberships.push(row);
      return view;
    }
    function parseOptions(raw) {
      var opts;
      try { opts = JSON.parse(raw); } catch (e) { return null; }
      if (!Array.isArray(opts) || opts.some(function (o) { return !o || typeof o.key !== "string" || !o.key || typeof o.value !== "string"; }))
        return null;
      return opts;
    }
    function optionsRate(opts) {
      var rate = 0;
      for (var oi = 0; oi < opts.length; oi++) if (opts[oi].key === "rate_limit") rate = parseInt(opts[oi].value, 10);
      return rate;
    }
    // The provisioning object per step, as the lidl documents it.
    var STEPS = ["waiting_for_wallet", "awaiting_funding", "registering", "done"];
    function provisioningView(step) {
      var p = { step: step, detail: "mock: " + step };
      if (step === "awaiting_funding") { p.payer = PAYER; p.required = "6000000"; p.price = "5000000"; p.fee_reserve = "1000000"; p.balance = "0"; }
      return p;
    }
    // One poll of a running pass: advance a step unless parked at the hold.
    function advancePass(registryId) {
      var p = st.pass;
      if (cfg.provisioning === "refused") { p.step = "refused"; return provisioningView("refused"); }
      if (p.step === cfg.provisioningHold && !st.release) return provisioningView(p.step);
      var i = STEPS.indexOf(p.step);
      if (p.step === "registering") mint(registryId, p.rlnId, p.rate);
      if (i < STEPS.length - 1) p.step = STEPS[i + 1];
      return provisioningView(p.step);
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
      if (DEAD.indexOf(method) >= 0)
        return err("internal", "mock: '" + method + "' is not on this wire (lez module 5.0.0 / rln 0.12.0) — call-site regression");
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
        case "wallet_status":
          return { detail: "", network: cfg.network, payer: PAYER, ready: true, state: "ready" };
        case "get_native_balance": return { balance: "0" };
        case "get_registry_bounds": return { max_rate_limit: 600, min_rate_limit: 100, price_per_unit: "10000", total_registrations: 1 };
        case "ensure_membership": {
          // Strict: (registry_id, options_json) with ONLY rate_limit in the
          // options array — delegated/gifter/auth keys are invalid here.
          if (args.length !== 2)
            return err("invalid_argument", "mock: ensure_membership takes 2 args (registry_id, options_json), got " + args.length);
          var eopts = parseOptions(args[1]);
          if (!eopts) return err("invalid_argument", "mock: options_json must be a RegistryOptions array of {key,value} string pairs");
          for (var ei = 0; ei < eopts.length; ei++) if (eopts[ei].key !== "rate_limit")
            return err("invalid_argument", "mock: ensure_membership accepts only rate_limit, got " + eopts[ei].key);
          var live = liveOnRegistry(args[0]);
          if (live) return { registry_id: args[0], state: live.state, membership_hash: live.membership_hash, leaf_index: live.leaf_index, leaf_pending: live.leaf_pending, rate_limit: live.rate_limit };
          st.pass = { step: STEPS[0], rlnId: "00".repeat(32), rate: optionsRate(eopts) || 100 };
          return { registry_id: args[0], state: "unknown", provisioning: provisioningView(st.pass.step) };
        }
        case "register_membership": {
          // Deliberately strict so a call-site regression fails here: the
          // scope pair, then the RegistryOptions array with a decimal-string
          // rate_limit (the module rejects non-string values / non-arrays);
          // a delegated registration must name the allocator, and an
          // auth_type must come with exactly one of auth_payload/auth_provider.
          if (args.length !== 3)
            return err("invalid_argument", "mock: register_membership takes 3 args (registry_id, rln_identifier_hex, options_json), got " + args.length);
          if (!/^(0x)?[0-9a-f]{64}$/.test(String(args[1])))
            return err("invalid_argument", "mock: rln_identifier_hex must be 32-byte hex, got " + args[1]);
          var opts = parseOptions(args[2]);
          if (!opts) return err("invalid_argument", "mock: options_json must be a RegistryOptions array of {key,value} string pairs");
          st.lastRegisterOptions = opts;
          var rate = optionsRate(opts);
          if (!(rate > 0))
            return err("invalid_argument", "mock: rate_limit must be a positive decimal string");
          var o = {};
          for (var oj = 0; oj < opts.length; oj++) o[opts[oj].key] = opts[oj].value;
          if (o.delegated === "true") {
            if (!o.gifter_peer_id || !o.gifter_multiaddr)
              return err("invalid_argument", "mock: delegated registration needs gifter_peer_id and gifter_multiaddr");
            if (o.auth_type && !!o.auth_payload === !!o.auth_provider)
              return err("invalid_argument", "mock: auth_type needs exactly one of auth_payload / auth_provider");
            if (!o.auth_type && (o.auth_payload || o.auth_provider))
              return err("invalid_argument", "mock: auth_payload/auth_provider need an auth_type");
          }
          return mint(args[0], args[1], rate);
        }
        case "get_membership_state": {
          if (args.length !== 2)
            return err("invalid_argument", "mock: get_membership_state takes 2 args (registry_id, rln_identifier_hex), got " + args.length);
          var m = findScoped(args[0], args[1]);
          if (m === "ambiguous") return err("ambiguous_selection", "mock: more than one record backs this scope");
          if (!m) {
            if (st.pass && st.pass.step !== "done")
              return { registry_id: args[0], state: "unknown", provisioning: advancePass(args[0]) };
            return { registry_id: args[0], state: "unknown" };
          }
          // Only a fresh submission settles to the scripted outcome; a settled
          // record keeps its state (the registry overlay never revives a
          // slashed or erased one).
          if (m.state === "pending") {
            if (cfg.registerState === "failed") { m.state = "failed"; m.failed_reason = cfg.registerFailReason; m.retryable = true; return { registry_id: args[0], state: "failed" }; }
            m.state = cfg.registerState;
          }
          if (m.state === "failed") return { registry_id: args[0], state: "failed" };
          return { leaf_index: m.leaf_index, leaf_pending: m.leaf_pending, membership_hash: m.membership_hash, rate_limit: m.rate_limit, registry_id: args[0], state: m.state };
        }
        case "get_membership":
          // lez 7.0.0: leaf_index is optional, absent for a registration this
          // module did not send.
          return { clock_timestamp: 1700003000, grace_period_duration: 600, grace_period_start_timestamp: 1700005580, rate_limit: 300, registered: true, state: cfg.registerState };
        // rln_gifter_module.libp2p_call relays createNode/start: the raw
        // {success,value,error} envelope (error:"" on success).
        case "libp2p_call": return { success: true, value: "", error: "" };
        case "card_status": return { present: st.cardPresent === true };
        case "address": return { address: cfg.ethAddress, persisted: true };
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
    f.unlockPhase = "idle"; f.unlockError = "";
    f.autoUnlockPhase = "idle"; f.autoUnlockKind = ""; f.started = false;
    f.regPhase = "idle"; f.regError = ""; f.regState = ""; f.commitment = ""; f.rateLimitMismatch = false; f.password = "";
    f.provisioning = {}; f.unknownPolls = 0; f.network = "";
    f.registrationMode = "funded"; f.gifterPhase = "idle"; f.gifterStage = ""; f.gifterError = "";
    f.gifterPeerId = ""; f.gifterMultiaddr = ""; f.authType = "none"; f.authArgs = ""; f.ethAddress = ""; f.libp2pNodeReady = false;
    f.rateLimit = ${cfg.rateLimit ?? 300};
    f.statePollMs = 20; f.unknownPollBudget = ${cfg.unknownPollBudget ?? 12};
    f.transientRetryMs = 15; f.transientRetryMax = 3;
    onboardingView.currentStep = 0; onboardingView.priorNotice = ""; root.preAdvancedMode = ""; root.mode = "probe";
    root.registryEdited = false; root.registryId = M.TESTNET_REGISTRY_ID;
    membershipView.celebrate = false; membershipView.completionRefresh = false; membershipView.rows = [];
    ${mockExpr(cfg)};
    return true;
  })()`;
}

async function setup(app, cfg) {
  await evalExpr(app, resetExpr(cfg));
  await evalExpr(app, "root.probe()");
}

// Drive the wizard into the allocator step with the given allocator config
// (auto-unlock skips the password screen), then start it.
async function startAllocator(app, cfg) {
  await waitPhase(app, "autoUnlockPhase", "done");
  // Not app.click: the allocator step's title and the expert view's toggle
  // share the link's text and the click BFS would match an invisible one.
  // Drive the link's handler directly.
  await evalExpr(app, "(function () { onboardingView.flowController.registrationMode = 'allocator'; onboardingView.advance(); return true; })()");
  await waitFor(app, async () => {
    if (await evalExpr(app, "onboardingView.currentStep") !== 2) throw new Error("not on step 2");
  }, "allocator step");
  if (await phase(app, "registrationMode") !== "allocator") throw new Error("mode not allocator");
  await evalExpr(app, `(function () { var f = onboardingView.flowController;
    f.gifterPeerId = ${JSON.stringify(cfg.peerId)}; f.gifterMultiaddr = ${JSON.stringify(cfg.multiaddr)};
    f.authType = ${JSON.stringify(cfg.authType)}; f.authArgs = ${JSON.stringify(cfg.authArgs ?? "")}; return true; })()`);
  await evalExpr(app, "onboardingView.flowController.retryGifter()");
}

const PEER = "16Uiu2HAm8KkYKyhBK5f8ZcSDJP947bxCqVRRbzP8DKDigqePtX2Y";
const MADDR = "/ip4/203.0.113.7/tcp/9000";

function optionsToObject(opts) {
  const o = {};
  for (const { key, value } of opts) o[key] = value;
  return o;
}

// ---- scenarios --------------------------------------------------------------

// 1. Golden funded path: auto-unlock → ensure_membership → the module's
//    provisioning pass (polled) → pending → active; completion lands on the
//    refreshed list, the first membership celebrates, and tapping the pill
//    opens detail. Nothing on the dead wire is ever dialled.
test("flow: golden funded path lands the first membership in a celebrating list", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await waitPhase(app, "autoUnlockPhase", "done");
  if (await phase(app, "password") !== "sec-created") throw new Error("secret not adopted as password");
  const skipped = await evalExpr(app, "onboardingView.passwordSkipped");
  if (skipped !== true) throw new Error("password screen not skipped after auto-unlock");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  const glog = await callLog(app);
  if (!glog.includes("ensure_membership"))
    throw new Error(`funded path did not use ensure_membership: ${glog.join(",")}`);
  if (glog.includes("register_membership"))
    throw new Error("funded path must not call register_membership itself");
  const dead = glog.filter((m) => DEAD_METHODS.includes(m));
  if (dead.length) throw new Error(`dead-wire methods dialled: ${dead.join(",")}`);
  if (await phase(app, "provisioningStep") !== "done") throw new Error("provisioning did not reach done");
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

// 1b. awaiting_funding renders "send <required> to <payer>" from the
//     structured fields, and the flow continues on its own once funded.
test("flow: awaiting_funding shows the payer and the amount, then continues", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active", provisioningHold: "awaiting_funding" });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "provisioningStep", "awaiting_funding");
  await app.expectTexts(["Fund your account", "Send at least", "6000000 native", "ab".repeat(32),
                         "Waiting for funds…"]);
  if (await phase(app, "regPhase") !== "running") throw new Error("flow stopped while awaiting funding");
  await evalExpr(app, "root.bridgeOverride.state.release = true");
  await waitPhase(app, "regPhase", "done", 12000);
  await waitMode(app, "status");
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
//    root.registryId; a valid CAIP-10 edit is adopted, and pins the registry
//    against a later network detection.
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
  const other = "logos:testnet:" + "ab".repeat(32);
  await evalExpr(app, `advancedView.registryEdited(${JSON.stringify(other)})`);
  if (await evalExpr(app, "root.registryId") !== other)
    throw new Error("valid registry edit not adopted");
  // An edited registry is never overridden by the wallet's network.
  await evalExpr(app, "onboardingView.flowController.detectNetwork()");
  await waitFor(app, async () => {
    if (await phase(app, "network") !== "testnet") throw new Error("network not read");
  }, "wallet_status network");
  if (await evalExpr(app, "root.registryId") !== other)
    throw new Error("network detection overrode an edited registry");
});

// 4b. The lez module's bound network selects the registry: a devnet wallet
//     moves the default (testnet) registry to devnet's; an unknown network
//     keeps it.
test("flow: the wallet's network picks the registry from the built-in table", async (app) => {
  await setup(app, { autoUnlock: "created", network: "devnet" });
  await waitMode(app, "onboarding");
  await evalExpr(app, "onboardingView.flowController.detectNetwork()");
  await waitFor(app, async () => {
    const id = await evalExpr(app, "root.registryId");
    const want = await evalExpr(app, "M.KNOWN_REGISTRIES.devnet");
    if (id !== want) throw new Error(`registry ${id}, want ${want}`);
  }, "devnet registry adopted");
  if (await evalExpr(app, "M.registryIdFor('nonet')") !== "") throw new Error("unknown network must map to ''");
});

// 5. New membership via the ghost: a completed run leaves regPhase done; the
//    "+ New Membership" ghost resets it so the re-run re-enters
//    ensure_membership and reaches active.
test("flow: the New Membership ghost re-runs the flow", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  await app.expectTexts(["+ New Membership"]);
  const before = (await callLog(app)).filter((m) => m === "ensure_membership").length;
  // Not app.click: MembershipView's always-instantiated (invisible) ghost
  // shares the text and the click BFS would match it. Drive the ghost's
  // handler (onNewMembershipRequested → restart) directly.
  await evalExpr(app, "onboardingView.restart()");
  await waitFor(app, async () => {
    const n = (await callLog(app)).filter((m) => m === "ensure_membership").length;
    if (n <= before) throw new Error(`no re-run: ensure_membership calls ${n} <= ${before}`);
  }, "re-run to begin", 8000);
  await waitPhase(app, "regPhase", "done", 12000);
});

// 5b. A relaunch into an existing membership never celebrates, and "+ New
//     Membership" on a registry that already holds a live one is idempotent:
//     ensure_membership answers the live membership, no provisioning pass
//     runs, the list keeps its one pill, and nothing celebrates.
test("flow: a re-run on a registry with a live membership is idempotent", async (app) => {
  const cOld = "cc".repeat(32);
  await setup(app, { autoUnlock: "created", registerState: "active",
    memberships: [{ credential: { identity_commitment: cOld }, membership_hash: "ff".repeat(32), leaf_index: 2, rate_limit: 200, state: "active", submitted_at: 1 }] });
  // A usable membership routes straight to the list — a relaunch, so no celebration.
  await waitMode(app, "status");
  const petOld = await evalExpr(app, `M.petname("${cOld}")`);
  await app.expectTexts(["Your Memberships", petOld, "200 msg/epoch", "+ New Membership"]);
  if (await evalExpr(app, "membershipView.celebrate") !== false)
    throw new Error("relaunch into the list must not celebrate");
  await evalExpr(app, "root.startNewMembership()");
  await waitMode(app, "onboarding");
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  await waitMode(app, "status");
  const log = await callLog(app);
  if (!log.includes("ensure_membership")) throw new Error("re-run did not ask ensure_membership");
  if (await phase(app, "provisioningStep") !== "") throw new Error("a provisioning pass ran despite a live membership");
  if (await evalExpr(app, "root.bridgeOverride.state.memberships.length") !== 1)
    throw new Error("a second record was minted on an idempotent re-run");
  await app.expectTexts(["Your Memberships", petOld, "+ New Membership"]);
  if (await evalExpr(app, "membershipView.celebrate") !== false)
    throw new Error("an idempotent re-run must not celebrate");
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

// 6. Error branches: a refused provisioning pass, a failed registration, an
//    "unknown" that never resolves.
test("flow: a refused provisioning pass surfaces its detail with retry", async (app) => {
  await setup(app, { autoUnlock: "created", provisioning: "refused" });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "error", 12000);
  await app.expectTexts(["Setup failed", "Retry"]);
  const err = await phase(app, "regError");
  if (!/refused/.test(err) || !/mock: refused/.test(err))
    throw new Error(`refusal detail missing: ${err}`);
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

test("flow: an unknown state with no provisioning pass fails within its budget", async (app) => {
  // force get_membership_state to never show a record: the mock's pass
  // completes but a forced state view keeps "unknown" without provisioning.
  await setup(app, { autoUnlock: "created", unknownPollBudget: 4 });
  await evalExpr(app, "root.bridgeOverride.state.pass = { step: 'done' }");
  await evalExpr(app, "root.bridgeOverride.state.force = {}");
  await waitPhase(app, "autoUnlockPhase", "done");
  // Make ensure_membership start no pass: pre-mark the pass as done so the
  // state poll answers a bare "unknown".
  await evalExpr(app, `(function () {
    var orig = root.bridgeOverride.callModuleAsync;
    root.bridgeOverride.callModuleAsync = function (module, method, args, cb, t) {
      if (method === "ensure_membership") { root.bridgeOverride.callLog.push(method); Qt.callLater(function () { cb(JSON.stringify({ registry_id: args[0], state: "unknown" })); }); return; }
      if (method === "get_membership_state") { root.bridgeOverride.callLog.push(method); Qt.callLater(function () { cb(JSON.stringify({ registry_id: args[0], state: "unknown" })); }); return; }
      orig(module, method, args, cb, t);
    }; return true; })()`);
  await app.click("Get started");
  await waitPhase(app, "regPhase", "error", 12000);
  if (!/no provisioning in progress/.test(await phase(app, "regError")))
    throw new Error(`unexpected error: ${await phase(app, "regError")}`);
});

// 7. Auto-retry recovery: transient bridge_failure errors on the first
//    ensure_membership calls self-heal — the flow reaches active without
//    surfacing the error.
test("flow: transient error on ensure_membership auto-recovers", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active",
    transientOnce: { ensure_membership: { kind: "bridge_failure", times: 2 } } });
  await waitPhase(app, "autoUnlockPhase", "done");
  await app.click("Get started");
  await waitPhase(app, "regPhase", "done", 12000);
  if (await phase(app, "regError") !== "") throw new Error("transient error leaked to the user");
  const log = await callLog(app);
  const n = log.filter((m) => m === "ensure_membership").length;
  if (n < 3) throw new Error(`expected retries, saw ${n} ensure_membership calls`);
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

// 9. Allocator path, eth-allowlist: the libp2p node comes up through the
//    gifter relay, the device address is read from eth_sign_module, and ONE
//    register_membership carries exactly the delegated options the lidl
//    names — auth_provider, never a payload, no funding key.
test("allocator: eth-allowlist delegates with the producer module as auth_provider", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await startAllocator(app, { peerId: PEER, multiaddr: MADDR, authType: "eth-allowlist" });
  await waitPhase(app, "regPhase", "done", 12000);
  if (await phase(app, "gifterPhase") !== "done") throw new Error("gifterPhase did not settle to done");
  if (await phase(app, "ethAddress") !== "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025")
    throw new Error("device address not read from eth_sign_module");
  const log = await callLog(app);
  for (const m of ["libp2p_call", "address", "register_membership"])
    if (!log.includes(m)) throw new Error(`${m} not dialled: ${log.join(",")}`);
  if (log.includes("ensure_membership")) throw new Error("allocator path must not call ensure_membership");
  if (log.includes("card_status")) throw new Error("eth path must not poll the card");
  const opts = await lastRegisterOptions(app);
  // The allocator path asks for the registry minimum (the gifter's default
  // cap), not the funded path's default rate.
  const want = [
    { key: "rate_limit", value: "100" }, { key: "delegated", value: "true" },
    { key: "gifter_peer_id", value: PEER }, { key: "gifter_multiaddr", value: MADDR },
    { key: "auth_type", value: "eth-allowlist" }, { key: "auth_provider", value: "eth_sign_module" }];
  if (JSON.stringify(opts) !== JSON.stringify(want))
    throw new Error(`delegated options differ:\n got ${JSON.stringify(opts)}\nwant ${JSON.stringify(want)}`);
  await waitMode(app, "status");
});

// 9b. Allocator path, keycard: gated on card presence, then the capture
//     module is the provider; auth_args rides along verbatim.
test("allocator: keycard waits for the card, then delegates with the capture module", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active", cardPresent: false });
  await startAllocator(app, { peerId: PEER, multiaddr: MADDR, authType: "keycard-attestation", authArgs: '{"slot":1}' });
  await waitPhase(app, "gifterStage", "capture");
  await app.expectTexts(["Hold your Keycard on the reader…"]);
  if ((await callLog(app)).includes("register_membership")) throw new Error("registered before the card was present");
  await evalExpr(app, "root.bridgeOverride.state.cardPresent = true");
  await waitPhase(app, "regPhase", "done", 12000);
  const o = optionsToObject(await lastRegisterOptions(app));
  if (o.auth_type !== "keycard-attestation" || o.auth_provider !== "keycard_capture_module")
    throw new Error(`keycard options wrong: ${JSON.stringify(o)}`);
  if (o.auth_args !== '{"slot":1}') throw new Error(`auth_args not forwarded: ${JSON.stringify(o)}`);
  if (!(await callLog(app)).includes("card_status")) throw new Error("card_status never polled");
});

// 9c. Allocator path, open: no auth keys at all.
test("allocator: an open allocator gets no auth keys", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "active" });
  await startAllocator(app, { peerId: PEER, multiaddr: MADDR, authType: "none" });
  await waitPhase(app, "regPhase", "done", 12000);
  const o = optionsToObject(await lastRegisterOptions(app));
  if (o.delegated !== "true" || o.gifter_peer_id !== PEER) throw new Error(`open options wrong: ${JSON.stringify(o)}`);
  for (const k of ["auth_type", "auth_provider", "auth_payload", "auth_args", "funding_holding_account_id"])
    if (k in o) throw new Error(`unexpected key ${k} in open-allocator options`);
  const log = await callLog(app);
  if (log.includes("address") || log.includes("card_status")) throw new Error("open path must not touch a producer");
});

// 9d. Allocator path, refusal: the module's failed record (e.g. the gifter
//     refused the credential) surfaces with Try again on the allocator step.
test("allocator: a failed delegated registration surfaces the reason", async (app) => {
  await setup(app, { autoUnlock: "created", registerState: "failed", registerFailReason: "gifter refused: credential already used" });
  await startAllocator(app, { peerId: PEER, multiaddr: MADDR, authType: "eth-allowlist" });
  await waitPhase(app, "regPhase", "error", 12000);
  if (await phase(app, "gifterPhase") !== "error") throw new Error("gifterPhase did not settle to error");
  await app.expectTexts(["Try again"]);
  // expectTexts matches whole element texts; the reason is part of the
  // fine-print sentence, so read it from the flow.
  if (!/credential already used/.test(await phase(app, "regError")))
    throw new Error(`failed_reason missing: ${await phase(app, "regError")}`);
});

// 10. Petname determinism, evaluated against the real M.petname.
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

// Since rln 0.15.0 / lez 7.0.0 the leaf index arrives once the registry module
// reports the claim of the registration that landed: until then the view says
// leaf_pending with a placeholder leaf_index of 0, and the UI must say
// "pending", not "0" — leaf 0 is a real leaf.
test("an unindexed membership shows its leaf as pending, an indexed leaf 0 as 0", async (app) => {
  const c = "aa".repeat(32), c2 = "cc".repeat(32);
  await setup(app, { memberships: [
    { credential: { identity_commitment: c }, membership_hash: "ee".repeat(32), leaf_index: 0, leaf_pending: true, rate_limit: 300, state: "active", submitted_at: 1 },
    { credential: { identity_commitment: c2 }, membership_hash: "ff".repeat(32), leaf_index: 0, rate_limit: 100, state: "active", submitted_at: 1 }] });
  if (await evalExpr(app, `M.fmtLeaf({ leaf_index: 0, leaf_pending: true })`) !== "pending")
    throw new Error("leaf_pending must render as pending");
  if (await evalExpr(app, `M.fmtLeaf({ leaf_index: 0 })`) !== "0")
    throw new Error("an indexed leaf 0 must render as 0");
  if (await evalExpr(app, `M.fmtLeaf({})`) !== "—")
    throw new Error("an absent leaf renders the placeholder");
  await evalExpr(app, `root.showDetail("${c}")`);
  await waitMode(app, "detail");
  await waitFor(app, async () => {
    if (await evalExpr(app, "detailCard.found") !== true) throw new Error("card not loaded");
  }, "detail card to load");
  // Through both reads: get_memberships and the get_membership_state poll.
  await waitFor(app, async () => {
    if (await evalExpr(app, "detailCard.refreshing") !== false) throw new Error("still refreshing");
  }, "detail refresh to settle");
  if (await evalExpr(app, "detailCard.leaf") !== "pending")
    throw new Error(`unindexed leaf shown as ${await evalExpr(app, "detailCard.leaf")}`);
});

// 11. Regression: detail "Refresh status" under a flaky transport must not
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
