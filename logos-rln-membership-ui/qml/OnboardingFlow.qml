// Non-visual onboarding controller. The wizard runs the keystore password
// first (its step's Next fires checkPassword), then ONE of two registration
// paths, both ending in the shared confirmation poll (pollRegistration):
//
//   funded     ensure_membership: the membership module provisions the
//              registry-wide membership itself — selects the network, waits
//              for its payer to hold price + fee reserve (the UI shows "send
//              <required> to <payer>" from the structured provisioning
//              object), registers — and this flow only polls.
//   allocator  one delegated register_membership: the module mints the
//              identity, asks the configured producer module for an auth
//              payload bound to it, dials the allocator over libp2p, and the
//              allocator pays. This flow brings the libp2p node up and gates
//              on what the chosen auth vector needs (card present, eth
//              address known).
//
// Sequential idempotent phases with observable progress. The expert
// RegisterView duplicates the register call; both build their options
// through membership.js (registryOptions / delegatedOptions). An Item (not
// QtObject) so it can own the poll Timers.
import QtQuick
import "membership.js" as M

Item {
    id: flow
    objectName: "flowController"
    visible: false

    required property var bridge
    required property string registryId

    // The keystore password (manual entry, or the auto-unlock secret).
    property string password: ""
    property int rateLimit: M.RATE_LIMIT_DEFAULT
    // The allocator path asks for the registry minimum: rln_gifter_module
    // clamps every request to its serve-time maxRateLimit (default 100)
    // WITHOUT saying so, and the membership module then flags the granted
    // rate as rate_limit_mismatch against what was asked. An allocator
    // configured for more can be matched from the expert Register tab.
    property int delegatedRateLimit: M.RATE_LIMIT_MIN
    property string priorNotice: ""

    // Set by Main from the startup probe (any local membership records ->
    // true); the password step frames itself as creation vs entry from it.
    property bool hasExistingAccount: false

    // Phase C — keystore password check (fired by the password step's Next).
    property string unlockPhase: "idle"
    property string unlockError: ""

    // Phase C′ — OS-keychain auto-unlock, fired by Main when routing into
    // onboarding. "done": unlockPhase is done and flow.password carries the
    // keychain secret. "fallback": the password screen runs manually;
    // autoUnlockKind carries the error kind.
    property string autoUnlockPhase: "idle"
    property string autoUnlockKind: ""
    // Set true by OnboardingView once the flow leaves Welcome; fences a late
    // startAutoUnlock from re-deciding the password path mid-flow. Reset by
    // restart().
    property bool started: false

    // Test-tunable poll cadence for the confirmation poll.
    property int statePollMs: 10000

    // Backoff and budget for callRetry's auto-retry of TRANSIENT failures;
    // test-tunable.
    property int transientRetryMs: 1500
    property int transientRetryMax: 4

    // True once the push channel is armed on this bridge (M.armModuleEvent);
    // false on hosts without onModuleEvent, where polling is the only
    // channel. MembershipCard reads this flag instead of arming a second
    // subscription for the same (module, event) pair.
    property bool eventsArmed: false

    // The network the lez module's wallet is bound to (wallet_status), ""
    // until read or unbound. Main adopts the matching built-in registry
    // through registryDetected.
    property string network: ""

    // Phase E — registration + confirmation poll. Both paths land here.
    // regPhase: idle | running | done | error. regState mirrors the last
    // get_membership_state (unknown while the module provisions).
    property string regPhase: "idle"
    property string regError: ""
    property string regState: ""
    property string commitment: ""
    property bool rateLimitMismatch: false
    // The module's provisioning object while a funded pass runs (see
    // M.provisioningLabel): {} outside one.
    property var provisioning: ({})
    readonly property string provisioningStep: provisioning && provisioning.step ? String(provisioning.step) : ""
    // "unknown" with no pass in flight is bounded: after unknownPollBudget
    // polls the flow fails instead of spinning forever.
    property int unknownPolls: 0
    property int unknownPollBudget: 12

    // ---- Allocator path --------------------------------------------------
    // "allocator" replaces ensure_membership with one delegated
    // register_membership call. Set on Welcome; reset by
    // resetForNewRegistration.
    property string registrationMode: "funded"
    // gifterPhase: idle | running | done | error. gifterStage is the running
    // sub-step (node -> capture | address) for the progress caption.
    property string gifterPhase: "idle"
    property string gifterStage: ""
    property string gifterError: ""
    // The allocator's identity: what its operator published (allocator.json
    // / the serve output). No default — the peer id is the trust anchor.
    property string gifterPeerId: ""
    property string gifterMultiaddr: ""
    // The auth vector (M.AUTH_VECTORS id) and its optional producer args
    // (a JSON string, forwarded verbatim as auth_args).
    property string authType: "none"
    property string authArgs: ""
    // eth-allowlist: this device's address (eth_sign_module.address), shown
    // so the allocator's operator can allowlist it before the request.
    property string ethAddress: ""
    // createNode + start run once per session; retries and later
    // registrations reuse the node.
    property bool libp2pNodeReady: false
    // Card-presence gate before the delegated register: gating keeps the
    // module's background capture + dial + register chain inside its 300s
    // pending confirmation window.
    property int cardWaitPolls: 0
    property int cardWaitBudget: 40

    Component.onCompleted: {
        flow.eventsArmed = M.armModuleEvent(flow.bridge, M.RLN_MODULE, M.MEMBERSHIP_STATE_CHANGED)
    }

    // Fired by finish() when the user leaves the completed wizard.
    signal completed(string commitment)
    // The lez module's wallet is bound to a network with a known registry.
    signal registryDetected(string registryId)

    function finish() {
        completed(commitment)
    }

    // Bounded auto-retry around M.call: a TRANSIENT error (M.isTransientError)
    // retries after transientRetryMs, up to transientRetryMax times; any other
    // error is delivered immediately. Each retry gets its own one-shot Timer.
    function callRetry(module, method, args, cb, timeoutMs) {
        callRetryAttempt(module, method, args, cb, 0, timeoutMs)
    }

    function callRetryAttempt(module, method, args, cb, attempt, timeoutMs) {
        M.call(bridge, module, method, args, function (r) {
            if (r.error && M.isTransientError(r.error) && attempt < flow.transientRetryMax) {
                var t = retryTimerComponent.createObject(flow, { interval: flow.transientRetryMs })
                t.triggered.connect(function () {
                    t.destroy()
                    flow.callRetryAttempt(module, method, args, cb, attempt + 1, timeoutMs)
                })
                t.start()
            } else {
                cb(r)
            }
        }, timeoutMs)
    }

    // wallet_status never touches the chain and answers before the first
    // sync: its `network` (since lez 4.1.0) names the registry table entry
    // to prefill. "" (unbound, operator-configured, or an error) keeps the
    // default. Main fires this after a SUCCESSFUL startup probe only: with
    // no backend loaded every bridge request blocks for its full timeout,
    // and a second one at startup would hold the host's event loop long
    // enough to miss the test harness's inspector window.
    function detectNetwork() {
        M.call(bridge, M.LEZ_RLN_MODULE, "wallet_status", [], function (r) {
            if (r.error || !r.network)
                return
            flow.network = String(r.network)
            var id = M.registryIdFor(flow.network)
            if (id !== "")
                flow.registryDetected(id)
        }, 8000)
    }

    // Reset for a NEW registration after a completed run: registration goes
    // back to idle so the re-run runs fresh. The libp2p node, if up, stays up.
    function resetForNewRegistration() {
        if (regPhase !== "running") {
            regPhase = "idle"
            regError = ""
            regState = ""
            commitment = ""
            rateLimitMismatch = false
            provisioning = {}
            unknownPolls = 0
        }
        // A re-run re-offers the Welcome choice.
        registrationMode = "funded"
        if (gifterPhase !== "running") {
            gifterPhase = "idle"
            gifterStage = ""
            gifterError = ""
        }
    }

    // ---- Phase C: keystore password ---------------------------------------
    // mirrors RegisterView.doUnlock — keep in sync. With an empty keystore
    // any password unlocks and becomes the encryption password at first
    // write.
    function checkPassword() {
        if (unlockPhase === "running" || unlockPhase === "done")
            return
        unlockPhase = "running"
        unlockError = ""
        callRetry(M.RLN_MODULE, "unlock_keystore", [password], function (r) {
            if (r.error) {
                flow.unlockPhase = "error"
                flow.unlockError = M.errorText(r.error)
                return
            }
            flow.unlockPhase = r.unlocked === true ? "done" : "error"
            if (flow.unlockPhase === "error") {
                flow.unlockError = "unlock_keystore did not unlock: " + JSON.stringify(r)
            } else if (flow.autoUnlockPhase === "fallback") {
                // Persist the password module-side after a keychain miss (the
                // plaintext never re-crosses the wire); fire-and-forget.
                M.call(bridge, M.RLN_MODULE, "remember_keystore_password", [], function (r2) {
                    if (r2.error)
                        console.warn("remember_keystore_password:", r2.error.kind, r2.error.message)
                })
            }
        })
    }

    // ---- Phase C′: OS-keychain auto-unlock ----------------------------------
    // The module fetches (or generates + persists) the keystore secret from
    // the macOS Keychain and unlocks with it; the reply's secret becomes
    // flow.password. Any failure routes to "fallback": the manual password
    // screen.
    function startAutoUnlock() {
        if (autoUnlockPhase === "running" || autoUnlockPhase === "done")
            return
        if (started)
            return
        if (unlockPhase === "done") {
            // A manual unlock already happened — never clobber it.
            autoUnlockPhase = "done"
            return
        }
        autoUnlockPhase = "running"
        autoUnlockKind = ""
        callRetry(M.RLN_MODULE, "unlock_keystore_auto", [], function (r) {
            if (r.error || r.unlocked !== true
                    || (r.source === "created" && !r.secret)) {
                flow.autoUnlockKind = r.error ? String(r.error.kind) : "bad_reply"
                flow.autoUnlockPhase = "fallback"
                return
            }
            flow.password = r.secret ? String(r.secret) : ""
            flow.unlockPhase = "done"
            flow.autoUnlockPhase = "done"
        })
    }

    // ---- Phase E (funded): ensure_membership + confirmation poll ------------
    // ensure_membership answers from the local records: a live membership of
    // any scope on the registry comes back as its state view; none spawns the
    // module's own provisioning pass and answers {"state":"unknown",
    // "provisioning":{…}}. Either way the shared poll drives regPhase to
    // completion; the provisioning object is re-read on every poll.
    function startRegistration() {
        if (regPhase === "running" || regPhase === "done")
            return
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        provisioning = {}
        unknownPolls = 0
        callRetry(M.RLN_MODULE, "ensure_membership",
               [registryId, M.registryOptions(rateLimit, {})], function (r) {
            if (r.error) { flow.regPhase = "error"; flow.regError = M.errorText(r.error); return }
            flow.commitment = (r.credential && r.credential.identity_commitment) || ""
            flow.regState = r.state || "unknown"
            flow.rateLimitMismatch = r.rate_limit_mismatch === true
            if (r.provisioning)
                flow.provisioning = r.provisioning
            if (flow.regState === "active" || flow.regState === "grace_period") {
                flow.regPhase = "done"
                return
            }
            regTimer.start()
        })
    }

    function retryRegistration() {
        if (regPhase === "running")
            return
        regPhase = "idle"
        if (registrationMode === "allocator")
            retryGifter()
        else
            startRegistration()
    }

    // mirrors RegisterView.pollState — keep in sync. The module bounds the
    // pending window at 300s, so this poll always terminates once a record
    // exists; "unknown" is bounded by unknownPollBudget once no provisioning
    // pass is reported. A TRANSIENT error is tolerated by continuing — the
    // next tick re-reads; only a non-transient error stops and fails.
    function pollRegistration() {
        M.call(bridge, M.RLN_MODULE, "get_membership_state",
               [registryId, M.DEFAULT_RLN_ID], function (r) {
            if (r.error) {
                if (M.isTransientError(r.error))
                    return
                regTimer.stop()
                flow.regPhase = "error"
                flow.regError = M.errorText(r.error)
                flow.settleGifter()
                return
            }
            flow.regState = r.state || "unknown"
            if (r.provisioning)
                flow.provisioning = r.provisioning
            if (flow.regState === "pending") {
                flow.unknownPolls = 0
                return
            }
            if (flow.regState === "unknown") {
                var step = flow.provisioningStep
                if (step === "refused") {
                    regTimer.stop()
                    flow.regPhase = "error"
                    flow.regError = "Registration refused"
                        + (flow.provisioning.detail ? ": " + String(flow.provisioning.detail) : "")
                    flow.settleGifter()
                    return
                }
                // A pass in flight: keep polling. Past "done" (or with no
                // pass at all) the record must appear within the budget.
                if (r.provisioning && step !== "done")
                    return
                flow.unknownPolls += 1
                if (flow.unknownPolls < flow.unknownPollBudget)
                    return
                regTimer.stop()
                flow.regPhase = "error"
                flow.regError = "The module reports no membership and no provisioning in "
                    + "progress for this registry."
                flow.settleGifter()
                return
            }
            regTimer.stop()
            if (flow.regState === "active" || flow.regState === "grace_period") {
                flow.regPhase = "done"
            } else if (flow.regState === "failed") {
                flow.fetchFailureReason()
                return
            } else {
                flow.regPhase = "error"
                flow.regError = "Registration settled in state \"" + flow.regState + "\"."
            }
            flow.settleGifter()
        })
    }

    // The allocator path settles with the registration itself.
    function settleGifter() {
        if (registrationMode === "allocator" && gifterPhase === "running") {
            gifterStage = ""
            gifterPhase = regPhase === "done" ? "done" : "error"
        }
    }

    // The merged-state view carries no reason; the memberships row does
    // (failed_reason, plus retryable — spec: a failed submission SHALL
    // report whether it is retryable; never present without the reason).
    // The funded path may not know its commitment (ensure_membership's pass
    // registers in the background), so the newest failed row stands in.
    function fetchFailureReason() {
        callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            var reason = ""
            var retryable
            if (!r.error) {
                var rows = r.memberships || []
                for (var i = rows.length - 1; i >= 0; i--) {
                    var full = rows[i].credential ? rows[i].credential.identity_commitment : ""
                    var mine = flow.commitment !== "" ? full === flow.commitment
                                                      : rows[i].state === "failed"
                    if (mine && rows[i].failed_reason) {
                        reason = String(rows[i].failed_reason)
                        retryable = rows[i].retryable
                        break
                    }
                }
            }
            flow.regPhase = "error"
            flow.regError = "Registration FAILED" + (reason !== "" ? ": " + reason : "")
                + (retryable === false
                   ? " — the module reports this failure is not retryable as-is: fix the "
                     + "cause (funding, registry, allocator) before trying again."
                   : " — Try again re-registers with a fresh identity.")
            flow.settleGifter()
        })
    }

    // ---- Allocator path ------------------------------------------------------
    // Bring up the transport, satisfy the chosen vector's gate, then hand the
    // whole delegated flow to the membership module with one
    // register_membership call; the shared poll tail drives regPhase.
    function startGifter() {
        if (gifterPhase === "running" || gifterPhase === "done")
            return
        gifterPhase = "running"
        gifterError = ""
        gifterStage = "node"
        ensureLibp2pNode(function (nodeErr) {
            if (nodeErr) { flow.failGifter(nodeErr); return }
            var gate = M.authVector(flow.authType).gate
            if (gate === "card") {
                flow.gifterStage = "capture"
                flow.cardWaitPolls = 0
                flow.pollCardThenRegister()
            } else if (gate === "address") {
                flow.gifterStage = "address"
                flow.fetchEthAddress(function (err) {
                    if (err) { flow.failGifter(err); return }
                    flow.registerDelegated()
                })
            } else {
                flow.registerDelegated()
            }
        })
    }

    function retryGifter() {
        if (gifterPhase === "running")
            return
        gifterPhase = "idle"
        startGifter()
    }

    function failGifter(msg) {
        flow.gifterStage = ""
        flow.gifterPhase = "error"
        flow.gifterError = msg
    }

    // Every libp2p_module call is relayed through rln_gifter_module.libp2p_call
    // — direct libp2p replies marshal to null over the QML bridge. argObj is
    // the method's single object arg (undefined for none); cb gets the parsed
    // {success,value,error}.
    function libp2pCall(method, argObj, cb, timeoutMs) {
        if (!bridge) { cb({ error: "no bridge" }); return }
        var args = (argObj === undefined || argObj === null) ? [] : [JSON.stringify(argObj)]
        bridge.callModuleAsync(M.GIFTER_MODULE, "libp2p_call",
            [JSON.stringify({ method: method, args: args })], function (raw) {
                cb(M.parseLibp2pReply(raw))
            }, timeoutMs === undefined ? 30000 : timeoutMs)
    }

    // A plain libp2p node (createNode + start, no RLN/mix context) suffices
    // to dial the allocator. The FIRST libp2p_call can race libp2p_module's
    // token registration ("auth token not recognized"/"Invalid response");
    // createNodeAttempt retries those.
    function ensureLibp2pNode(cb) {
        if (libp2pNodeReady) { cb(""); return }
        flow.createNodeAttempt(0, cb)
    }

    function createNodeAttempt(attempt, cb) {
        flow.libp2pCall("createNode", M.LIBP2P_NODE_CONFIG, function (r) {
            var err = M.libp2pError(r)
            if (err !== "" && err.indexOf("already") === -1) {
                var racey = err.indexOf("token") !== -1 || err.indexOf("Invalid response") !== -1
                          || err.indexOf("not recognized") !== -1 || err.indexOf("not connected") !== -1
                if (attempt < 8 && racey) {
                    var t = retryTimerComponent.createObject(flow, { interval: 700 })
                    t.triggered.connect(function () { t.destroy(); flow.createNodeAttempt(attempt + 1, cb) })
                    t.start()
                    return
                }
                cb("Could not create the peer-to-peer node: " + err)
                return
            }
            flow.libp2pCall("start", undefined, function (r2) {
                var e2 = M.libp2pError(r2)
                if (e2 !== "" && e2.indexOf("already") === -1) {
                    cb("Could not start the peer-to-peer node: " + e2)
                    return
                }
                flow.libp2pNodeReady = true
                cb("")
            })
        })
    }

    // Wait for a Keycard on the reader before delegating: the in-module
    // capture starts right after register() is dispatched, and presence keeps
    // the background chain inside the module's pending confirmation window.
    function pollCardThenRegister() {
        M.call(bridge, M.CAPTURE_MODULE, "card_status", [], function (r) {
            // A reader/module fault is not "no card yet" — surface the real
            // cause immediately.
            if (r.error) { flow.failGifter(M.errorText(r.error)); return }
            if (r.present === true) { flow.registerDelegated(); return }
            flow.cardWaitPolls += 1
            if (flow.cardWaitPolls >= flow.cardWaitBudget) {
                flow.failGifter("No Keycard detected. Place your card on the reader and try again.")
                return
            }
            var t = retryTimerComponent.createObject(flow, { interval: 1500 })
            t.triggered.connect(function () { t.destroy(); flow.pollCardThenRegister() })
            t.start()
        })
    }

    // eth-allowlist: read (and on first use mint) this device's signing
    // address from the producer module, so the user can hand it to the
    // allocator's operator before registering. cb(errorText) is optional.
    function fetchEthAddress(cb) {
        M.call(bridge, M.ETH_SIGN_MODULE, "address", [], function (r) {
            if (r.error || !r.address) {
                var msg = r.error ? M.errorText(r.error) : "eth_sign_module returned no address"
                if (cb) cb("Couldn't read this device's Ethereum address: " + msg)
                return
            }
            flow.ethAddress = String(r.address)
            if (cb) cb("")
        })
    }

    // The one delegated call: register_membership generates the identity
    // in-module and returns the pending membership immediately; the module
    // then asks the producer, dials, and registers in the background.
    // Confirmation comes through the shared poll.
    function registerDelegated() {
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        provisioning = {}
        var options = M.delegatedOptions(delegatedRateLimit, {
            peerId: gifterPeerId,
            multiaddr: gifterMultiaddr,
            authType: authType,
            authArgs: authArgs
        })
        callRetry(M.RLN_MODULE, "register_membership",
               [registryId, M.DEFAULT_RLN_ID, options], function (r) {
            if (r.error) {
                flow.regPhase = "error"
                flow.regError = M.errorText(r.error)
                flow.failGifter(M.errorText(r.error))
                return
            }
            flow.commitment = (r.credential && r.credential.identity_commitment) || ""
            flow.regState = r.state || "pending"
            flow.rateLimitMismatch = r.rate_limit_mismatch === true
            regTimer.start()
        })
    }

    Timer {
        id: regTimer
        // Events only tighten latency, never replace the poll: armed widens
        // the interval to a 60s slow-poll safety net — except while the
        // module's provisioning pass runs, whose captions and funding
        // numbers come from this poll alone.
        interval: (flow.eventsArmed && flow.provisioningStep === "") ? 60000 : flow.statePollMs
        repeat: true
        onTriggered: flow.pollRegistration()
    }

    // One-shot backoff timer for callRetry, instantiated per retry and
    // self-destroyed on fire.
    Component {
        id: retryTimerComponent
        Timer { repeat: false }
    }

    // Wake-up only, never a data source: pollRegistration's
    // get_membership_state stays the sole authority on state. Any state
    // change on our registry (even another registrant's) wakes the poll
    // early — one extra idempotent read at most. Gated on regTimer.running
    // so events outside an active confirmation wait are no-ops.
    Connections {
        target: flow.bridge
        enabled: flow.eventsArmed
        function onModuleEventReceived(moduleName, eventName, data) {
            if (moduleName !== M.RLN_MODULE || eventName !== M.MEMBERSHIP_STATE_CHANGED)
                return
            var evt = M.decodeMembershipStateChanged(data)
            if (evt && evt.registry_id === flow.registryId && regTimer.running)
                flow.pollRegistration()
        }
    }
}
