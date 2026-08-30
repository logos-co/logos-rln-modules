// Non-visual onboarding controller: wallet -> sync -> keystore password ->
// faucet claim -> registration, as sequential idempotent phases with
// observable progress. Each phase duplicates an Advanced view's logic and
// carries a "mirrors <view>.<fn> — keep in sync" cross-reference. An Item
// (not QtObject) so it can own the poll Timers.
import QtQuick
import "membership.js" as M

Item {
    id: flow
    visible: false

    required property var bridge
    required property string registryId

    // Single password for both stores (wallet storage + keystore); frozen by
    // the password step once walletCreated — create_new consumed it.
    property string password: ""
    property int rateLimit: M.RATE_LIMIT_DEFAULT
    property string priorNotice: ""

    // Set by Main from the startup probe (any local membership records ->
    // true); the password step frames itself as creation vs entry from it.
    property bool hasExistingAccount: false

    // Phase A — wallet (provision + open/create).
    property string walletPhase: "idle"
    property string walletError: ""
    // Captured from create_new but not displayed; kept for a future
    // recovery/export surface.
    property string mnemonic: ""
    property bool walletCreated: false

    // Phase B — sync (auto-chained after A).
    property string syncPhase: "idle"
    property string syncError: ""
    property int syncTarget: 0
    // The wallet's block when this sync began — the progress bar's origin.
    property int syncStart: 0
    property int lastSynced: -1
    // Total sync_to_block calls this run (hard global bound).
    property int syncAttempts: 0
    property bool syncToppedUp: false
    // Sync throughput varies wildly: ~110–180 blocks/s when first measured
    // (2026-08-04), but ~8–10 blocks/s for the v0.2.2 wallet against the
    // hosted testnet (2026-08-14). 250-block chunks keep one chunk near ~30s
    // even at the slow end, so the bar still ticks and the probe loop can
    // tell "slow" from "stuck".
    readonly property int syncChunk: 250
    // The wallet module serves NO reads while a sync_to_block runs: a slow
    // chunk outlives the bridge reply, and progress probes queue behind it —
    // both come back bridge_failure while the wallet keeps syncing
    // underneath. So the chunk reply is advisory; probeChunk re-checks every
    // syncProbeMs and declares failure only after syncProbePatienceMs with
    // NO block progress (any advance resets the patience). Test-tunable.
    property int syncProbeMs: 3000
    property int syncProbePatienceMs: 180000
    property int syncChunkTarget: 0
    property double syncProbeDeadline: 0

    // Phase C — keystore password check (fired by the password step's Next).
    property string unlockPhase: "idle"
    property string unlockError: ""

    // Phase C′ — OS-keychain auto-unlock, fired by Main when routing into
    // onboarding. "done": unlockPhase is done and flow.password carries the
    // keychain secret (it feeds create_new too). "fallback": the password
    // screen runs manually; autoUnlockKind carries the error kind.
    property string autoUnlockPhase: "idle"
    property string autoUnlockKind: ""
    // Set true by OnboardingView once the flow leaves Welcome; fences a late
    // startAutoUnlock from re-deciding the password path mid-flow. Reset by
    // restart().
    property bool started: false

    // Test-tunable poll cadences. claimPollBudget x claimPollMs bounds the
    // claim timeout (36 x 5s = 180s in production).
    property int claimPollMs: 5000
    property int claimPollBudget: 36
    property int statePollMs: 10000

    // Backoff and budget for callRetry's auto-retry of TRANSIENT failures;
    // test-tunable. claim/create_new are never auto-retried.
    property int transientRetryMs: 1500
    property int transientRetryMax: 4

    // True once the push channel is armed on this bridge (M.armModuleEvent);
    // false on hosts without onModuleEvent, where polling is the only
    // channel. MembershipCard reads this flag instead of arming a second
    // subscription for the same (module, event) pair.
    property bool eventsArmed: false

    // Phase D — faucet claim into a fresh holding.
    property string fundPhase: "idle"
    property string fundError: ""
    property string pricePerUnit: ""
    property int claimAmount: 0
    property string holdingHex: ""
    property int claimPolls: 0

    // Phase E — registration + confirmation poll. register() generates the
    // identity credential in-module; this flow only sees the public
    // commitment from its reply.
    property string regPhase: "idle"
    property string regError: ""
    property string regState: ""
    property string commitment: ""
    property bool rateLimitMismatch: false

    // ---- Gifter path (alternative to Phases A/B/D) -------------------------
    // "gifter" replaces wallet-provision + sync + faucet with one delegated
    // register() call: the membership module generates the identity, the
    // capture module produces an attestation bound to its commitment, and
    // the gifter node pays for the registration. The Phase E poll tail
    // handles confirmation. Set on Welcome; reset by resetForNewRegistration.
    property string registrationMode: "wallet"
    // gifterPhase: idle | running | done | error. gifterStage is the running
    // sub-step (wallet -> node -> capture) for the progress caption.
    property string gifterPhase: "idle"
    property string gifterStage: ""
    property string gifterError: ""
    property string gifterPeerId: M.GIFTER_PEER_ID_DEFAULT
    property string gifterMultiaddr: M.GIFTER_MULTIADDR_DEFAULT
    // createNode + start run once per session; retries and later gifted
    // memberships reuse the node.
    property bool libp2pNodeReady: false
    // The gifter pays for registration, but the client still needs an OPEN
    // wallet for on-chain reads ("Null wallet handle" otherwise).
    // Provisioned + opened once, unfunded, unsynced.
    property bool gifterWalletReady: false
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
            if (r.error && M.isTransientError(r.error.kind) && attempt < flow.transientRetryMax) {
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

    // Reset for a NEW registration after a completed run: funding,
    // registration, and sync go back to idle so the re-run runs fresh
    // (registering against a stale sync head drops the claim into the 180s
    // timeout); the wallet phase stays done.
    function resetForNewRegistration() {
        if (syncPhase !== "running") {
            syncPhase = "idle"
            syncError = ""
            syncStart = 0
            lastSynced = -1
            syncTarget = 0
        }
        if (fundPhase !== "running") {
            fundPhase = "idle"
            fundError = ""
        }
        if (regPhase !== "running") {
            regPhase = "idle"
            regError = ""
            regState = ""
            commitment = ""
            rateLimitMismatch = false
        }
        // A re-run re-offers the Welcome choice; the libp2p node, if up,
        // stays up.
        registrationMode = "wallet"
        if (gifterPhase !== "running") {
            gifterPhase = "idle"
            gifterStage = ""
            gifterError = ""
        }
    }

    // ---- Phase A: wallet ---------------------------------------------------
    // mirrors WalletView.doProvision — keep in sync
    function startWallet() {
        if (walletPhase === "running" || walletPhase === "done")
            return
        walletPhase = "running"
        walletError = ""
        callRetry(M.RLN_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: M.TESTNET_SEQUENCER_ADDR })], function (r) {
            if (r.error) { flow.walletPhase = "error"; flow.walletError = M.errorText(r.error); return }
            if (r.storage_exists === true)
                flow.openWallet(String(r.config_path || ""), String(r.storage_path || ""))
            else
                flow.createWallet(String(r.config_path || ""), String(r.storage_path || ""))
        })
    }

    // mirrors WalletView.doOpen — keep in sync. A daemon-lifetime wallet from
    // a previous run reports open != 0; a working chain-head read proves it
    // is still usable.
    function openWallet(configPath, storagePath) {
        callRetry(M.WALLET_MODULE, "open",
               [configPath, storagePath, M.statsPathFor(storagePath)], function (r) {
            if (!r.error && r.value === 0) {
                flow.walletPhase = "done"
                flow.startSync()
                return
            }
            callRetry(M.WALLET_MODULE, "get_current_block_height", [], function (r2) {
                if (!r2.error && r2.value > 0) {
                    flow.walletPhase = "done"
                    flow.startSync()
                } else {
                    flow.walletPhase = "error"
                    flow.walletError = r.error ? M.errorText(r.error)
                        : "open returned status " + r.value + " and the wallet answers no "
                          + "chain-head probe — wrong files, or the wallet module is wedged."
                }
            })
        })
    }

    // mirrors WalletView.doCreateFresh — keep in sync
    function createWallet(configPath, storagePath) {
        M.call(bridge, M.WALLET_MODULE, "create_new",
               [configPath, storagePath, M.statsPathFor(storagePath), password], function (r) {
            if (r.error) {
                // create_new returns "" (-> empty_reply) when a DIFFERENT
                // wallet is already open in the daemon; that wallet is
                // usable, so recover by opening it.
                if (r.error.kind === "empty_reply") { flow.openWallet(configPath, storagePath); return }
                flow.walletPhase = "error"; flow.walletError = M.errorText(r.error); return
            }
            var words = r.value !== undefined ? String(r.value) : ""
            if (words === "") {
                flow.openWallet(configPath, storagePath)
                return
            }
            flow.mnemonic = words
            flow.walletCreated = true
            M.call(bridge, M.WALLET_MODULE, "save", [], function (r2) {
                flow.walletPhase = "done"
                flow.startSync()
            })
        })
    }

    // ---- Phase B: sync -----------------------------------------------------
    // mirrors WalletView.startSync — keep in sync; execution is chunked here
    // (see syncChunkStep).
    function startSync() {
        if (syncPhase === "running" || syncPhase === "done")
            return
        syncAttempts = 0
        syncChunkTarget = 0
        syncToppedUp = false
        syncPhase = "running"
        syncError = ""
        callRetry(M.WALLET_MODULE, "get_current_block_height", [], function (r) {
            if (r.error || !(r.value > 0)) {
                flow.syncPhase = "error"
                flow.syncError = "Cannot discover the chain head (get_current_block_height "
                    + "returned " + (r.error ? "an error" : r.value) + ") — is the sequencer reachable?"
                return
            }
            flow.syncTarget = r.value
            callRetry(M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
                var last = (!r2.error && r2.value !== undefined) ? r2.value : 0
                flow.syncStart = last
                flow.lastSynced = last
                if (last >= flow.syncTarget) {
                    flow.syncPhase = "done"
                    return
                }
                flow.syncChunkStep()
            })
        })
    }

    // Deliberately diverges from WalletView.runSyncAttempt: the wallet module
    // serves NO reads while a sync call is in flight (concurrent
    // get_last_synced_block starves; clients disconnecting mid-call can even
    // crash the module host), so sync runs as strictly serial chunks and
    // each chunk completion is the progress tick.
    function syncChunkStep() {
        syncAttempts += 1
        if (syncAttempts > 200) {
            flow.syncPhase = "error"
            flow.syncError = "Sync did not complete (attempt budget exhausted, synced "
                + flow.lastSynced + " / " + flow.syncTarget + "). Transactions from an "
                + "unsynced wallet are accepted but never apply — retry before claiming "
                + "or registering."
            return
        }
        flow.syncChunkTarget = Math.min(lastSynced + syncChunk, syncTarget)
        flow.syncProbeDeadline = Date.now() + syncProbePatienceMs
        M.call(bridge, M.WALLET_MODULE, "sync_to_block", [flow.syncChunkTarget], function (r) {
            // The reply is advisory — see the syncProbeMs comment. Success and
            // bridge_failure alike fall through to the probe loop.
            flow.probeChunk()
        }, 0)
    }

    function probeChunk() {
        M.call(bridge, M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
            var last = (!r2.error && r2.value !== undefined) ? r2.value : -1
            if (last > flow.lastSynced) {
                flow.lastSynced = last
                flow.syncProbeDeadline = Date.now() + flow.syncProbePatienceMs
            }
            if (last >= flow.syncChunkTarget) {
                if (last >= flow.syncTarget)
                    flow.syncTopUp()
                else
                    flow.syncChunkStep()
            } else if (Date.now() < flow.syncProbeDeadline) {
                // Still inside the patience window: the chunk is (probably)
                // grinding server-side. Re-probe after a pause — each probe
                // already self-paces by its own bridge timeout when queued.
                syncProbeTimer.restart()
            } else {
                flow.syncPhase = "error"
                flow.syncError = "Sync did not complete (no progress for "
                    + Math.round(flow.syncProbePatienceMs / 1000) + "s, last status "
                    + (r2.error ? r2.error.kind : last) + ", synced " + last + " / "
                    + flow.syncTarget + "). Transactions from an unsynced wallet are "
                    + "accepted but never apply — retry before claiming or registering."
            }
        })
    }

    // The head can advance while a long sync runs; one top-up pass re-syncs
    // the difference. One pass suffices — register tolerates being a few
    // blocks behind the live head.
    function syncTopUp() {
        if (syncToppedUp) {
            syncPhase = "done"
            return
        }
        syncToppedUp = true
        M.call(bridge, M.WALLET_MODULE, "get_current_block_height", [], function (r) {
            if (!r.error && r.value > flow.syncTarget) {
                flow.syncTarget = r.value
                flow.syncChunkStep()
            } else {
                flow.syncPhase = "done"
            }
        })
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
            // A manual unlock already happened, possibly with a password
            // create_new consumed — never clobber it.
            autoUnlockPhase = "done"
            return
        }
        autoUnlockPhase = "running"
        autoUnlockKind = ""
        callRetry(M.RLN_MODULE, "unlock_keystore_auto", [], function (r) {
            // The reply carries the secret ONLY on source "created" (wire
            // 0.7 change) — a resume needs no passphrase, wallet open is
            // passwordless.
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

    // ---- Phase D: faucet claim ---------------------------------------------
    // mirrors WalletView.startClaim — keep in sync. Always claims into a
    // FRESH holding: no wire method lists holdings, so a relaunch mid-claim
    // orphans the previous claim's tokens.
    function startFunding() {
        if (fundPhase === "running" || fundPhase === "done")
            return
        var cfg = M.registryConfigHex(registryId)
        if (cfg === "") {
            fundPhase = "error"
            fundError = "Registry id is not logos:<ref>:<64-hex> — cannot derive the config account."
            return
        }
        fundPhase = "running"
        fundError = ""
        holdingHex = ""
        claimPolls = 0
        callRetry(M.LEZ_RLN_MODULE, "get_registry_bounds", [cfg], function (r) {
            if (r.error || r.price_per_unit === undefined) {
                flow.fundPhase = "error"
                flow.fundError = r.error ? M.errorText(r.error)
                                         : "get_registry_bounds returned no price_per_unit"
                return
            }
            flow.pricePerUnit = String(r.price_per_unit)
            flow.claimAmount = M.suggestedClaimAmount(flow.rateLimit, flow.pricePerUnit)
            if (!(flow.claimAmount > 0)) {
                // A non-numeric price would make a 0-token claim that is
                // accepted and silently never funds — surface it instead.
                flow.fundPhase = "error"
                flow.fundError = "Couldn't determine the registration price (got \""
                    + flow.pricePerUnit + "\")."
                return
            }
            flow.deriveHolding(cfg, 0)
        })
    }

    // A failed registration may have consumed the holding, so a revisit can
    // explicitly claim again.
    function restartFunding() {
        if (fundPhase === "running")
            return
        fundPhase = "idle"
        startFunding()
    }

    // mirrors WalletView.deriveHolding — keep in sync. The shared seed wallet
    // replays the same account sequence deterministically, so derive until
    // get_token_balance reports exists:false.
    function deriveHolding(cfg, tries) {
        if (tries >= 15) {
            fundPhase = "error"
            fundError = "No unused holding account after 15 derivations."
            return
        }
        callRetry(M.WALLET_MODULE, "create_account_public", [], function (r) {
            if (r.error || r.value === undefined) {
                flow.fundPhase = "error"
                flow.fundError = "create_account_public failed"
                    + (r.error ? ": " + M.errorText(r.error) : "")
                return
            }
            var acc = String(r.value)
            callRetry(M.LEZ_RLN_MODULE, "get_token_balance", [acc], function (rb) {
                if (rb.error) { flow.fundPhase = "error"; flow.fundError = M.errorText(rb.error); return }
                if (rb.exists === false) {
                    flow.holdingHex = acc
                    flow.submitClaim(cfg, acc)
                } else {
                    flow.deriveHolding(cfg, tries + 1)
                }
            })
        })
    }

    // mirrors WalletView.submitClaim — keep in sync
    function submitClaim(cfg, acc) {
        M.call(bridge, M.LEZ_RLN_MODULE, "claim_tokens", [cfg, acc, claimAmount], function (r) {
            if (r.error) { flow.fundPhase = "error"; flow.fundError = M.errorText(r.error); return }
            flow.claimPolls = 0
            claimTimer.start()
        })
    }

    // mirrors WalletView.pollClaim — keep in sync. An over-faucet claim is
    // accepted and silently never funds — hence the hard claimPollBudget x
    // claimPollMs timeout (180s in production).
    function pollClaim() {
        claimPolls += 1
        M.call(bridge, M.LEZ_RLN_MODULE, "get_token_balance", [holdingHex], function (r) {
            if (!r.error) {
                var bal = parseInt(r.balance !== undefined ? r.balance : "0", 10)
                if (r.exists === true && bal >= flow.claimAmount) {
                    claimTimer.stop()
                    flow.fundPhase = "done"
                    return
                }
            }
            if (flow.claimPolls >= flow.claimPollBudget) {
                claimTimer.stop()
                flow.fundPhase = "error"
                flow.fundError = "Claim submitted but never funded within 180s — the faucet may "
                    + "be exhausted or the wallet unsynced (transactions from an unsynced "
                    + "wallet are silently dropped)."
            }
        })
    }

    // ---- Phase E: registration ----------------------------------------------
    // mirrors RegisterView.doRegister — keep in sync. register() generates
    // the identity credential in-module.
    function startRegistration() {
        if (regPhase === "running" || regPhase === "done")
            return
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        flow.submitRegistration()
    }

    function retryRegistration() {
        if (regPhase === "running")
            return
        regPhase = "idle"
        startRegistration()
    }

    function submitRegistration() {
        // Wallet path only — the gifter path submits via registerDelegated().
        var options = JSON.stringify({ funding_holding_account_id: holdingHex })
        callRetry(M.RLN_MODULE, "register",
               [registryId, M.DEFAULT_RLN_ID, rateLimit, options], function (r) {
            if (r.error) { flow.regPhase = "error"; flow.regError = M.errorText(r.error); return }
            flow.commitment = (r.credential && r.credential.identity_commitment) || ""
            flow.regState = r.state || "pending"
            flow.rateLimitMismatch = r.rate_limit_mismatch === true
            regTimer.start()
        })
    }

    // mirrors RegisterView.pollState — keep in sync. The module bounds the
    // pending window at 300s, so this poll always terminates. A TRANSIENT
    // error is tolerated by continuing — the next tick re-reads; only a
    // non-transient error stops and fails.
    function pollRegistration() {
        M.call(bridge, M.RLN_MODULE, "get_membership_state",
               [registryId, M.DEFAULT_RLN_ID], function (r) {
            if (r.error) {
                if (M.isTransientError(r.error.kind))
                    return
                regTimer.stop()
                flow.regPhase = "error"
                flow.regError = M.errorText(r.error)
                return
            }
            flow.regState = r.state || "unknown"
            if (flow.regState === "pending")
                return
            regTimer.stop()
            if (flow.regState === "active" || flow.regState === "grace_period") {
                flow.regPhase = "done"
            } else if (flow.regState === "failed") {
                flow.fetchFailureReason()
            } else {
                flow.regPhase = "error"
                flow.regError = "Registration settled in state \"" + flow.regState + "\"."
            }
            // The gifter path settles with the registration itself.
            if (flow.registrationMode === "gifter" && flow.gifterPhase === "running") {
                flow.gifterStage = ""
                if (flow.regPhase === "done")
                    flow.gifterPhase = "done"
                else
                    flow.gifterPhase = "error"
            }
        })
    }

    // The merged-state view carries no reason; the memberships row does.
    function fetchFailureReason() {
        callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            var reason = ""
            if (!r.error) {
                var rows = r.memberships || []
                for (var i = 0; i < rows.length; i++) {
                    var full = rows[i].credential ? rows[i].credential.identity_commitment : ""
                    if (full === flow.commitment && rows[i].failed_reason) {
                        reason = String(rows[i].failed_reason)
                        break
                    }
                }
            }
            flow.regPhase = "error"
            flow.regError = "Registration FAILED" + (reason !== "" ? ": " + reason : "")
                + " — Try again re-registers with a fresh identity; if funds ran short, "
                + "get more tokens first."
        })
    }

    // ---- Gifter path ---------------------------------------------------------
    // Bring up the transport, gate on card presence, then hand the whole
    // delegated flow to the membership module with one register() call; the
    // Phase E poll tail drives regPhase to completion.
    function startGifter() {
        if (gifterPhase === "running" || gifterPhase === "done")
            return
        // Keycard grants are clamped server-side to RATE_LIMIT_MIN; asking
        // for anything else makes the reply warn spuriously about the
        // granted rate differing from the requested one.
        rateLimit = M.RATE_LIMIT_MIN
        gifterPhase = "running"
        gifterError = ""
        gifterStage = "wallet"
        ensureGifterWallet(function (wErr) {
        if (wErr) { flow.failGifter(wErr); return }
        flow.gifterStage = "node"
        flow.ensureLibp2pNode(function (nodeErr) {
            if (nodeErr) { flow.failGifter(nodeErr); return }
            flow.gifterStage = "capture"
            flow.cardWaitPolls = 0
            flow.pollCardThenRegister()
        })
        })
    }

    // Open a wallet for the client's on-chain reads only — no sync, no
    // faucet. get_membership and the idempotent register need it or they hit
    // "Null wallet handle".
    function ensureGifterWallet(cb) {
        if (gifterWalletReady) { cb(""); return }
        flow.callRetry(M.RLN_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: M.TESTNET_SEQUENCER_ADDR })], function (r) {
            if (r.error) { cb("Couldn't set up the wallet: " + M.errorText(r.error)); return }
            var configPath = String(r.config_path || "")
            var storagePath = String(r.storage_path || "")
            if (r.storage_exists === true) {
                flow.callRetry(M.WALLET_MODULE, "open",
                       [configPath, storagePath, M.statsPathFor(storagePath)], function (ro) {
                    // A non-zero open on an already-open daemon wallet is fine for
                    // reads; proceed either way.
                    flow.gifterWalletReady = true
                    cb("")
                })
            } else {
                M.call(bridge, M.WALLET_MODULE, "create_new",
                       [configPath, storagePath, M.statsPathFor(storagePath), flow.password], function (rc) {
                    if (rc.error && rc.error.kind !== "empty_reply") {
                        cb("Couldn't create the wallet: " + M.errorText(rc.error)); return
                    }
                    M.call(bridge, M.WALLET_MODULE, "save", [], function () {
                        flow.gifterWalletReady = true
                        cb("")
                    })
                })
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
    // to dial the gifter. The FIRST libp2p_call can race libp2p_module's
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

    // The one delegated call: register() generates the identity in-module and
    // returns the pending membership immediately; the module then captures,
    // dials, and registers in the background. Confirmation comes through the
    // shared Phase E poll.
    function registerDelegated() {
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        var options = JSON.stringify({
            delegated: "true",
            gifter_peer_id: gifterPeerId.trim(),
            gifter_multiaddr: gifterMultiaddr.trim(),
            // The capture module (an rln_auth_vector producer) supplies the
            // attestation bound to the module-generated commitment.
            auth_type: "keycard-attestation",
            auth_provider: M.CAPTURE_MODULE
        })
        callRetry(M.RLN_MODULE, "register",
               [registryId, M.DEFAULT_RLN_ID, rateLimit, options], function (r) {
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
        id: syncProbeTimer
        interval: flow.syncProbeMs
        repeat: false
        onTriggered: flow.probeChunk()
    }

    Timer {
        id: claimTimer
        interval: flow.claimPollMs
        repeat: true
        onTriggered: flow.pollClaim()
    }

    Timer {
        id: regTimer
        // Events only tighten latency, never replace the poll: armed widens
        // the interval to a 60s slow-poll safety net; unarmed keeps the
        // statePollMs cadence (and its test-tunability).
        interval: flow.eventsArmed ? 60000 : flow.statePollMs
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
