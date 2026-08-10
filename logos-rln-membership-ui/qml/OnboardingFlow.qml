// Non-visual onboarding controller: wallet -> sync -> keystore password ->
// faucet claim -> registration, as sequential idempotent phases with
// observable progress, no widget references. The flow logic deliberately
// DUPLICATES the live-proven Advanced views (they stay byte-identical —
// their logic is entangled with their widgets); every phase carries a
// "mirrors <view>.<fn> — keep in sync" cross-reference. An Item (not
// QtObject) so it can own the poll Timers; visible:false, zero footprint.
import QtQuick
import "membership.js" as M

Item {
    id: flow
    visible: false

    required property var bridge
    required property string registryId

    // Single password for both stores (wallet storage + keystore). Frozen by
    // the password step once walletCreated — create_new consumed it.
    property string password: ""
    property int rateLimit: M.RATE_LIMIT_DEFAULT
    property string priorNotice: ""

    // Set by Main from the startup probe (any local membership records ->
    // true) so the password step can frame itself as creation vs entry.
    // Imperfect by design: a keystore can exist with zero membership records
    // (unlocked once, never registered) — in that rare case the "new
    // account" framing shows, and a wrong password still surfaces through
    // the bad_password error line, which is acceptable.
    property bool hasExistingAccount: false

    // Phase A — wallet (provision + open/create).
    property string walletPhase: "idle"
    property string walletError: ""
    // Captured from create_new but not displayed; kept for a future
    // recovery/export surface without a wire change.
    property string mnemonic: ""
    property bool walletCreated: false

    // Phase B — sync (auto-chained after A).
    property string syncPhase: "idle"
    property string syncError: ""
    property int syncTarget: 0
    // The wallet's block when this sync began — the progress bar's origin,
    // so a resumed wallet still shows visible movement instead of opening
    // at 90%.
    property int syncStart: 0
    property int lastSynced: -1
    // Total sync_to_block calls this run (hard global bound) and consecutive
    // no-progress failures on the current chunk (small bounded retries).
    property int syncAttempts: 0
    property int syncChunkRetries: 0
    property bool syncToppedUp: false
    // Chunk size measured live 2026-07-16 against the testnet (fresh scratch
    // wallet, temp daemon, serial CLI calls): 500 blocks ≈ 2.7–4.5s,
    // 1000 ≈ 7–11s, 2000 ≈ 13–17s (~110–180 blocks/s). 500 gives a visible
    // bar step every few seconds; a fresh ~23k-block sync is ~47 chunks,
    // well inside the 200-call budget.
    readonly property int syncChunk: 500

    // Phase C — keystore password check (fired by the password step's Next).
    property string unlockPhase: "idle"
    property string unlockError: ""

    // Phase C′ — OS-keychain auto-unlock, fired by Main when routing into
    // onboarding. "done" implies unlockPhase is done and flow.password
    // carries the keychain secret (it feeds the wallet's create_new too);
    // "fallback" means the password screen runs manually — autoUnlockKind
    // keeps the error kind so the step can explain a stale saved sign-in.
    property string autoUnlockPhase: "idle"
    property string autoUnlockKind: ""
    // Set true by OnboardingView once the flow leaves Welcome; fences a late
    // startAutoUnlock from re-deciding the password path mid-flow. Reset to
    // false by restart() (which returns to Welcome).
    property bool started: false

    // Test-tunable poll cadence (production defaults preserved). A
    // deterministic mock-bridge test shrinks these so the flow runs in
    // seconds and the claim timeout is reachable. NOTE: sync is chunk-
    // callback-chained (no interval), so it has no tunable — it already runs
    // as fast as replies arrive. claimPollBudget bounds the claim timeout
    // (36 x claimPollMs = 180s in production).
    property int claimPollMs: 5000
    property int claimPollBudget: 36
    property int statePollMs: 10000

    // Bounded auto-retry for TRANSIENT transport failures on critical wire
    // calls (see callRetry). Same test-tunable pattern: a test sets
    // transientRetryMs tiny so retries run in ms. Max 4: the flaky transport
    // occasionally exhausts 3 retries on idempotent reads; the extra attempt is
    // cheap; claim/create_new are never auto-retried.
    property int transientRetryMs: 1500
    property int transientRetryMax: 4

    // True once the module's push channel is armed on this bridge (see
    // M.armModuleEvent) — set once at startup below. false on a host
    // predating onModuleEvent; regTimer then just keeps its normal cadence,
    // polling being the one channel. MembershipCard reads this flag too
    // (via its `flow` reference) rather than arming a second subscription
    // for the same (module, event) pair.
    property bool eventsArmed: false

    // Phase D — faucet claim into a fresh holding.
    property string fundPhase: "idle"
    property string fundError: ""
    property string pricePerUnit: ""
    property int claimAmount: 0
    property string holdingHex: ""
    property int claimPolls: 0

    // Phase E — registration + confirmation poll. The identity credential is
    // generated INSIDE the membership module by register(); this flow only ever
    // sees the public commitment from its reply.
    property string regPhase: "idle"
    property string regError: ""
    property string regState: ""
    property string commitment: ""
    property bool rateLimitMismatch: false

    // ---- Gifter path (alternative to Phases A/B/D) -------------------------
    // "gifter" replaces wallet-provision + sync + faucet with ONE delegated
    // register() call: the membership module generates the identity, drives
    // rln_gifter_module.request with its commitment, and the gifter client
    // has the keycard capture module produce the attestation (bound to that
    // commitment) before dialing the gifter node that pays for the
    // registration. The Phase E poll tail is REUSED for confirmation. Set on
    // Welcome; reset to "wallet" by resetForNewRegistration.
    property string registrationMode: "wallet"
    // idle | running | done | error. gifterStage is the running sub-step, for
    // the progress caption: wallet -> node -> capture (which the caption keeps
    // showing while the module's background chain captures, dials, and
    // registers).
    property string gifterPhase: "idle"
    property string gifterStage: ""
    property string gifterError: ""
    // Gifter node coordinates (StepGifter inputs); both prefilled to the local
    // dev gifter's stable peerId + address, freely editable.
    property string gifterPeerId: M.GIFTER_PEER_ID_DEFAULT
    property string gifterMultiaddr: M.GIFTER_MULTIADDR_DEFAULT
    // createNode + start are one-time per session; once a node answers peerInfo
    // we skip re-creating it on a retry or a second gifted membership.
    property bool libp2pNodeReady: false
    // The gifter pays for registration, but the CLIENT still needs an OPEN wallet
    // for on-chain READS: the membership module's confirmation poller fetches
    // accounts through the wallet's sequencer connection ("Null wallet handle"
    // otherwise). Provisioned + opened once, unfunded, unsynced.
    property bool gifterWalletReady: false
    // Card-presence gate before the delegated register: the in-module capture
    // starts right after register() is called, and gating keeps the whole
    // background chain (capture + dial + on-chain register) inside the module's
    // 300s pending confirmation window.
    property int cardWaitPolls: 0
    property int cardWaitBudget: 40

    // Arm the push channel as soon as the flow exists — bridge is a
    // required property, already resolved (possibly to null under a bare
    // preview) by the time Component.onCompleted runs.
    Component.onCompleted: {
        flow.eventsArmed = M.armModuleEvent(flow.bridge, M.RLN_MODULE, M.MEMBERSHIP_STATE_CHANGED)
    }

    // Fired by finish() when the user leaves the completed wizard.
    signal completed(string commitment)

    function finish() {
        completed(commitment)
    }

    // Bounded auto-retry wrapper around M.call for the flow's critical wire
    // calls. On a TRANSIENT error (transport/host/sequencer flakiness — see
    // M.isTransientError) it waits transientRetryMs and retries, up to
    // transientRetryMax times, before delivering the error; a NON-transient
    // error (bad_password, invalid_argument, …) is delivered immediately
    // (retrying won't help). The one-shot backoff Timer is created per retry
    // from retryTimerComponent and self-destroys, so concurrent retries never
    // collide. Read-ish and idempotent calls use this; the manual Retry
    // button remains the backstop once auto-retry is exhausted.
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

    // A NEW registration after a completed run: funding and registration
    // must run fresh (their "done" would otherwise no-op the restarts and
    // the progress screen would open pre-completed). Sync also resets to
    // idle so the re-run re-syncs the delta since last time (the wallet is
    // already open → a cheap catch-up); leaving it "done" would register
    // against a stale head and drop the claim into the 180s timeout. The
    // wallet phase stays done — the wallet itself is unchanged.
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
        // A re-run re-offers the Welcome choice, so default back to the wallet
        // path and clear the last gift attempt. The libp2p node, if up, stays up.
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

    // mirrors WalletView.doOpen — keep in sync (plus the already-open probe:
    // a daemon-lifetime wallet from a previous wizard run reports open!=0,
    // but a working chain-head read proves it is usable).
    function openWallet(configPath, storagePath) {
        callRetry(M.WALLET_MODULE, "open", [configPath, storagePath], function (r) {
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

    // mirrors WalletView.doCreateFresh — keep in sync (no clobber guard
    // needed here: provision_wallet_home just reported storage_exists:false
    // for this exact path).
    function createWallet(configPath, storagePath) {
        M.call(bridge, M.WALLET_MODULE, "create_new",
               [configPath, storagePath, password], function (r) {
            if (r.error) {
                // create_new returns "" (the wallet module's ""-on-error
                // convention -> empty_reply) when a DIFFERENT wallet is
                // already open in the daemon (e.g. opened from the Advanced
                // Wallet tab). That wallet is usable, so recover by opening
                // it — mirrors startWallet's non-zero-open -> chain-head
                // probe. A genuine error still fails the phase.
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
    // mirrors WalletView.startSync — keep in sync (plus an already-synced
    // fast-path so "New membership" reruns skip the wait, and the chunked
    // execution divergence documented at syncChunkStep).
    function startSync() {
        if (syncPhase === "running" || syncPhase === "done")
            return
        syncAttempts = 0
        syncChunkRetries = 0
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

    // DELIBERATE divergence from WalletView.runSyncAttempt (which issues ONE
    // sync_to_block(head) and polls a 4s progress timer): measured live
    // 2026-07-16, the wallet module serves NO reads while a sync call is in
    // flight — concurrent get_last_synced_block starves until the sync
    // finishes (and impatient clients disconnecting mid-call can even crash
    // the module host), so the poll never moved and the bar sat gray. Here
    // sync runs in strictly SERIAL chunks — sync_to_block(min(last + chunk,
    // target)), then read the wallet's own last-synced block — so each chunk
    // completion IS the progress tick and no calls ever overlap. Success per
    // chunk is status 0 AND the read reaching the chunk target; a failed or
    // stalled chunk retries ITSELF a few times before the phase fails with
    // the unsynced-wallet diagnostic.
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
        var chunkTarget = Math.min(lastSynced + syncChunk, syncTarget)
        M.call(bridge, M.WALLET_MODULE, "sync_to_block", [chunkTarget], function (r) {
            M.call(bridge, M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
                var last = (!r2.error && r2.value !== undefined) ? r2.value : -1
                var progressed = last > flow.lastSynced
                if (last >= 0)
                    flow.lastSynced = last
                if (!r.error && r.value === 0 && last >= chunkTarget) {
                    flow.syncChunkRetries = 0
                    if (last >= flow.syncTarget)
                        flow.syncTopUp()
                    else
                        flow.syncChunkStep()
                } else if (progressed || flow.syncChunkRetries < 3) {
                    flow.syncChunkRetries = progressed ? 0 : flow.syncChunkRetries + 1
                    flow.syncChunkStep()
                } else {
                    flow.syncPhase = "error"
                    flow.syncError = "Sync did not complete (last status "
                        + (r.error ? r.error.kind : r.value) + ", synced " + last + " / "
                        + flow.syncTarget + "). Transactions from an unsynced wallet are "
                        + "accepted but never apply — retry before claiming or registering."
                }
            })
        }, 0)
    }

    // The head can advance while a long sync runs: one top-up pass re-reads
    // it and syncs the difference. One pass is enough — the register path
    // tolerates being a few blocks behind the live head.
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
    // mirrors RegisterView.doUnlock — keep in sync. Front-loads bad_password
    // BEFORE the minutes-long sync/claim steps; with an empty keystore any
    // password unlocks and becomes the encryption password at first write.
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
                // Migration hook: a manual unlock after a keychain miss
                // persists the password module-side (the plaintext never
                // re-crosses the wire) so the next launch is silent.
                // Fire-and-forget — a failure only means the password
                // screen returns next time.
                M.call(bridge, M.RLN_MODULE, "remember_keystore_password", [], function (r2) {
                    if (r2.error)
                        console.warn("remember_keystore_password:", r2.error.kind, r2.error.message)
                })
            }
        })
    }

    // ---- Phase C′: OS-keychain auto-unlock ----------------------------------
    // The module fetches (or generates + persists FIRST) the keystore secret
    // from the macOS Keychain and unlocks through its normal verification
    // seam; the reply's secret becomes flow.password so the wallet's
    // create_new sees the same passphrase a manual entry would have. Any
    // failure (non-macOS, denied keychain, manual-era keystore without an
    // item, stale item -> bad_password) routes to "fallback": the password
    // screen, whose successful unlock then remembers itself (above).
    function startAutoUnlock() {
        if (autoUnlockPhase === "running" || autoUnlockPhase === "done")
            return
        // Fence: once the flow has moved past Welcome, the password decision
        // is already made (manual entry or an earlier auto-unlock) — never
        // let a late startAutoUnlock flip autoUnlockPhase and re-skip the
        // screen out from under an in-progress flow.
        if (started)
            return
        if (unlockPhase === "done") {
            // A manual unlock already happened — possibly with a password
            // that create_new consumed and froze. Never clobber it.
            autoUnlockPhase = "done"
            return
        }
        autoUnlockPhase = "running"
        autoUnlockKind = ""
        callRetry(M.RLN_MODULE, "unlock_keystore_auto", [], function (r) {
            if (r.error || r.unlocked !== true || !r.secret) {
                flow.autoUnlockKind = r.error ? String(r.error.kind) : "bad_reply"
                flow.autoUnlockPhase = "fallback"
                return
            }
            flow.password = String(r.secret)
            flow.unlockPhase = "done"
            flow.autoUnlockPhase = "done"
        })
    }

    // ---- Phase D: faucet claim ---------------------------------------------
    // mirrors WalletView.startClaim — keep in sync (amount comes from
    // M.suggestedClaimAmount instead of an editable field; editing lives in
    // Advanced). Always claims into a FRESH holding: no wire method lists
    // holdings, so a relaunch mid-claim orphans the previous claim's tokens.
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
                // Non-numeric price would make a 0-token claim that is
                // accepted and silently dropped — surface it instead.
                flow.fundPhase = "error"
                flow.fundError = "Couldn't determine the registration price (got \""
                    + flow.pricePerUnit + "\")."
                return
            }
            flow.deriveHolding(cfg, 0)
        })
    }

    // Back-to-Tokens path: a failed registration may have consumed the
    // holding, so a revisit can explicitly claim again.
    function restartFunding() {
        if (fundPhase === "running")
            return
        fundPhase = "idle"
        startFunding()
    }

    // mirrors WalletView.deriveHolding — keep in sync (the shared seed
    // wallet replays the same account sequence deterministically, so keep
    // deriving until get_token_balance says exists:false).
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
    // claimPollMs timeout (180s in production) naming BOTH causes.
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
    // mirrors RegisterView.doRegister — keep in sync. The membership module
    // generates the identity credential inside register().
    function startRegistration() {
        if (regPhase === "running" || regPhase === "done")
            return
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        // The credential is generated inside the module by register — there is
        // no client-side generate_identity step; the secret never leaves it.
        flow.submitRegistration()
    }

    function retryRegistration() {
        if (regPhase === "running")
            return
        regPhase = "idle"
        startRegistration()
    }

    function submitRegistration() {
        // Wallet path: register generates the credential in-module (the caller
        // supplies no credential) and the faucet holding pays. The gifter path
        // never comes through here — it submits via registerDelegated().
        var options = JSON.stringify({ funding_holding_account_id: holdingHex })
        callRetry(M.RLN_MODULE, "register",
               [registryId, M.DEFAULT_RLN_ID, rateLimit, options], function (r) {
            if (r.error) { flow.regPhase = "error"; flow.regError = M.errorText(r.error); return }
            // register returns the public Membership view; the commitment is the
            // only credential-derived value it exposes.
            flow.commitment = (r.credential && r.credential.identity_commitment) || ""
            flow.regState = r.state || "pending"
            flow.rateLimitMismatch = r.rate_limit_mismatch === true
            regTimer.start()
        })
    }

    // mirrors RegisterView.pollState — keep in sync. The module bounds the
    // pending window at 300s, so this poll always terminates. Note: this is
    // itself a retry loop (the regTimer re-polls), so a TRANSIENT error is
    // tolerated by simply continuing — the next tick re-reads the state (the
    // poller tolerates the same "empty reply" the same way). Only a
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
            // The gifter path runs its whole chain (capture -> dial -> on-chain
            // register) behind the one delegated register(); its phase settles
            // with the registration itself.
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
    // Bring up the transport, gate on a Keycard being on the reader, then hand
    // the WHOLE delegated flow to the membership module: one register() call
    // generates the identity in-module, drives rln_gifter_module.request with
    // its commitment, the auth_provider (the capture module) produces the
    // attestation bound to exactly that commitment — the ordering constraint
    // is internal to the module — and the
    // gifter node pays for the on-chain registration. The Phase E poll tail
    // drives regPhase, so OnboardingView completes the wizard exactly as the
    // wallet path does.
    function startGifter() {
        if (gifterPhase === "running" || gifterPhase === "done")
            return
        // Keycard grants are clamped server-side to RATE_LIMIT_MIN regardless of
        // the request, so ask for exactly that — otherwise the reply reports the
        // granted rate differing from the requested one and warns spuriously.
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

    // Open a wallet for the CLIENT's on-chain reads (the gifter still pays for the
    // registration). provision_wallet_home creates the config/home; then open an
    // existing store or create a fresh one — NO sync, NO faucet. get_membership +
    // the idempotent register need this or they hit "Null wallet handle".
    function ensureGifterWallet(cb) {
        if (gifterWalletReady) { cb(""); return }
        flow.callRetry(M.RLN_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: M.TESTNET_SEQUENCER_ADDR })], function (r) {
            if (r.error) { cb("Couldn't set up the wallet: " + M.errorText(r.error)); return }
            var configPath = String(r.config_path || "")
            var storagePath = String(r.storage_path || "")
            if (r.storage_exists === true) {
                flow.callRetry(M.WALLET_MODULE, "open", [configPath, storagePath], function (ro) {
                    // A non-zero open on an already-open daemon wallet is fine for
                    // reads; proceed either way.
                    flow.gifterWalletReady = true
                    cb("")
                })
            } else {
                M.call(bridge, M.WALLET_MODULE, "create_new", [configPath, storagePath, flow.password], function (rc) {
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

    // Every libp2p_module call is RELAYED through rln_gifter_module.libp2p_call
    // — direct libp2p replies marshal to null over the QML bridge. argObj is the
    // libp2p method's single object arg (undefined for no-arg methods); cb gets
    // the parsed {success,value,error}.
    function libp2pCall(method, argObj, cb, timeoutMs) {
        if (!bridge) { cb({ error: "no bridge" }); return }
        var args = (argObj === undefined || argObj === null) ? [] : [JSON.stringify(argObj)]
        bridge.callModuleAsync(M.GIFTER_MODULE, "libp2p_call",
            [JSON.stringify({ method: method, args: args })], function (raw) {
                cb(M.parseLibp2pReply(raw))
            }, timeoutMs === undefined ? 30000 : timeoutMs)
    }

    // Bring up a PLAIN libp2p node with createNode + start — the gifter client
    // only needs to dial the gifter and open a stream, so no RLN/mix context is
    // required (works against vanilla upstream libp2p_module). start's success is
    // the gate. The FIRST libp2p_call can race libp2p_module's token registration
    // ("auth token not recognized"/"Invalid response"); retry a few times.
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

    // Wait for a Keycard on the reader before delegating: the in-module capture
    // starts right after register() is dispatched, so gating on presence keeps
    // the background chain (capture + dial + on-chain register) fast and inside
    // the module's pending confirmation window. Bounded, with a clear message.
    function pollCardThenRegister() {
        M.call(bridge, M.CAPTURE_MODULE, "card_status", [], function (r) {
            // A reader/module fault is not "no card yet" — surface the real
            // cause immediately instead of burning the presence budget and
            // reporting a misleading no-card message.
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

    // The ONE delegated call: register() generates the identity in-module and
    // returns the public Pending membership immediately; the module then drives
    // the gifter in the background (capture bound to its commitment -> dial ->
    // the gifter's funded on-chain register). Confirmation comes through the
    // shared Phase E poll; keep the card on the reader until it settles.
    function registerDelegated() {
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        var options = JSON.stringify({
            delegated: "true",
            gifter_peer_id: gifterPeerId.trim(),
            gifter_multiaddr: gifterMultiaddr.trim(),
            // Keycard vector via the generic auth surface: the gifter client
            // asks the capture module (an rln_auth_vector producer) for the
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

    // No sync progress Timer anymore: mid-sync reads starve (and can crash
    // the module host) — chunk completions are the progress ticks.

    Timer {
        id: claimTimer
        interval: flow.claimPollMs
        repeat: true
        onTriggered: flow.pollClaim()
    }

    Timer {
        id: regTimer
        // Events only tighten latency, never replace the poll: when armed
        // the interval widens to 60s (a slow-poll safety net behind the
        // push channel); statePollMs keeps the normal cadence — and its
        // full test-tunability — when this bridge has no event support.
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

    // Wake-up only, never a data source: get_membership_state (via
    // pollRegistration, the same call regTimer already makes every tick)
    // stays the sole authority on state. This flow tracks no
    // membership_hash to narrow the filter further (register()'s reply is
    // never captured), so any state change on OUR registry — even one
    // belonging to a different registrant on this shared-faucet testnet
    // registry — wakes the poll early; that costs one extra idempotent
    // read, never a missed one. Gated on regTimer.running so an event
    // arriving outside an active confirmation wait (before registration
    // starts, or after it already settled) is a no-op.
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
