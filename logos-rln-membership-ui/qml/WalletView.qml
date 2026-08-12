// Wallet & funding flow: open (or create) the execution-zone wallet, sync it
// to the chain head, then claim RLNTOK from the faucet into a freshly
// derived holding account, which auto-fills the Register tab's funding
// field via the funded() signal. Two chain facts shape the flow: an
// unsynced wallet's transactions are accepted (tx hash and all) but
// silently never apply, and a claim exceeding the faucet's remaining
// balance is also silently dropped — so sync completion is verified and
// the claim credit is polled with a hard timeout.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosScrollView {
    id: view

    required property var bridge
    required property string registryId

    // Emitted once a fresh holding is confirmed funded (the credit landed).
    signal funded(string holdingHex)

    // Wallet session (the wallet module holds one open wallet per daemon).
    property bool walletOpen: false
    property string mnemonic: ""

    // Sync progress. `synced` flips only when sync_to_block returns 0 AND
    // get_last_synced_block has reached the head discovered at start.
    property bool syncing: false
    property int syncTarget: 0
    property int lastSynced: -1
    property int syncAttempts: 0
    property bool synced: false

    // Claim flow. claimAmount is frozen at claim start so edits to the field
    // mid-poll cannot move the goalposts of the credit check.
    property bool claiming: false
    property string holdingHex: ""
    property string holdingBalance: ""
    property string pricePerUnit: ""
    property bool amountTouched: false
    property int claimAmount: 0
    property int claimPolls: 0

    property bool busy: false
    property string status: ""
    property bool statusIsError: false

    function report(text, isError) {
        status = text
        statusIsError = isError === true
    }

    // The membership module provisions wallet-home (sandboxed QML cannot
    // create files), then storage_exists decides open vs create. The
    // returned paths land in the advanced fields, so both flows share
    // doOpen/doCreate below.
    function doProvision() {
        busy = true
        M.call(bridge, M.RLN_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: sequencerField.text.trim() })], function (r) {
            if (r.error) { view.busy = false; view.report(M.errorText(r.error), true); return }
            configField.text = String(r.config_path || "")
            storageField.text = String(r.storage_path || "")
            view.busy = false
            if (r.storage_exists === true)
                view.doOpen()
            else
                view.doCreate()
        })
    }

    function doOpen() {
        busy = true
        M.call(bridge, M.WALLET_MODULE, "open",
               [configField.text.trim(), storageField.text.trim()], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            if (r.value === 0) {
                view.walletOpen = true
                view.report("Wallet open — sync it before claiming or registering.", false)
            } else {
                view.report("open returned status " + r.value + " — wrong paths, or a wallet "
                    + "is already open in this daemon (if so, just proceed to Sync).", true)
            }
        })
    }

    // Create must never clobber an existing (possibly funded) storage file.
    // The QML sandbox cannot stat the path and the wallet wire has no exists
    // probe, so the guard is: try open() first — if the storage opens,
    // refuse to create over it and keep the now-open wallet instead.
    function doCreate() {
        busy = true
        M.call(bridge, M.WALLET_MODULE, "open",
               [configField.text.trim(), storageField.text.trim()], function (r) {
            if (!r.error && r.value === 0) {
                view.busy = false
                view.walletOpen = true
                view.report("Refusing to create: that storage file already exists and opened fine "
                    + "— creating would have overwritten it. The existing wallet is now open; "
                    + "proceed to Sync.", true)
                return
            }
            view.doCreateFresh()
        })
    }

    function doCreateFresh() {
        M.call(bridge, M.WALLET_MODULE, "create_new",
               [configField.text.trim(), storageField.text.trim(), createPasswordField.text], function (r) {
            if (r.error) { view.busy = false; view.report(M.errorText(r.error), true); return }
            var words = r.value !== undefined ? String(r.value) : ""
            if (words === "") {
                view.busy = false
                view.report("create_new failed — the config file must exist, the storage path "
                    + "must be writable, and no wallet may already be open in this daemon.", true)
                return
            }
            view.mnemonic = words
            view.walletOpen = true
            M.call(bridge, M.WALLET_MODULE, "save", [], function (r2) {
                view.busy = false
                if (r2.error || r2.value !== 0)
                    view.report("Wallet created but save() failed — storage.json may not be on disk yet.", true)
                else
                    view.report("Wallet created and saved. WRITE DOWN the recovery mnemonic above — "
                        + "it is shown only once. Then sync.", false)
            })
        })
    }

    function startSync() {
        syncAttempts = 0
        synced = false
        syncing = true
        report("Discovering the chain head…", false)
        M.call(bridge, M.WALLET_MODULE, "get_current_block_height", [], function (r) {
            if (r.error || !(r.value > 0)) {
                view.syncing = false
                view.report("Cannot discover the chain head (get_current_block_height returned "
                    + (r.error ? "an error" : r.value) + ") — is the wallet open and the sequencer reachable?", true)
                return
            }
            view.syncTarget = r.value
            view.runSyncAttempt()
        })
    }

    // Unsynced wallets silently drop transactions, so keep re-issuing
    // sync_to_block until it reports SUCCESS (0) and the wallet's own last
    // synced block reaches the target. No client timeout: a fresh wallet
    // takes minutes; progressTimer surfaces movement meanwhile.
    function runSyncAttempt() {
        syncAttempts += 1
        report("Syncing to block " + syncTarget + " (attempt " + syncAttempts
            + ") — a fresh wallet can take several minutes…", false)
        progressTimer.start()
        M.call(bridge, M.WALLET_MODULE, "sync_to_block", [syncTarget], function (r) {
            M.call(bridge, M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
                var last = (!r2.error && r2.value !== undefined) ? r2.value : -1
                view.lastSynced = last
                if (!r.error && r.value === 0 && last >= view.syncTarget) {
                    progressTimer.stop()
                    view.syncing = false
                    view.synced = true
                    view.report("Synced to block " + last + ".", false)
                    view.fetchSuggestedAmount()
                } else if (view.syncAttempts < 10) {
                    view.runSyncAttempt()
                } else {
                    progressTimer.stop()
                    view.syncing = false
                    view.report("Sync did not complete (last status "
                        + (r.error ? r.error.kind : r.value) + ", synced " + last + " / " + view.syncTarget
                        + "). Transactions from an unsynced wallet are accepted but never apply — "
                        + "retry Sync before claiming or registering.", true)
                }
            })
        }, 0)
    }

    function pollSyncProgress() {
        M.call(bridge, M.WALLET_MODULE, "get_last_synced_block", [], function (r) {
            if (!r.error && r.value !== undefined)
                view.lastSynced = r.value
        })
    }

    // Suggested claim: rate × live price_per_unit × 1.2 slack. Only fills the
    // field while the user hasn't edited it.
    function fetchSuggestedAmount() {
        var cfg = M.registryConfigHex(registryId)
        if (cfg === "")
            return
        M.call(bridge, M.LEZ_RLN_MODULE, "get_registry_bounds", [cfg], function (r) {
            if (r.error || r.price_per_unit === undefined)
                return
            view.pricePerUnit = String(r.price_per_unit)
            if (!view.amountTouched)
                amountField.text = String(Math.ceil(
                    M.RATE_LIMIT_DEFAULT * parseInt(view.pricePerUnit, 10) * 1.2))
        })
    }

    function startClaim() {
        var cfg = M.registryConfigHex(registryId)
        if (cfg === "") {
            report("Registry id is not logos:<ref>:<64-hex> — cannot derive the config account.", true)
            return
        }
        var amount = parseInt(amountField.text, 10)
        if (!(amount > 0)) {
            report("Claim amount must be a positive integer (RLNTOK).", true)
            return
        }
        claimAmount = amount
        claiming = true
        holdingHex = ""
        holdingBalance = ""
        report("Deriving a fresh holding account…", false)
        deriveHolding(cfg, amount, 0)
    }

    // The shared seed wallet derives the SAME account sequence
    // deterministically, so earlier-derived accounts may already exist
    // on-chain — keep deriving until get_token_balance says exists:false.
    function deriveHolding(cfg, amount, tries) {
        if (tries >= 15) {
            claiming = false
            report("No unused holding account after 15 derivations.", true)
            return
        }
        M.call(bridge, M.WALLET_MODULE, "create_account_public", [], function (r) {
            if (r.error || r.value === undefined) {
                view.claiming = false
                view.report("create_account_public failed"
                    + (r.error ? ": " + M.errorText(r.error) : ""), true)
                return
            }
            var acc = String(r.value)
            M.call(bridge, M.LEZ_RLN_MODULE, "get_token_balance", [acc], function (rb) {
                if (rb.error) { view.claiming = false; view.report(M.errorText(rb.error), true); return }
                if (rb.exists === false) {
                    view.holdingHex = acc
                    view.submitClaim(cfg, acc, amount)
                } else {
                    view.deriveHolding(cfg, amount, tries + 1)
                }
            })
        })
    }

    function submitClaim(cfg, acc, amount) {
        report("Claiming " + amount + " RLNTOK into " + M.truncateHex(acc, 10, 6) + "…", false)
        M.call(bridge, M.LEZ_RLN_MODULE, "claim_tokens", [cfg, acc, amount], function (r) {
            if (r.error) { view.claiming = false; view.report(M.errorText(r.error), true); return }
            view.report("Claim accepted — waiting for the credit to land…", false)
            view.claimPolls = 0
            claimTimer.start()
        })
    }

    // A claim beyond the faucet's remaining balance is accepted and then
    // silently never funds the holding — hence the hard poll timeout
    // (36 polls x 5s = 180s).
    function pollClaim() {
        claimPolls += 1
        M.call(bridge, M.LEZ_RLN_MODULE, "get_token_balance", [holdingHex], function (r) {
            if (!r.error) {
                var bal = parseInt(r.balance !== undefined ? r.balance : "0", 10)
                view.holdingBalance = String(bal)
                if (r.exists === true && bal >= view.claimAmount) {
                    claimTimer.stop()
                    view.claiming = false
                    view.report("Holding funded with " + bal + " RLNTOK — the Register tab's "
                        + "funding account has been filled in.", false)
                    view.funded(view.holdingHex)
                    return
                }
            }
            if (view.claimPolls >= 36) {
                claimTimer.stop()
                view.claiming = false
                view.report("Claim submitted but never funded within 180s — the faucet may be "
                    + "exhausted or the wallet unsynced (transactions from an unsynced wallet are "
                    + "silently dropped). Re-run Sync, check the faucet balance, then try a "
                    + "smaller claim.", true)
            } else {
                view.report("Waiting for the credit to land… (" + (view.claimPolls * 5)
                    + "s of 180s, balance " + (view.holdingBalance === "" ? "0" : view.holdingBalance)
                    + ")", false)
            }
        })
    }

    Timer {
        id: progressTimer
        interval: 4000
        repeat: true
        onTriggered: view.pollSyncProgress()
    }

    Timer {
        id: claimTimer
        interval: 5000
        repeat: true
        onTriggered: view.pollClaim()
    }

    ColumnLayout {
        width: view.availableWidth
        spacing: Theme.spacing.medium

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Wallet"

            ColumnLayout {
                spacing: Theme.spacing.small

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText {
                        text: "Sequencer"
                        color: Theme.palette.textSecondary
                    }
                    LogosTextField {
                        id: sequencerField
                        Layout.fillWidth: true
                        text: M.TESTNET_SEQUENCER_ADDR
                        placeholderText: "Sequencer address for a freshly provisioned wallet_config.json"
                    }

                    LogosText {
                        text: "Password"
                        color: Theme.palette.textSecondary
                    }
                    LogosTextField {
                        id: createPasswordField
                        Layout.fillWidth: true
                        echoMode: TextInput.Password
                        placeholderText: "Storage password (used when creating a new wallet)"
                    }
                }

                RowLayout {
                    spacing: Theme.spacing.small

                    LogosButton {
                        implicitWidth: 180
                        implicitHeight: 40
                        text: "Use basecamp wallet"
                        enabled: !view.busy && !view.walletOpen && sequencerField.text.trim() !== ""
                        onClicked: view.doProvision()
                    }
                    LogosSpinner {
                        visible: view.busy
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                    LogosText {
                        visible: view.walletOpen
                        text: "Wallet open"
                        color: Theme.palette.success
                        font.pixelSize: Theme.typography.secondaryText
                    }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "One click: the membership module provisions wallet-home under its own "
                        + "basecamp data directory (wallet_config.json is written once with this "
                        + "sequencer), then the wallet is opened — or created, showing its "
                        + "recovery mnemonic once, when no storage exists there yet."
                }

                LogosText {
                    visible: view.mnemonic !== ""
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.warning
                    text: "Recovery mnemonic (shown once — write it down):\n" + view.mnemonic
                }

                LogosCheckbox {
                    id: advancedToggle
                    text: "Advanced: use existing wallet files"
                }

                ColumnLayout {
                    visible: advancedToggle.checked
                    Layout.fillWidth: true
                    spacing: Theme.spacing.small

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: Theme.spacing.medium
                        rowSpacing: Theme.spacing.small

                        LogosText {
                            text: "Config"
                            color: Theme.palette.textSecondary
                        }
                        LogosTextField {
                            id: configField
                            Layout.fillWidth: true
                            placeholderText: "Path to wallet_config.json"
                        }

                        LogosText {
                            text: "Storage"
                            color: Theme.palette.textSecondary
                        }
                        LogosTextField {
                            id: storageField
                            Layout.fillWidth: true
                            placeholderText: "Path to storage.json (created by Create wallet)"
                        }
                    }

                    RowLayout {
                        spacing: Theme.spacing.small

                        LogosButton {
                            implicitWidth: 130
                            implicitHeight: 40
                            text: "Open wallet"
                            enabled: !view.busy && !view.walletOpen
                                     && configField.text.trim() !== "" && storageField.text.trim() !== ""
                            onClicked: view.doOpen()
                        }
                        LogosButton {
                            implicitWidth: 130
                            implicitHeight: 40
                            text: "Create wallet"
                            enabled: !view.busy && !view.walletOpen
                                     && configField.text.trim() !== "" && storageField.text.trim() !== ""
                            onClicked: view.doCreate()
                        }
                    }

                    LogosText {
                        visible: !view.walletOpen
                                 && (configField.text.trim() === "" || storageField.text.trim() === "")
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.typography.secondaryText
                        color: Theme.palette.warning
                        text: "Fill in both paths to enable Open / Create (an externally staged "
                            + "wallet, e.g. a funded wallet-home, stays reachable this way)."
                    }

                    LogosText {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.typography.secondaryText
                        color: Theme.palette.textTertiary
                        text: "The wallet module reads these paths itself (it runs outside the UI "
                            + "sandbox). Open expects an existing storage.json; Create must point at "
                            + "a NEW storage file next to an existing wallet_config.json — it refuses "
                            + "a storage file that opens, but an existing file that FAILS to open "
                            + "(corrupt, foreign format) would be overwritten. Deployment fixtures "
                            + "are staged with tools/deployments/stage.sh <deployment-dir> <wallet-home>."
                    }
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Sync"

            ColumnLayout {
                spacing: Theme.spacing.small

                RowLayout {
                    spacing: Theme.spacing.small

                    LogosButton {
                        implicitWidth: 130
                        implicitHeight: 40
                        text: "Sync to head"
                        enabled: view.walletOpen && !view.syncing && !view.busy
                        onClicked: view.startSync()
                    }
                    LogosSpinner {
                        visible: view.syncing
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                    LogosText {
                        visible: view.syncing || view.synced || view.lastSynced >= 0
                        text: view.synced
                              ? "Synced to block " + view.lastSynced
                              : (view.syncTarget > 0
                                 ? "Block " + Math.max(view.lastSynced, 0) + " / " + view.syncTarget
                                 : "")
                        color: view.synced ? Theme.palette.success : Theme.palette.textSecondary
                        font.pixelSize: Theme.typography.secondaryText
                    }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "The chain head is discovered from the wallet's sequencer connection. "
                        + "Sync must genuinely complete before claiming or registering: an "
                        + "unsynced wallet's transactions are accepted but never apply."
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Faucet claim"

            ColumnLayout {
                spacing: Theme.spacing.small

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText {
                        text: "Amount"
                        color: Theme.palette.textSecondary
                    }
                    RowLayout {
                        spacing: Theme.spacing.small

                        LogosTextField {
                            id: amountField
                            Layout.preferredWidth: 180
                            placeholderText: "RLNTOK"
                        }
                        LogosText {
                            text: view.pricePerUnit !== ""
                                  ? "RLNTOK (registration costs rate × " + view.pricePerUnit + ")"
                                  : "RLNTOK (suggested after sync: rate × price × 1.2)"
                            color: Theme.palette.textTertiary
                            font.pixelSize: Theme.typography.secondaryText
                        }
                    }
                }

                RowLayout {
                    spacing: Theme.spacing.small

                    LogosButton {
                        implicitWidth: 200
                        implicitHeight: 40
                        text: "Claim into fresh holding"
                        enabled: view.walletOpen && view.synced && !view.claiming && !view.busy
                                 && parseInt(amountField.text, 10) > 0
                        onClicked: view.startClaim()
                    }
                    LogosSpinner {
                        visible: view.claiming
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                }

                RowLayout {
                    visible: view.holdingHex !== ""
                    spacing: Theme.spacing.small

                    LogosText {
                        text: "Holding"
                        color: Theme.palette.textSecondary
                        font.pixelSize: Theme.typography.secondaryText
                    }
                    LogosText {
                        text: M.truncateHex(view.holdingHex, 16, 8)
                              + (view.holdingBalance !== "" ? "   balance " + view.holdingBalance : "")
                        font.pixelSize: Theme.typography.secondaryText
                    }
                }

                LogosText {
                    visible: view.status !== ""
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: view.statusIsError ? Theme.palette.error : Theme.palette.textSecondary
                    text: view.status
                }
            }
        }
    }

    Connections {
        target: amountField.textInput
        function onTextEdited() { view.amountTouched = true }
    }
}
