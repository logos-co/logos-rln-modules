// Membership DETAIL panel (Main "detail" mode), opened by tapping a pill.
// Shows the selected commitment's petname title, live state badge, on-chain
// expiry context (from the rln module's CLOCK read — never local time), leaf,
// rate, and the real commitment id; a 10s live poll refreshes state while
// visible and degrades silently on a transient provider failure. Back returns
// to the list; Re-register is offered for expired/failed/erased.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: card

    required property var bridge
    required property string registryId
    required property OnboardingFlow flow
    // The membership to show (its public commitment).
    property string commitment: ""

    signal newMembershipRequested()
    signal advancedRequested()
    signal backRequested()

    property bool found: false
    property string liveState: ""
    property string timeContext: ""
    property string leaf: ""
    property string rate: ""
    property string failedReason: ""
    property real submittedAt: 0
    property string error: ""

    // Registration transaction, parsed from the row's (double-encoded)
    // tx_result. hasTx is false for a membership adopted via the
    // already-registered pre-check (no tx we submitted) — the section hides.
    property bool hasTx: false
    property string txHash: ""
    property bool txSuccess: false
    property string txError: ""

    // In-flight guard: one refresh cycle (get_memberships → pollLive's two
    // reads) at a time. Without it, every "Refresh status" tap and every 10s
    // tick spawns an INDEPENDENT get_memberships + pollLive + auto-retry
    // chain; under the flaky transport those chains are long-lived (retries
    // at transientRetryMs, up to an 8s per-attempt timeout on a dropped
    // reply) and stack, flooding the single QtRO transport — an async call
    // storm that hangs the UI without pegging CPU. `pending` counts the
    // reads still outstanding in the current cycle.
    property bool refreshing: false
    property int pending: 0
    // Bound a stuck attempt so a dropped reply releases the guard in seconds
    // instead of the default 30s (auto-retry semantics unchanged).
    readonly property int readTimeoutMs: 8000

    readonly property bool renewable: M.isRenewable(liveState)

    function refresh() {
        if (commitment === "" || refreshing)
            return
        refreshing = true
        flow.callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            if (r.error) {
                // Transient hiccup: keep the card as-is, retry next tick.
                if (!M.isTransientError(r.error.kind)) card.error = M.errorText(r.error)
                card.refreshing = false
                return
            }
            card.error = ""
            var rows = r.memberships || []
            var row = null
            for (var i = 0; i < rows.length; i++) {
                var c = rows[i].credential ? rows[i].credential.identity_commitment : ""
                if (c === card.commitment) { row = rows[i]; break }
            }
            if (!row) { card.found = false; card.refreshing = false; return }
            card.found = true
            card.liveState = row.state || "unknown"
            card.leaf = M.fmtOptionalNum(row.leaf_index)
            card.rate = M.fmtOptionalNum(row.rate_limit)
            card.failedReason = row.failed_reason || ""
            card.submittedAt = row.submitted_at || 0
            card.timeContext = card.liveState === "pending"
                ? "submitted " + M.formatTimestamp(card.submittedAt) : ""
            var tx = M.parseTxResult(row.tx_result)
            card.hasTx = tx !== null
            card.txHash = tx ? tx.hash : ""
            card.txSuccess = tx ? tx.success : false
            card.txError = tx ? tx.error : ""
            card.pollLive()
        }, readTimeoutMs)
    }

    // Clears the guard once every read in the cycle has settled.
    function readDone() {
        card.pending -= 1
        if (card.pending <= 0)
            card.refreshing = false
    }

    function pollLive() {
        if (commitment === "") { card.refreshing = false; return }
        var cfg = M.registryConfigHex(registryId)
        card.pending = cfg === "" ? 1 : 2
        flow.callRetry(M.RLN_MODULE, "get_membership_state",
               [registryId, M.DEFAULT_RLN_ID], function (r) {
            if (!r.error) {
                card.liveState = r.state || card.liveState
                if (r.leaf_index !== undefined)
                    card.leaf = String(r.leaf_index)
                if (r.rate_limit !== undefined)
                    card.rate = String(r.rate_limit)
            }
            card.readDone()
        }, readTimeoutMs)
        if (cfg === "")
            return
        flow.callRetry(M.LEZ_RLN_MODULE, "get_membership", [cfg, commitment], function (r) {
            if (!r.error && r.registered === true) {
                var clock = r.clock_timestamp
                var graceStart = r.grace_period_start_timestamp
                var graceLen = r.grace_period_duration
                if (clock !== undefined && graceStart !== undefined) {
                    if (card.liveState === "active")
                        card.timeContext = "expires in ~" + Math.max(0, Math.round((graceStart - clock) / 60)) + "m"
                    else if (card.liveState === "grace_period" && graceLen !== undefined)
                        card.timeContext = "grace ends in ~"
                            + Math.max(0, Math.round((graceStart + graceLen - clock) / 60)) + "m"
                }
            }
            card.readDone()
        }, readTimeoutMs)
    }

    onVisibleChanged: if (visible) refresh()
    onCommitmentChanged: if (visible) refresh()

    // The periodic live refresh goes through the SAME guarded refresh(), so a
    // tick that lands mid-cycle is skipped rather than stacking a new chain.
    // 60s once the flow's push channel is armed (a slow-poll safety net
    // behind the events below); 10s otherwise, unchanged.
    Timer {
        interval: card.flow.eventsArmed ? 60000 : 10000
        repeat: true
        running: card.visible && card.found
        onTriggered: card.refresh()
    }

    // Wake-up only, exactly like OnboardingFlow's own Connections — refresh()
    // re-reads authoritatively and does its own commitment lookup. Reuses
    // flow.eventsArmed rather than arming a second subscription for the
    // same (module, event) pair on the same bridge object flow already
    // armed. No membership_hash is tracked here either, so any state change
    // on this registry re-triggers while the card is visible; refresh()'s
    // `refreshing` in-flight guard bounds the cost of an unrelated wake-up.
    Connections {
        target: card.flow.bridge
        enabled: card.flow.eventsArmed
        function onModuleEventReceived(moduleName, eventName, data) {
            if (moduleName !== M.RLN_MODULE || eventName !== M.MEMBERSHIP_STATE_CHANGED)
                return
            var evt = M.decodeMembershipStateChanged(data)
            if (evt && evt.registry_id === card.registryId && card.visible && card.found)
                card.refresh()
        }
    }

    CenteredScrollColumn {
        anchors.fill: parent
        spacing: M.sc(Theme.spacing.large)

        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: M.sc(Theme.typography.titleText)
            font.weight: Theme.typography.weightBold
            text: M.petname(card.commitment)
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: M.sc(Theme.spacing.small)

            StateBadge {
                membershipState: card.liveState === "" ? "unknown" : card.liveState
            }
            LogosText {
                visible: card.timeContext !== ""
                text: card.timeContext
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }
        }

        LogosText {
            visible: card.failedReason !== ""
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.error
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: card.failedReason
        }

        GridLayout {
            Layout.fillWidth: true
            columns: 2
            columnSpacing: M.sc(Theme.spacing.large)
            rowSpacing: M.sc(Theme.spacing.small)

            LogosText {
                text: "Rate limit"
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }
            LogosText {
                text: M.rateText(card.rate === "—" ? undefined : card.rate)
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }

            LogosText {
                text: "Leaf index"
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }
            LogosText {
                text: card.leaf
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }

            LogosText {
                text: "Membership id"
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }
            // The full commitment is copyable — it's what `check-membership`
            // (and any on-chain lookup) keys on, since the tx hash isn't
            // queryable on this sequencer.
            RowLayout {
                Layout.fillWidth: true
                spacing: M.sc(Theme.spacing.small)

                LogosText {
                    Layout.fillWidth: true
                    text: M.truncateHex(card.commitment, 10, 8)
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }
                CopyButton {
                    visible: card.commitment !== ""
                    payload: card.commitment
                }
            }
        }

        // Registration transaction (hidden for adopted memberships,
        // which carry no tx we submitted). Same label/value grid style
        // as above: on-chain status, the tx hash, and when it landed.
        ColumnLayout {
            visible: card.hasTx
            Layout.fillWidth: true
            spacing: M.sc(Theme.spacing.small)

            LogosText {
                text: "Registration"
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.primaryText)
                font.weight: Theme.typography.weightMedium
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: M.sc(Theme.spacing.large)
                rowSpacing: M.sc(Theme.spacing.small)

                LogosText {
                    text: "Status"
                    color: Theme.palette.textSecondary
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }
                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    text: card.txSuccess ? "Confirmed"
                         : (card.txError !== "" ? card.txError : "Failed")
                    color: card.txSuccess ? Theme.palette.success : Theme.palette.error
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }

                LogosText {
                    text: "Transaction"
                    color: Theme.palette.textSecondary
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: M.sc(Theme.spacing.small)

                    LogosText {
                        Layout.fillWidth: true
                        text: card.txHash !== "" ? M.truncateHex(card.txHash, 10, 8) : "—"
                        font.pixelSize: M.sc(Theme.typography.secondaryText)
                    }
                    // Copies the FULL hash, not the truncated display.
                    CopyButton {
                        visible: card.txHash !== ""
                        payload: card.txHash
                    }
                }

                LogosText {
                    text: card.liveState === "pending" ? "Submitted" : "Registered"
                    color: Theme.palette.textSecondary
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }
                LogosText {
                    Layout.fillWidth: true
                    text: card.submittedAt > 0 ? M.formatTimestamp(card.submittedAt) : "—"
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                }
            }
        }

        LogosText {
            visible: card.error !== ""
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.error
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: card.error
        }

        PrimaryButton {
            visible: card.renewable
            Layout.fillWidth: true
            implicitHeight: M.sc(44)
            text: "Re-register"
            onClicked: card.newMembershipRequested()
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: M.sc(Theme.spacing.xlarge)

            LinkText {
                text: "Back"
                onClicked: card.backRequested()
            }
            LinkText {
                text: "Refresh status"
                onClicked: card.refresh()
            }
            LinkText {
                text: "Advanced"
                onClicked: card.advancedRequested()
            }
        }
    }
}
