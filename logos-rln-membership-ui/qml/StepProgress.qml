// Segmented Syncing→Claiming→Registering bar driven by the flow's phase
// properties, with a stage caption above it and an inline Retry on a failed
// segment. OnboardingView hands off the instant registration completes, so
// this view only ever paints the in-progress and error states.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

ColumnLayout {
    id: step

    required property OnboardingFlow flow

    // Item 1 folds wallet provision/open/create into "syncing".
    readonly property string syncStatus:
        (flow.walletPhase === "error" || flow.syncPhase === "error") ? "error"
        : flow.syncPhase === "done" ? "done"
        : flow.walletPhase === "idle" ? "upcoming" : "active"

    readonly property string currentError:
        flow.walletPhase === "error" ? flow.walletError
        : flow.syncPhase === "error" ? flow.syncError
        : flow.fundPhase === "error" ? flow.fundError
        : flow.regPhase === "error" ? flow.regError : ""

    // Resume-aware kick-off: the guards cover already-done phases; the
    // Connections chain live transitions.
    function entered() {
        if (flow.walletPhase === "done")
            flow.startSync()
        else
            flow.startWallet()
        if (flow.syncPhase === "done" && flow.fundPhase !== "done")
            flow.startFunding()
        if (flow.fundPhase === "done" && flow.regPhase !== "done")
            flow.startRegistration()
    }

    function retryErroredSegment() {
        if (flow.walletPhase === "error") { flow.startWallet(); return }
        if (flow.syncPhase === "error") { flow.startSync(); return }
        if (flow.fundPhase === "error") { flow.restartFunding(); return }
        if (flow.regPhase === "error") { flow.retryRegistration(); return }
    }

    Connections {
        target: step.flow
        function onSyncPhaseChanged() {
            if (step.flow.syncPhase === "done")
                step.flow.startFunding()
        }
        function onFundPhaseChanged() {
            if (step.flow.fundPhase === "done")
                step.flow.startRegistration()
        }
    }

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: "Setting everything up…"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        text: "This takes a few minutes — hang tight."
    }

    // Hidden during an error — the bar's own error row carries the message.
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        visible: step.flow.regPhase !== "done" && step.currentError === ""
        font.pixelSize: M.sc(Theme.typography.subtitleText)
        font.weight: Theme.typography.weightMedium
        color: Theme.palette.text
        text: progressRow.stageLabel
    }

    // Intra-sync progress lives inside segment 1's fill (which advances with
    // the chunked sync); there is no separate sync bar.
    MembershipRow {
        id: progressRow
        Layout.fillWidth: true
        rowKind: "progress"
        flow: step.flow
        commitment: step.flow.commitment
        onRetryRequested: step.retryErroredSegment()
    }

    LogosText {
        visible: step.currentError !== ""
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.textTertiary
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: step.currentError
    }

    // Registration may have failed for lack of funds: offer a fresh claim.
    // LogosButton has no font hook, so text stays "" and a scaled overlay
    // LogosText paints the label; the plain Text passes clicks through.
    LogosButton {
        visible: step.flow.regPhase === "error"
        Layout.alignment: Qt.AlignHCenter
        implicitWidth: M.sc(160)
        implicitHeight: M.sc(34)
        text: ""
        onClicked: step.flow.restartFunding()
        LogosText {
            anchors.centerIn: parent
            text: "Get more tokens"
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            font.weight: Theme.typography.weightMedium
            color: Theme.palette.text
        }
    }

    LogosText {
        visible: step.flow.rateLimitMismatch
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.warning
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: "This identity is already registered with different settings — the existing registration wins."
    }
}
