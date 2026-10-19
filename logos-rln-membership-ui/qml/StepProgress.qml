// The funded-path work screen (step 2 in "funded" mode): a segmented
// Preparing→Registering bar driven by the flow's phase properties, the
// module's provisioning caption above it, the "send <required> to <payer>"
// block while the module waits for funds, and an inline Retry on a failed
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

    readonly property string currentError: flow.regPhase === "error" ? flow.regError : ""
    readonly property var prov: flow.provisioning || ({})
    readonly property bool awaitingFunding: flow.provisioningStep === "awaiting_funding"

    // Resume-aware kick-off: the guard covers an already-done registration.
    function entered() {
        if (flow.regPhase !== "done")
            flow.startRegistration()
    }

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: step.awaitingFunding ? "Fund your account" : "Setting everything up…"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        text: step.awaitingFunding
              ? "Registration costs a small native balance. Send it to the account below "
                + "and this screen continues on its own."
              : "This takes a few minutes — hang tight."
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

    MembershipRow {
        id: progressRow
        Layout.fillWidth: true
        rowKind: "progress"
        flow: step.flow
        commitment: step.flow.commitment
        onRetryRequested: step.flow.retryRegistration()
    }

    // The module's own sentence for the step (e.g. why it is waiting), as
    // fine print under the bar.
    LogosText {
        visible: step.currentError === "" && !!step.prov.detail && !step.awaitingFunding
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.textTertiary
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: String(step.prov.detail || "")
    }

    // awaiting_funding: the numbers behind the sentence, rendered from the
    // structured fields (never parsed out of `detail`).
    ColumnLayout {
        objectName: "fundingBlock"
        visible: step.awaitingFunding && step.currentError === ""
        Layout.fillWidth: true
        spacing: M.sc(Theme.spacing.small)

        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textSecondary
            text: "Send at least"
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: M.sc(Theme.spacing.small)
            LogosText {
                objectName: "fundingRequired"
                Layout.fillWidth: true
                font.pixelSize: M.sc(Theme.typography.subtitleText)
                font.weight: Theme.typography.weightBold
                text: String(step.prov.required || "—") + " native"
            }
            CopyButton { payload: String(step.prov.required || "") }
        }
        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textTertiary
            text: "(price " + String(step.prov.price || "—") + " + fee reserve "
                  + String(step.prov.fee_reserve || "—") + ")"
        }
        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textSecondary
            text: "to this account"
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: M.sc(Theme.spacing.small)
            LogosText {
                objectName: "fundingPayer"
                Layout.fillWidth: true
                elide: Text.ElideMiddle
                font.pixelSize: M.sc(Theme.typography.secondaryText)
                font.family: "monospace"
                text: String(step.prov.payer || "—")
            }
            CopyButton { payload: String(step.prov.payer || "") }
        }
        LogosText {
            visible: step.prov.balance !== undefined
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textTertiary
            text: "Balance so far: " + String(step.prov.balance)
        }
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
