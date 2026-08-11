// The gifter work screen (step 2 in "gifter" mode): point at a gifter node,
// tap a Keycard, and let the gifter pay for the registration. Unlike the wallet
// path's unattended bar this screen takes input (the gifter's peer id/address)
// and a physical card tap, so it owns its own action button and progress — the
// shell hides the shared CTA on step 2. On success the flow's regPhase reaches
// done and OnboardingView hands off to the membership list, same as the wallet
// path.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

ColumnLayout {
    id: step

    required property OnboardingFlow flow

    readonly property bool busy: flow.gifterPhase === "running" || flow.regPhase === "running"
    readonly property bool ready: flow.gifterPeerId.trim().length > 0
                                  && flow.gifterMultiaddr.trim().length > 0
                                  && !step.busy
    // No auto-start: the user supplies the gifter address and taps the card.
    function entered() {}

    // Plain-language caption for the running sub-step. After the delegated
    // register() is dispatched the module captures + dials in the background,
    // so the "capture" caption (keep the card on the reader) holds until the
    // shared confirmation poll settles.
    readonly property string stageCaption:
        flow.gifterStage === "wallet" ? "Setting up your account…"
        : flow.gifterStage === "node" ? "Starting a peer-to-peer node…"
        : flow.gifterStage === "capture" ? "Hold your Keycard on the reader…"
        : flow.regPhase === "running" ? "Confirming your membership on-chain…"
        : "Working…"

    // LogosTextField sizes its glyphs from a fixed caption token; lift them to
    // the scaled size at 2x, as StepPassword does.
    Component.onCompleted: {
        var px = M.sc(Theme.typography.secondaryText)
        peerIdField.text = step.flow.gifterPeerId
        multiaddrField.text = step.flow.gifterMultiaddr
        peerIdField.textInput.font.pixelSize = px
        peerIdField.placeholderItem.font.pixelSize = px
        multiaddrField.textInput.font.pixelSize = px
        multiaddrField.placeholderItem.font.pixelSize = px
    }

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: "Register with a Keycard gift"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        text: "No wallet or tokens needed — a provider registers your membership "
              + "when you prove you hold a genuine Keycard."
    }

    // Gifter coordinates. Hidden once the work starts so the screen becomes a
    // clean progress view.
    ColumnLayout {
        visible: step.flow.gifterPhase === "idle" || step.flow.gifterPhase === "error"
        Layout.fillWidth: true
        spacing: M.sc(Theme.spacing.small)

        LogosTextField {
            id: peerIdField
            Layout.fillWidth: true
            implicitHeight: M.sc(40)
            placeholderText: "Gifter peer id"
            enabled: !step.busy
            onTextChanged: step.flow.gifterPeerId = text
        }
        LogosTextField {
            id: multiaddrField
            Layout.fillWidth: true
            implicitHeight: M.sc(40)
            placeholderText: "Gifter address (/ip4/…/tcp/…)"
            enabled: !step.busy
            onTextChanged: step.flow.gifterMultiaddr = text
        }
    }

    // The action. Owns its own button because step 2 has no shared CTA.
    PrimaryButton {
        visible: step.flow.gifterPhase !== "done" || step.flow.regPhase === "error"
        Layout.fillWidth: true
        implicitHeight: M.sc(44)
        text: step.flow.gifterPhase === "error" ? "Try again" : "Register with Keycard"
        enabled: step.ready
        onClicked: step.flow.retryGifter()
    }

    // Running: a spinner + the current sub-step caption. The capture step is the
    // one that waits on the human, so its caption names the card tap.
    RowLayout {
        visible: step.busy
        Layout.alignment: Qt.AlignHCenter
        spacing: M.sc(Theme.spacing.small)

        LogosSpinner {
            implicitWidth: M.sc(18)
            implicitHeight: M.sc(18)
            thickness: M.sc(2)
            dotSize: M.sc(4)
        }
        LogosText {
            text: step.stageCaption
            color: Theme.palette.text
            font.pixelSize: M.sc(Theme.typography.subtitleText)
            font.weight: Theme.typography.weightMedium
        }
    }

    // Error: plain line + the technical detail, with the retry above.
    ColumnLayout {
        visible: step.flow.gifterError !== "" || step.flow.regError !== ""
        Layout.fillWidth: true
        spacing: M.sc(Theme.spacing.tiny)

        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: M.sc(Theme.typography.primaryText)
            color: Theme.palette.error
            text: "That didn't work — check the gifter details and your card, then try again."
        }
        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.textTertiary
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: step.flow.gifterError !== "" ? step.flow.gifterError : step.flow.regError
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
