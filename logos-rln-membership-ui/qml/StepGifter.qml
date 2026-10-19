// The allocator work screen (step 2 in "allocator" mode): point at an
// allocator node, pick the auth vector it accepts, satisfy its gate (card on
// the reader / address allowlisted), and the allocator pays for the
// registration. Takes input, so it owns its own action button and progress —
// the shell hides the shared CTA on step 2.
//
// This is the "configure your app for membership allocation" surface: the
// three fields map 1:1 onto the delegated RegistryOptions
// (gifter_peer_id, gifter_multiaddr, auth_type + auth_provider) that
// M.delegatedOptions builds for liblogos_rln_module.register_membership.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

ColumnLayout {
    id: step

    required property OnboardingFlow flow

    readonly property var vector: M.authVector(flow.authType)
    readonly property bool busy: flow.gifterPhase === "running" || flow.regPhase === "running"
    readonly property bool ready: flow.gifterPeerId.trim().length > 0
                                  && flow.gifterMultiaddr.trim().length > 0
                                  && !step.busy
    // No auto-start: the user supplies the allocator and starts it.
    function entered() {}

    // Caption for the running sub-step. The "capture" caption (keep the card
    // on the reader) holds while the module captures + dials in the
    // background, until the shared confirmation poll settles.
    readonly property string stageCaption:
        flow.gifterStage === "node" ? "Starting a peer-to-peer node…"
        : flow.gifterStage === "capture" ? "Hold your Keycard on the reader…"
        : flow.gifterStage === "address" ? "Reading this device's Ethereum address…"
        : flow.regPhase === "running" ? "Waiting for the allocator and the registry…"
        : "Working…"

    // LogosTextField sizes its glyphs from a fixed caption token; lift them
    // to the scaled size at 2x.
    Component.onCompleted: {
        var px = M.sc(Theme.typography.secondaryText)
        peerIdField.text = step.flow.gifterPeerId
        multiaddrField.text = step.flow.gifterMultiaddr
        authArgsField.text = step.flow.authArgs
        var fields = [peerIdField, multiaddrField, authArgsField]
        for (var i = 0; i < fields.length; i++) {
            fields[i].textInput.font.pixelSize = px
            fields[i].placeholderItem.font.pixelSize = px
        }
    }

    // eth-allowlist: show the address as soon as the vector is chosen, so the
    // operator can allowlist it before the first request.
    function onVectorPicked(id) {
        step.flow.authType = id
        if (M.authVector(id).gate === "address" && step.flow.ethAddress === "")
            step.flow.fetchEthAddress()
    }

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: "Register through an allocator"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        text: "No funds needed — an allocator registers your membership and pays for it "
              + "once you prove what it asks for. Its operator publishes the peer id and "
              + "address below."
    }

    ColumnLayout {
        visible: step.flow.gifterPhase === "idle" || step.flow.gifterPhase === "error"
        Layout.fillWidth: true
        spacing: M.sc(Theme.spacing.small)

        LogosTextField {
            id: peerIdField
            objectName: "gifterPeerIdField"
            Layout.fillWidth: true
            implicitHeight: M.sc(40)
            placeholderText: "Allocator peer id (16Uiu2HAm…)"
            enabled: !step.busy
            onTextChanged: step.flow.gifterPeerId = text
        }
        LogosTextField {
            id: multiaddrField
            objectName: "gifterMultiaddrField"
            Layout.fillWidth: true
            implicitHeight: M.sc(40)
            placeholderText: "Allocator address (/ip4/…/tcp/…)"
            enabled: !step.busy
            onTextChanged: step.flow.gifterMultiaddr = text
        }

        LogosText {
            Layout.fillWidth: true
            Layout.topMargin: M.sc(Theme.spacing.tiny)
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textSecondary
            text: "How the allocator checks you:"
        }
        AuthVectorPicker {
            Layout.fillWidth: true
            scale: M.UI_SCALE
            authType: step.flow.authType
            enabled: !step.busy
            onPicked: function (id) { step.onVectorPicked(id) }
        }
        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            color: Theme.palette.textTertiary
            text: step.vector.hint + " Allocators grant " + step.flow.delegatedRateLimit
                  + " messages per epoch unless their operator raised the cap."
        }

        // eth-allowlist: the address the operator has to allowlist.
        ColumnLayout {
            visible: step.vector.gate === "address"
            Layout.fillWidth: true
            spacing: M.sc(Theme.spacing.tiny)

            LogosText {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                font.pixelSize: M.sc(Theme.typography.secondaryText)
                color: Theme.palette.textSecondary
                text: "Ask the allocator's operator to allowlist this device's address:"
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: M.sc(Theme.spacing.small)

                LogosText {
                    objectName: "ethAddressText"
                    Layout.fillWidth: true
                    elide: Text.ElideMiddle
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                    font.family: "monospace"
                    text: step.flow.ethAddress !== "" ? step.flow.ethAddress : "reading…"
                }
                CopyButton { payload: step.flow.ethAddress }
            }
        }

        LogosTextField {
            id: authArgsField
            objectName: "authArgsField"
            visible: step.vector.id !== "none"
            Layout.fillWidth: true
            implicitHeight: M.sc(40)
            placeholderText: "Producer arguments (JSON, optional)"
            enabled: !step.busy
            onTextChanged: step.flow.authArgs = text
        }
    }

    PrimaryButton {
        objectName: "registerDelegatedButton"
        visible: step.flow.gifterPhase !== "done" || step.flow.regPhase === "error"
        Layout.fillWidth: true
        implicitHeight: M.sc(44)
        text: step.flow.gifterPhase === "error" ? "Try again"
            : step.vector.gate === "card" ? "Register with Keycard"
            : "Register via allocator"
        enabled: step.ready
        onClicked: step.flow.retryGifter()
    }

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
            text: "That didn't work — check the allocator details"
                  + (step.vector.gate === "card" ? " and your card" : "") + ", then try again."
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
