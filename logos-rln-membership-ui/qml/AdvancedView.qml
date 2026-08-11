// The expert three-tab UI (Register / Memberships / Wallet) — a verbatim
// lift of the pre-wizard Main body, live-proven against the testnet, now
// demoted to the "Advanced" mode behind the onboarding wizard and status
// card. Additions over the lifted body: the "Exit advanced" affordance and
// the registryEdited signal (the registry field is Advanced-only; edits
// propagate up to Main, which re-probes on exit).
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: view

    required property var bridge
    // Initial value only — the field is the live source while in Advanced,
    // reported upward through registryEdited.
    property string registryId: M.TESTNET_REGISTRY_ID

    signal registryEdited(string registryId)
    signal exitRequested()

    Component.onCompleted: registryField.text = registryId

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacing.large
        spacing: Theme.spacing.medium

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacing.small

            LogosText {
                text: "RLN Membership"
                font.pixelSize: Theme.typography.titleText
                font.weight: Theme.typography.weightBold
            }
            Item { Layout.fillWidth: true }
            LogosButton {
                implicitWidth: 130
                implicitHeight: 36
                text: "Exit advanced"
                onClicked: view.exitRequested()
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacing.small

            LogosText {
                text: "Registry"
                color: Theme.palette.textSecondary
            }
            LogosTextField {
                id: registryField
                Layout.fillWidth: true
                placeholderText: "logos:<reference>:<config-account-hex> (CAIP-10)"
                onTextChanged: view.registryEdited(text.trim())
            }
        }

        LogosTabBar {
            id: tabs
            Layout.fillWidth: true
            LogosTabButton { text: "Register" }
            LogosTabButton { text: "Memberships" }
            LogosTabButton { text: "Wallet" }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabs.currentIndex

            RegisterView {
                id: registerView
                bridge: view.bridge
                registryId: registryField.text.trim()
            }
            MembershipsView {
                bridge: view.bridge
                registryId: registryField.text.trim()
            }
            WalletView {
                bridge: view.bridge
                registryId: registryField.text.trim()
                // A confirmed faucet claim fills the Register tab's funding
                // account with the freshly funded holding.
                onFunded: function (holdingHex) {
                    registerView.fundingAccount = holdingHex
                }
            }
        }
    }
}
