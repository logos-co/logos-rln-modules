// Register flow: unlock keystore -> register (the membership module generates
// the credential) -> poll get_membership_state until the pending window
// settles. The funding holding account is either typed in or auto-filled by
// the Wallet tab's faucet claim (Main.qml wires WalletView.funded to
// fundingAccount).
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosScrollView {
    id: view

    required property var bridge
    required property string registryId

    // Written by Main.qml when the Wallet tab confirms a funded holding.
    property alias fundingAccount: fundingField.text

    // Keystore session (unlock holds the password module-side; lock drops it).
    property bool unlocked: false
    property int membershipCount: -1

    // The public commitment from register's reply. The identity secret is
    // generated and kept inside the module and never reaches QML.
    property string commitment: ""

    property bool busy: false
    property string status: ""
    property bool statusIsError: false
    property string liveState: ""

    // True once the module's push channel is armed on this bridge (see
    // M.armModuleEvent). This view is wired with only bridge + registryId,
    // so it arms its own subscription.
    property bool eventsArmed: false

    Component.onCompleted: {
        view.eventsArmed = M.armModuleEvent(view.bridge, M.RLN_MODULE, M.MEMBERSHIP_STATE_CHANGED)
    }

    function report(text, isError) {
        status = text
        statusIsError = isError === true
    }

    function doUnlock() {
        busy = true
        M.call(bridge, M.RLN_MODULE, "unlock_keystore", [passwordField.text], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            view.unlocked = r.unlocked === true
            view.membershipCount = r.membership_count !== undefined ? r.membership_count : -1
            view.report(view.membershipCount === 0
                ? "Keystore unlocked (empty) — this password becomes the encryption password when the first credential is stored."
                : "Keystore unlocked — " + view.membershipCount + " stored credential"
                  + (view.membershipCount === 1 ? "" : "s") + ".", false)
        })
    }

    function doLock() {
        busy = true
        M.call(bridge, M.RLN_MODULE, "lock_keystore", [], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            view.unlocked = false
            view.membershipCount = -1
            view.report("Keystore locked.", false)
        })
    }

    function doRegister() {
        // The credential is generated inside the module; the caller supplies
        // only the scope (registry_id + rln_identifier) and, for the logos
        // namespace, the paying account.
        var options = JSON.stringify({
            funding_holding_account_id: fundingField.text.trim()
        })
        busy = true
        liveState = ""
        M.call(bridge, M.RLN_MODULE, "register",
               [registryId, M.DEFAULT_RLN_ID, rateSpin.value, options], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            // register returns the public Membership view; the commitment is the
            // only credential-derived value it exposes.
            view.commitment = (r.credential && r.credential.identity_commitment) || ""
            view.liveState = r.state || "pending"
            var note = r.rate_limit_mismatch === true
                ? " NOTE: already registered on-chain with a different rate limit." : ""
            view.report("Registration submitted (membership "
                + M.truncateHex(r.membership_hash || "", 12, 6)
                + ") — testnet confirmation takes ~60-90s." + note, false)
            pollTimer.start()
        })
    }

    function pollState() {
        if (registryId === "") { pollTimer.stop(); return }
        M.call(bridge, M.RLN_MODULE, "get_membership_state",
               [registryId, M.DEFAULT_RLN_ID], function (r) {
            if (r.error) { pollTimer.stop(); view.report(M.errorText(r.error), true); return }
            view.liveState = r.state || "unknown"
            if (view.liveState === "pending") return
            pollTimer.stop()
            if (view.liveState === "active")
                view.report("Membership ACTIVE at leaf " + r.leaf_index
                    + ". On this testnet it stays active ~43 min before grace_period/expired.", false)
            else if (view.liveState === "failed")
                view.report("Registration FAILED — see the Memberships tab for the failure reason.", true)
            else
                view.report("Membership settled in state \"" + view.liveState + "\".", false)
        })
    }

    // The pending confirmation window is bounded (300s) module-side, so the
    // poll always reaches a settled state and stops itself. 60s once
    // eventsArmed (a slow-poll safety net behind the Connections below);
    // 10s otherwise.
    Timer {
        id: pollTimer
        interval: view.eventsArmed ? 60000 : 10000
        repeat: true
        onTriggered: view.pollState()
    }

    // Wake-up only — pollState() re-reads authoritatively. Any state change
    // on this registry re-triggers while a registration is pending; gated on
    // pollTimer.running so an event outside an active confirmation wait is a
    // no-op.
    Connections {
        target: view.bridge
        enabled: view.eventsArmed
        function onModuleEventReceived(moduleName, eventName, data) {
            if (moduleName !== M.RLN_MODULE || eventName !== M.MEMBERSHIP_STATE_CHANGED)
                return
            var evt = M.decodeMembershipStateChanged(data)
            if (evt && evt.registry_id === view.registryId && pollTimer.running)
                view.pollState()
        }
    }

    ColumnLayout {
        width: view.availableWidth
        spacing: Theme.spacing.medium

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Keystore"

            ColumnLayout {
                spacing: Theme.spacing.small

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacing.small

                    LogosTextField {
                        id: passwordField
                        Layout.fillWidth: true
                        echoMode: TextInput.Password
                        placeholderText: "Keystore password"
                        enabled: !view.unlocked
                    }
                    LogosButton {
                        implicitWidth: 110
                        implicitHeight: 40
                        text: view.unlocked ? "Lock" : "Unlock"
                        enabled: !view.busy && (view.unlocked || passwordField.text.length > 0)
                        onClicked: view.unlocked ? view.doLock() : view.doUnlock()
                    }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "First use: with an empty keystore ANY password unlocks and becomes "
                        + "the keystore's encryption password when the first credential is "
                        + "stored (the keystore format has no up-front verifier). Later "
                        + "unlocks are checked against the stored credentials."
                }

                LogosText {
                    visible: view.unlocked
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.success
                    text: view.membershipCount < 0 ? "Unlocked"
                        : "Unlocked — " + view.membershipCount + " stored credential"
                          + (view.membershipCount === 1 ? "" : "s")
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Identity"

            ColumnLayout {
                spacing: Theme.spacing.small

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "The identity credential is generated inside the membership module "
                        + "when you register; its secret never leaves the module. The public "
                        + "commitment appears below after registration."
                }

                RowLayout {
                    visible: view.commitment !== ""
                    spacing: Theme.spacing.small

                    LogosText {
                        text: "Commitment"
                        color: Theme.palette.textSecondary
                        font.pixelSize: Theme.typography.secondaryText
                    }
                    LogosText {
                        text: M.truncateHex(view.commitment, 16, 8)
                        font.pixelSize: Theme.typography.secondaryText
                    }
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Registration"

            ColumnLayout {
                spacing: Theme.spacing.small

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText {
                        text: "Rate limit"
                        color: Theme.palette.textSecondary
                    }
                    RowLayout {
                        spacing: Theme.spacing.small

                        LogosSpinBox {
                            id: rateSpin
                            from: M.RATE_LIMIT_MIN
                            to: M.RATE_LIMIT_MAX
                            value: M.RATE_LIMIT_DEFAULT
                            stepSize: 10
                        }
                        LogosText {
                            text: "messages per epoch (" + M.RATE_LIMIT_MIN + "–" + M.RATE_LIMIT_MAX + ")"
                            color: Theme.palette.textTertiary
                            font.pixelSize: Theme.typography.secondaryText
                        }
                    }

                    LogosText {
                        text: "Funding account"
                        color: Theme.palette.textSecondary
                    }
                    LogosTextField {
                        id: fundingField
                        Layout.fillWidth: true
                        placeholderText: "Funded holding account (hex or base58) — or claim one on the Wallet tab"
                    }
                }

                RowLayout {
                    spacing: Theme.spacing.small

                    LogosButton {
                        implicitWidth: 180
                        implicitHeight: 40
                        text: "Register membership"
                        enabled: !view.busy && view.unlocked
                                 && fundingField.text.trim() !== "" && view.registryId !== ""
                        onClicked: view.doRegister()
                    }
                    LogosSpinner {
                        visible: view.busy || pollTimer.running
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                    StateBadge {
                        visible: view.liveState !== ""
                        membershipState: view.liveState
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
}
