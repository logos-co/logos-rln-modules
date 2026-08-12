// Step 2 — one password encrypts both the wallet storage and the credential
// keystore. Copy adapts to Main's probe: creation framing (with confirm) for
// fresh installs, entry framing when local records exist. The shell gates
// Continue on unlock_keystore succeeding; fields freeze once walletCreated.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

ColumnLayout {
    id: step

    required property OnboardingFlow flow
    readonly property bool ready: passwordField.text.length > 0
                                  && (flow.hasExistingAccount
                                      || passwordField.text === confirmField.text)
                                  && flow.unlockPhase !== "running"
    function entered() {}

    // LogosTextField sizes its input/placeholder from a fixed caption token
    // with no declarative hook; lift them once to the scaled size.
    Component.onCompleted: {
        var px = M.sc(Theme.typography.secondaryText)
        passwordField.textInput.font.pixelSize = px
        passwordField.placeholderItem.font.pixelSize = px
        confirmField.textInput.font.pixelSize = px
        confirmField.placeholderItem.font.pixelSize = px
    }

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: step.flow.hasExistingAccount ? "Enter your password" : "Choose a password"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        // bad_password here means a stale saved sign-in: a keychain item
        // exists but its secret no longer opens the keystore.
        text: step.flow.autoUnlockKind === "bad_password"
              ? "Your saved sign-in didn't match — use the password from your earlier setup."
              : step.flow.hasExistingAccount
                ? "Use the password from your earlier setup."
                : "It protects your account on this device."
    }

    LogosTextField {
        id: passwordField
        Layout.fillWidth: true
        implicitHeight: M.sc(40)
        echoMode: TextInput.Password
        placeholderText: "Password"
        enabled: !step.flow.walletCreated
        onTextChanged: if (!step.flow.walletCreated) step.flow.password = text
    }
    // For an existing account the unlock check is the confirmation.
    LogosTextField {
        id: confirmField
        visible: !step.flow.hasExistingAccount
        Layout.fillWidth: true
        implicitHeight: M.sc(40)
        echoMode: TextInput.Password
        placeholderText: "Confirm password"
        enabled: !step.flow.walletCreated
    }

    LogosText {
        visible: !step.flow.hasExistingAccount && confirmField.text.length > 0
                 && passwordField.text !== confirmField.text
        Layout.fillWidth: true
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.warning
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: "Passwords don't match yet."
    }

    LogosText {
        visible: step.flow.walletCreated
        Layout.fillWidth: true
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.textTertiary
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: "Your password is set."
    }

    RowLayout {
        visible: step.flow.unlockPhase === "running"
        Layout.alignment: Qt.AlignHCenter
        spacing: M.sc(Theme.spacing.small)

        LogosSpinner {
            implicitWidth: M.sc(18)
            implicitHeight: M.sc(18)
            thickness: M.sc(2)
            dotSize: M.sc(4)
        }
        LogosText {
            text: step.flow.hasExistingAccount ? "Checking…" : "Just a moment…"
            color: Theme.palette.textSecondary
            font.pixelSize: M.sc(Theme.typography.secondaryText)
        }
    }

    ColumnLayout {
        visible: step.flow.unlockError !== ""
        Layout.fillWidth: true
        spacing: M.sc(Theme.spacing.tiny)

        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: M.sc(Theme.typography.primaryText)
            color: Theme.palette.error
            text: "Check your password and try again."
        }
        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.textTertiary
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: step.flow.unlockError
        }
    }
}
