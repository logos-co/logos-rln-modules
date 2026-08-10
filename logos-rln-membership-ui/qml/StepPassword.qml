// Step 2 — one password protects the whole account (it encrypts both the
// wallet storage and the credential keystore). The copy adapts to Main's
// probe: creation framing ("Choose a password" + confirm — a typo would
// lock the user out of both stores) for fresh installs, entry framing
// ("Enter your password", no confirm: the unlock check IS the
// confirmation) when local records exist. The shell gates Continue on
// unlock_keystore succeeding, so a wrong password surfaces here, before
// the minutes-long setup steps. Fields freeze once the account was created
// with this password. The rate limit is fixed at the default here —
// choosing one is an Advanced concern.
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

    // LogosTextField sizes its inner input/placeholder from a fixed caption
    // token with no declarative hook, so at 2x the glyphs would stay small in
    // a doubled field. Lift them once to the scaled size to match the rest.
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
        // A stale saved sign-in (keychain item present but its secret no
        // longer opens the keystore) is the one fallback worth naming.
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
    // Confirming is a creation concern — for an existing account the unlock
    // check itself is the confirmation.
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
            // A brand-new account has nothing to check against — the
            // password is being adopted, so the copy stays neutral.
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
