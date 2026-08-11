// Step 1 — the pitch and nothing else: one headline, one sentence, Get
// started. A prior-membership notice from the startup probe and a plain
// explanation when no logos bridge exists are the only extras.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

ColumnLayout {
    id: step

    required property OnboardingFlow flow
    // Also wait for auto-unlock to settle (done|fallback) so Get started
    // knows whether to skip the password screen — instant hermetically (no
    // backend -> immediate fallback), sub-second live.
    readonly property bool ready: flow.bridge !== null
                                  && (flow.autoUnlockPhase === "done"
                                      || flow.autoUnlockPhase === "fallback")
    function entered() {}

    spacing: M.sc(Theme.spacing.medium)

    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.titleText)
        font.weight: Theme.typography.weightBold
        text: "Register to participate in p2p messaging and more!"
    }
    LogosText {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        font.pixelSize: M.sc(Theme.typography.primaryText)
        color: Theme.palette.textSecondary
        text: "It only takes a couple of minutes — we set everything up for you."
    }

    LogosText {
        visible: step.flow.priorNotice !== ""
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.warning
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: step.flow.priorNotice
    }

    LogosText {
        visible: !step.ready
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        color: Theme.palette.error
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        text: "This view must run inside the Logos app for setup to work."
    }
}
