// Onboarding shell: one centered column (both axes), dot progress, step
// bodies in a StackLayout (state retention on Back — a StackView pop would
// destroy the password and progress widgets), a single full-width
// primary CTA, and Back / Advanced-setup as quiet text links. Deliberately
// jargon-free: the steps carry all user-facing copy; the flow controller
// keeps only technical diagnostics, which the steps demote to fine print.
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import "membership.js" as M

Item {
    id: view

    required property var bridge
    required property string registryId

    property alias priorNotice: flow.priorNotice
    property alias hasExistingAccount: flow.hasExistingAccount
    // Read-only handle to the flow controller for inspection/testing (like
    // the design system's *Item aliases) — the mock-bridge harness reads its
    // phase properties and calls its methods through this; prod-inert.
    readonly property alias flowController: flow

    signal completed()
    signal advancedRequested()

    property int currentStep: 0
    readonly property var ctaLabels: ["Get started", "Continue"]

    // When the module auto-unlocked from the keychain, the password screen
    // (physical slot 1) is skipped: Welcome jumps straight to the progress
    // checklist. StepPassword stays instantiated (the hermetic test asserts
    // its title) — only unreachable on the auto path.
    readonly property bool passwordSkipped: flow.autoUnlockPhase === "done"

    // Null-safe sentinel for an out-of-range index so stepItem(i).ready /
    // .entered() can never throw if a future change lets currentStep escape
    // [0,2].
    readonly property var nullStep: ({ ready: false, entered: function () {} })

    function stepItem(i) {
        var items = [welcomeStep, passwordStep, workStep]
        return (i >= 0 && i < items.length) ? items[i] : nullStep
    }

    function advance() {
        // Skip the password slot when auto-unlock already set flow.password.
        currentStep = (currentStep === 0 && passwordSkipped) ? 2 : currentStep + 1
        flow.started = currentStep > 0
        stepItem(currentStep).entered()
    }

    // Re-run for a new membership ("+ New Membership" ghost, or the card's
    // New-membership): funding/registration/sync reset so the progress bar
    // runs fresh; wallet fast-paths on its own. Return to Welcome (clears the
    // started fence) FIRST, then re-fire auto-unlock — a status-first launch
    // never ran it, so without this Welcome's CTA would sit disabled
    // (StepWelcome.ready needs autoUnlock settled). When the account is
    // already unlocked (the post-completion ghost path), jump straight to a
    // fresh segmented bar instead of showing Welcome again.
    function restart() {
        flow.resetForNewRegistration()
        currentStep = 0
        flow.started = false
        flow.startAutoUnlock()
        if (flow.autoUnlockPhase === "done")
            advance()
    }

    // Called by Main when it routes into onboarding.
    function startAutoUnlock() {
        flow.startAutoUnlock()
    }

    function goBack() {
        if (currentStep > 0)
            currentStep -= 1
        flow.started = currentStep > 0
    }

    // The password step's CTA is a gate, not a move: it fires the keystore
    // check and the flow advances only when unlock reports done (the
    // Connections below) — a wrong password surfaces here, before the
    // minutes-long setup steps.
    function onNextClicked() {
        if (currentStep === 1 && flow.unlockPhase !== "done") {
            flow.checkPassword()
            return
        }
        advance()
    }

    OnboardingFlow {
        id: flow
        bridge: view.bridge
        registryId: view.registryId
        onCompleted: view.completed()
    }

    Connections {
        target: flow
        function onUnlockPhaseChanged() {
            if (flow.unlockPhase === "done" && view.currentStep === 1)
                view.advance()
        }
        // Registration done → hand off to the membership list (Main routes to
        // status). The completed membership appears as a pill in the list, so
        // the handoff reads as continuous.
        function onRegPhaseChanged() {
            if (flow.regPhase === "done" && view.currentStep === 2)
                flow.finish()
        }
    }

    // At 2x the centered column can exceed a small pane, so it scrolls (never
    // clips) when it doesn't fit — see CenteredScrollColumn.
    CenteredScrollColumn {
        anchors.fill: parent
        spacing: M.sc(Theme.spacing.xlarge)

        // Progress dots: done/current filled, future muted — screens,
        // not a labeled map. One fewer dot when the password screen is
        // skipped; visualStep maps the physical slot (Welcome 0,
        // Progress 2) onto the dot index so the current dot is right in
        // both layouts.
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: M.sc(Theme.spacing.small)

            Repeater {
                model: view.passwordSkipped ? 2 : 3

                Rectangle {
                    required property int index
                    readonly property int visualStep: view.passwordSkipped
                        ? (view.currentStep === 0 ? 0 : 1) : view.currentStep
                    width: M.sc(8)
                    height: M.sc(8)
                    radius: M.sc(4)
                    color: index < visualStep ? Theme.palette.success
                         : index === visualStep ? Theme.palette.primary
                         : Theme.palette.borderSubtle
                }
            }
        }

        StackLayout {
            Layout.fillWidth: true
            currentIndex: view.currentStep

            StepWelcome { id: welcomeStep; flow: flow }
            StepPassword { id: passwordStep; flow: flow }
            // The work step swaps on registrationMode: the wallet path's
            // unattended bar, or the gifter path's card-tap screen. entered()
            // dispatches to whichever is showing so the shell's kickoff is
            // mode-agnostic; ready is unused (step 2 hides the shared CTA).
            StackLayout {
                id: workStep
                currentIndex: flow.registrationMode === "gifter" ? 1 : 0
                readonly property bool ready: true
                function entered() {
                    if (flow.registrationMode === "gifter")
                        gifterStep.entered()
                    else
                        progressStep.entered()
                }
                StepProgress { id: progressStep; flow: flow }
                StepGifter { id: gifterStep; flow: flow }
            }
        }

        // Steps 0/1 only: the progress step (2) runs unattended to
        // completion and needs no CTA — so the bindings below (which
        // still evaluate on the hidden button) stay inside [0,1].
        PrimaryButton {
            Layout.fillWidth: true
            implicitHeight: M.sc(44)
            visible: view.currentStep < 2
            text: view.currentStep < 2 ? view.ctaLabels[view.currentStep] : ""
            enabled: view.currentStep < 2 && view.stepItem(view.currentStep).ready
            onClicked: view.onNextClicked()
        }

        // Back only makes sense before the checklist starts working.
        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 1
            text: "Back"
            onClicked: view.goBack()
        }

        // Advanced is reachable only at safe moments: the Welcome
        // screen (before anything starts) and — via its own link — the
        // status card. Never from the password screen or the progress
        // checklist, where jumping to Advanced could interfere with
        // in-progress wallet/sync/claim/register work. restart() ("New
        // membership" from the card) resets currentStep to 0, so this
        // covers re-entry too.
        // The alternative path: register via a gifter node + Keycard instead of
        // a funded wallet. Sets the mode, then advances the same way Get started
        // does (through the password/keystore step, which the gifter path still
        // needs to persist the grant) — landing on StepGifter at the work step.
        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 0 && welcomeStep.ready
            text: "Register with a Keycard gift"
            onClicked: {
                flow.registrationMode = "gifter"
                view.advance()
            }
        }

        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 0
            text: "Advanced setup"
            onClicked: view.advancedRequested()
        }
    }
}
