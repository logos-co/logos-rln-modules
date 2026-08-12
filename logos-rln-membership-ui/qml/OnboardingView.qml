// Onboarding shell: one centered column, dot progress, step bodies in a
// StackLayout (not a StackView — steps must retain state on Back), a single
// full-width primary CTA, and Back / Advanced-setup as quiet text links.
// Steps carry the user-facing copy; the flow controller keeps only technical
// diagnostics, which the steps demote to fine print.
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
    // Read-only handle to the flow controller for the mock-bridge test
    // harness; prod-inert.
    readonly property alias flowController: flow

    signal completed()
    signal advancedRequested()

    property int currentStep: 0
    readonly property var ctaLabels: ["Get started", "Continue"]

    // Keychain auto-unlock skips the password screen (physical slot 1):
    // Welcome jumps straight to the progress step. StepPassword stays
    // instantiated — the hermetic test asserts its title — just unreachable.
    readonly property bool passwordSkipped: flow.autoUnlockPhase === "done"

    // Null-safe sentinel for an out-of-range step index.
    readonly property var nullStep: ({ ready: false, entered: function () {} })

    function stepItem(i) {
        var items = [welcomeStep, passwordStep, workStep]
        return (i >= 0 && i < items.length) ? items[i] : nullStep
    }

    function advance() {
        currentStep = (currentStep === 0 && passwordSkipped) ? 2 : currentStep + 1
        flow.started = currentStep > 0
        stepItem(currentStep).entered()
    }

    // Re-run for a new membership. Returns to Welcome (clearing the started
    // fence) BEFORE re-firing auto-unlock — StepWelcome.ready needs
    // autoUnlock settled, and a status-first launch never ran it. When the
    // account is already unlocked, jumps straight to the progress step.
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

    // On the password step the CTA gates rather than moves: it fires the
    // keystore check and advances only when unlock reports done (the
    // Connections below).
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
        // Registration done → hand off to the membership list (Main routes
        // to status).
        function onRegPhaseChanged() {
            if (flow.regPhase === "done" && view.currentStep === 2)
                flow.finish()
        }
    }

    CenteredScrollColumn {
        anchors.fill: parent
        spacing: M.sc(Theme.spacing.xlarge)

        // Progress dots. One fewer when the password screen is skipped;
        // visualStep maps the physical slot onto the dot index so the
        // current dot is right in both layouts.
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
            // The work step swaps on registrationMode; entered() dispatches
            // to whichever body shows. ready is unused — step 2 hides the
            // shared CTA.
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

        // Steps 0/1 only; bindings still evaluate while hidden, so they
        // guard on currentStep < 2.
        PrimaryButton {
            Layout.fillWidth: true
            implicitHeight: M.sc(44)
            visible: view.currentStep < 2
            text: view.currentStep < 2 ? view.ctaLabels[view.currentStep] : ""
            enabled: view.currentStep < 2 && view.stepItem(view.currentStep).ready
            onClicked: view.onNextClicked()
        }

        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 1
            text: "Back"
            onClicked: view.goBack()
        }

        // Alternative path: register via a gifter node + Keycard. Sets the
        // mode, then advances through the password step (which the gifter
        // path still needs to persist the grant) to StepGifter.
        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 0 && welcomeStep.ready
            text: "Register with a Keycard gift"
            onClicked: {
                flow.registrationMode = "gifter"
                view.advance()
            }
        }

        // Reachable only from Welcome: jumping to Advanced mid-flow could
        // interfere with in-progress wallet/sync/claim/register work.
        LinkText {
            Layout.alignment: Qt.AlignHCenter
            visible: view.currentStep === 0
            text: "Advanced setup"
            onClicked: view.advancedRequested()
        }
    }
}
