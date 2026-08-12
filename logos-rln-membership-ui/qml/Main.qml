// RLN Membership GUI (ui_qml module): an onboarding wizard by default, a
// membership status card once one exists, and a three-tab expert UI under
// "Advanced". Backend access goes through the host-injected `logos` bridge;
// Logos.Theme + Logos.Controls come from the host (basecamp / logos-standalone-app).
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Rectangle {
    id: root
    // Defaults for a bare/standalone preview; a host pane sets its own size.
    // Each mode's column scrolls rather than clips when the pane is smaller.
    width: M.sc(500)
    height: M.sc(440)
    color: Theme.palette.background

    // Test-only: tests/flow-tests.mjs injects a mock bridge here via the
    // inspector; null in production. The whole tree draws its bridge from the
    // one binding below, so an override re-threads everywhere.
    property var bridgeOverride: null

    // Injected by the host; null under a bare qml preview so the views
    // degrade to readable errors instead of reference crashes.
    readonly property var bridge: bridgeOverride !== null ? bridgeOverride
                                : (typeof logos !== "undefined") ? logos : null

    // The registry is not a wizard concern: it lives here, starts at the
    // deployed testnet, and only Advanced can edit it.
    property string registryId: M.TESTNET_REGISTRY_ID

    property string mode: "probe"

    // Leaving the list clears the one-shot celebration: "You're in!" shows
    // only for the completion event that set it, never on a return visit.
    onModeChanged: if (mode !== "status") membershipView.celebrate = false

    // Mode in effect when Advanced was entered; the exit re-probe restores it
    // on a transient error. Empty = no prior mode.
    property string preAdvancedMode: ""

    // Startup routing via local-only get_memberships (works unlocked and
    // providerless; 8s per-attempt timeout, transient errors retried): a
    // usable row -> status; rows but none usable -> onboarding with a notice.
    function probe() {
        mode = "probe"
        onboardingView.flowController.callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            if (r.error) {
                // An erroring exit-from-Advanced re-probe restores the prior
                // mode rather than bouncing a valid member into onboarding.
                if (root.preAdvancedMode !== "") {
                    root.mode = root.preAdvancedMode
                    root.preAdvancedMode = ""
                    return
                }
                onboardingView.priorNotice = ""
                onboardingView.hasExistingAccount = false
                onboardingView.startAutoUnlock()
                root.mode = "onboarding"
                return
            }
            root.preAdvancedMode = ""
            var rows = r.memberships || []
            // Existing local records: the wizard frames the password step as
            // entry, not creation.
            onboardingView.hasExistingAccount = rows.length > 0
            var usable = false
            for (var i = 0; i < rows.length; i++)
                usable = usable || M.isUsableState(rows[i].state)
            if (usable) {
                root.mode = "status"
            } else {
                onboardingView.priorNotice = rows.length === 0 ? ""
                    : "Your previous membership is no longer active — let's set up a new one."
                onboardingView.startAutoUnlock()
                root.mode = "onboarding"
            }
        }, 8000)
    }

    function enterAdvanced() {
        preAdvancedMode = mode
        mode = "advanced"
    }

    property string detailCommitment: ""
    property string detailReturnMode: "status"

    function showDetail(commitment) {
        detailCommitment = commitment
        detailReturnMode = mode
        mode = "detail"
    }

    function startNewMembership() {
        onboardingView.restart()
        mode = "onboarding"
    }

    // Land on the refreshed membership list; markCompletion() celebrates only
    // a first membership (count 0->1).
    function onboardingCompleted() {
        membershipView.markCompletion()
        mode = "status"
    }

    Component.onCompleted: probe()

    // All modes stay instantiated: wizard state (mnemonic, phase progress)
    // must survive an Advanced/detail excursion and back.
    StackLayout {
        anchors.fill: parent
        currentIndex: root.mode === "onboarding" ? 1
                    : root.mode === "status" ? 2
                    : root.mode === "advanced" ? 3
                    : root.mode === "detail" ? 4
                    : 0

        Item {
            LogosSpinner {
                anchors.centerIn: parent
                implicitWidth: M.sc(36)
                implicitHeight: M.sc(36)
            }
        }

        OnboardingView {
            id: onboardingView
            bridge: root.bridge
            registryId: root.registryId
            onCompleted: root.onboardingCompleted()
            onAdvancedRequested: root.enterAdvanced()
        }

        MembershipView {
            id: membershipView
            bridge: root.bridge
            registryId: root.registryId
            flow: onboardingView.flowController
            onDetailRequested: function (commitment) { root.showDetail(commitment) }
            onNewMembershipRequested: root.startNewMembership()
            onAdvancedRequested: root.enterAdvanced()
        }

        AdvancedView {
            id: advancedView
            bridge: root.bridge
            registryId: root.registryId
            // Adopt an edited registry only when it parses as a valid CAIP-10;
            // a cleared or garbled field keeps the last-good value.
            onRegistryEdited: function (registryId) {
                if (M.registryConfigHex(registryId) !== "")
                    root.registryId = registryId
            }
            // State may have changed in Advanced (registrations, registry
            // edits) — route by reality, not by where the user came from.
            onExitRequested: root.probe()
        }

        MembershipCard {
            id: detailCard
            bridge: root.bridge
            registryId: root.registryId
            flow: onboardingView.flowController
            commitment: root.detailCommitment
            onBackRequested: root.mode = root.detailReturnMode
            onNewMembershipRequested: root.startNewMembership()
            onAdvancedRequested: root.enterAdvanced()
        }
    }
}
