// RLN Membership GUI (ui_qml module): a guided onboarding wizard by default,
// a membership status card once one exists, and the live-proven three-tab
// expert UI demoted to an "Advanced" mode. All backend access goes through
// the host-injected `logos` bridge; Logos.Theme + Logos.Controls come from
// the host's design-system copy (basecamp / logos-standalone-app).
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Rectangle {
    id: root
    // Roomy 2x defaults for a bare/standalone preview; basecamp gives its own
    // (large) pane. Each mode's centered column lives in a LogosScrollView, so
    // if a host pane is smaller than the scaled content it scrolls instead of
    // hard-clipping.
    width: M.sc(500)
    height: M.sc(440)
    color: Theme.palette.background

    // Test-only bridge injection: null in production, so the readonly bridge
    // below resolves to the host's `logos` object exactly as before. A
    // deterministic mock-bridge test (tests/flow-tests.mjs) sets this via the
    // inspector; the whole tree draws its bridge from the one binding, so an
    // injected override reactively re-threads everywhere.
    property var bridgeOverride: null

    // Injected by the host; null under a bare qml preview so the views
    // degrade to readable errors instead of reference crashes.
    readonly property var bridge: bridgeOverride !== null ? bridgeOverride
                                : (typeof logos !== "undefined") ? logos : null

    // The registry is deliberately NOT a wizard concern: it lives here,
    // starts at the deployed testnet, and only Advanced can edit it.
    property string registryId: M.TESTNET_REGISTRY_ID

    property string mode: "probe"

    // Any navigation AWAY from the list clears the one-shot celebration, so
    // the "You're in!" header shows only for the completion event that set it
    // (a first membership) and never on a relaunch or a return to the list.
    onModeChanged: if (mode !== "status") membershipView.celebrate = false

    // The mode in effect when Advanced was entered, so the exit re-probe can
    // restore it on a transient error instead of bouncing a user with a
    // valid membership into onboarding. Empty = first launch (no prior mode).
    property string preAdvancedMode: ""

    // Startup routing: local-only get_memberships (works unlocked and
    // providerless) with an 8s per-attempt timeout so the splash can never
    // hang. Routed through the flow's callRetry so a TRANSIENT transport
    // hiccup on launch/exit self-heals instead of mis-routing (any error
    // otherwise falls through to onboarding / preAdvancedMode restore). A
    // usable row (pending counts — a mid-confirmation relaunch belongs on the
    // card) -> status; rows but none usable -> onboarding with a Welcome note.
    function probe() {
        mode = "probe"
        onboardingView.flowController.callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            if (r.error) {
                // Exit-from-Advanced on a transient error: restore where the
                // user was (a valid membership shouldn't vanish because one
                // get_memberships call hiccuped). First launch (no prior
                // mode) still defaults to onboarding.
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
            // Local records mean local state was set up before — the wizard
            // frames the password step as entry, not creation.
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

    // Enter Advanced, remembering where we came from so the exit re-probe
    // can restore it on a transient error.
    function enterAdvanced() {
        preAdvancedMode = mode
        mode = "advanced"
    }

    // The commitment shown in the detail view, and the mode to return to.
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

    // Onboarding finished a registration: land on the LIST (status mode),
    // refreshed so the just-created membership joins the pills — instead of
    // lingering on StepProgress's single morphed pill. markCompletion() lets
    // that refresh celebrate ("You're in!") ONLY when this is the user's first
    // membership (count 0->1); a later membership reads "Your Memberships".
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
            // Registration finished → hand off to the membership list.
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
            // Adopt an edited registry ONLY when it parses to a valid logos
            // CAIP-10; a cleared/garbled field keeps the last-good value so
            // it can never poison the exit re-probe or the funding step.
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
