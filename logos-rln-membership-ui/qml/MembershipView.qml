// The simple end-state view (Main "status" mode): the registry's memberships
// rendered as pill rows (best first) with a "+ New Membership" ghost beneath,
// each pill clickable → membership detail. This is BOTH the relaunch landing
// and the onboarding-completion landing — a finished registration hands off
// here (refreshed so the new membership joins the pills), celebrating "You're
// in!" only for the first one. get_memberships is local-only + auto-retried,
// so a transient hiccup on entry self-heals rather than blanking the list.
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: view

    required property var bridge
    required property string registryId
    // The flow controller (from Main) so this view can auto-retry reads the
    // same way the onboarding flow does.
    required property OnboardingFlow flow

    signal detailRequested(string commitment)
    signal newMembershipRequested()
    signal advancedRequested()

    property var rows: []
    property string error: ""
    // In-flight guard: one get_memberships cycle at a time, so a burst of
    // "Refresh" taps (or a tap landing on a visible-change refresh) doesn't
    // stack overlapping auto-retry chains against the flaky transport.
    property bool refreshing: false

    // One-shot celebration: the header reads "You're in!" instead of "Your
    // Memberships" for exactly the completion event where this became the
    // user's FIRST membership (count 0->1). Set by the completion refresh
    // below, cleared by Main on any navigation away, never set on a relaunch.
    // No persistence — it lives only for that one landing.
    property bool celebrate: false
    // Marks the NEXT refresh as the post-completion one, so its callback can
    // decide the one-shot celebrate from the freshly-read membership count.
    property bool completionRefresh: false

    // Called by Main on the onboarding→list handoff: the next refresh is the
    // completion one, so its result decides the one-shot celebrate.
    function markCompletion() {
        completionRefresh = true
        refresh()
    }

    function refresh() {
        if (refreshing)
            return
        refreshing = true
        // Snapshot + clear the one-shot BEFORE the async read: only this cycle
        // may celebrate, and only if it is the completion landing.
        var wasCompletion = completionRefresh
        completionRefresh = false
        flow.callRetry(M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            view.refreshing = false
            if (r.error) {
                // A transient poll hiccup (bridge/module timeout, e.g. a slow
                // on-chain read) must NOT replace the shown memberships with an
                // error — keep the last-known list and let the next tick retry.
                if (!M.isTransientError(r.error.kind)) view.error = M.errorText(r.error)
                return
            }
            view.error = ""
            var list = (r.memberships || []).map(function (m) {
                return {
                    commitment: m.credential ? m.credential.identity_commitment : "",
                    state: m.state || "unknown",
                    rate_limit: m.rate_limit
                }
            })
            list.sort(function (a, b) { return M.stateRank(a.state) - M.stateRank(b.state) })
            view.rows = list
            // Celebrate ONLY the completion that IS the first membership
            // (count 0->1). A later membership (>1) or any non-completion
            // refresh leaves the plain "Your Memberships" header.
            if (wasCompletion)
                view.celebrate = list.length === 1
        }, 8000)
    }

    onVisibleChanged: if (visible) refresh()

    CenteredScrollColumn {
        anchors.fill: parent
        spacing: M.sc(Theme.spacing.large)

        LogosText {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: M.sc(Theme.typography.titleText)
            font.weight: Theme.typography.weightBold
            text: view.celebrate ? "You're in!" : "Your Memberships"
        }

        // The pill rows, best state first.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: M.sc(Theme.spacing.small)

            Repeater {
                model: view.rows

                MembershipRow {
                    required property var modelData
                    Layout.fillWidth: true
                    rowKind: "membership"
                    commitment: modelData.commitment
                    membershipState: modelData.state
                    rateLimit: modelData.rate_limit
                    onClicked: view.detailRequested(modelData.commitment)
                }
            }

            MembershipRow {
                Layout.fillWidth: true
                rowKind: "ghost"
                onClicked: view.newMembershipRequested()
            }
        }

        LogosText {
            visible: view.error !== ""
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.error
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: view.error
        }
        LogosText {
            visible: view.rows.length === 0 && view.error === ""
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            color: Theme.palette.textSecondary
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            text: "No membership yet."
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: M.sc(Theme.spacing.xlarge)

            LinkText {
                text: "Refresh"
                onClicked: view.refresh()
            }
            LinkText {
                text: "Advanced"
                onClicked: view.advancedRequested()
            }
        }
    }
}
