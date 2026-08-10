// Membership lifecycle state as a LogosBadge with a per-state status color
// (every state the merged-state view can report: pending/failed/active/
// grace_period/expired/erased/unknown — easy to hit on this testnet, where
// memberships stay active only ~43 min).
import QtQuick
import Logos.Theme
import Logos.Controls

LogosBadge {
    // Named membershipState (not `state`) to avoid shadowing Item.state.
    property string membershipState: "unknown"

    text: membershipState
    color: membershipState === "active"       ? Theme.palette.success
         : membershipState === "pending"      ? Theme.palette.info
         : membershipState === "grace_period" ? Theme.palette.warning
         : membershipState === "expired"      ? Theme.palette.textTertiary
         : membershipState === "failed"       ? Theme.palette.error
         : membershipState === "erased"       ? Theme.palette.error
         : Theme.palette.textSecondary
}
