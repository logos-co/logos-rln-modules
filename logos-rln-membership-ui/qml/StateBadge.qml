// Membership lifecycle state as a LogosBadge with a per-state status color,
// covering every state the merged-state view can report: pending/failed/
// active/grace_period/expired/erased/unknown.
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
