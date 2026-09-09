// Membership lifecycle state as a LogosBadge with a per-state status color,
// covering the full MembershipStatus vocabulary (M.MEMBERSHIP_STATES):
// pending/failed/active/grace_period/expired/erased_awaits_withdrawal/
// erased/slashed/unknown. Anything else (a state a later wire adds) falls
// through to the neutral color — the text still renders verbatim.
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
         : membershipState === "erased_awaits_withdrawal" ? Theme.palette.warning
         : membershipState === "slashed"      ? Theme.palette.error
         : Theme.palette.textSecondary
}
