// Shared onboarding/status/detail scaffold: a LogosScrollView whose content is
// a horizontally-centered, max-width ColumnLayout — centered when it fits the
// viewport, scrollable (never clipped) when it doesn't, and only ever scrolling
// vertically. Consumers' children fill the column (default `content`); `spacing`
// sets the column gap (the one per-view variant). Wraps LogosScrollView in an
// Item because ScrollView's default property and `spacing` are FINAL.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: root

    default property alias content: col.data
    property alias spacing: col.spacing

    LogosScrollView {
        anchors.fill: parent

        Item {
            id: sizer
            // Sized from the STABLE outer root (never the ScrollView's own
            // height, which would feed its contentHeight and loop): as tall as
            // the viewport when the column fits, taller (scrollable) when not.
            // Width is pinned to the viewport so only the vertical axis scrolls.
            width: root.width
            implicitHeight: Math.max(root.height,
                                     col.implicitHeight + 2 * M.sc(Theme.spacing.xxlarge))

            ColumnLayout {
                id: col
                anchors.centerIn: parent
                width: Math.min(sizer.width - 2 * M.sc(Theme.spacing.xxlarge), M.sc(420))
            }
        }
    }
}
