// A LogosScrollView holding a horizontally-centered, max-width ColumnLayout:
// centered when the content fits the viewport, vertically scrollable when it
// doesn't. Children fill the column (default `content`); `spacing` sets the gap.
// Wrapped in an Item because ScrollView's default property and `spacing` are FINAL.
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
            // Sized from the outer root, never the ScrollView's own height
            // (that would feed its contentHeight and binding-loop). Width is
            // pinned to the viewport so only the vertical axis scrolls.
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
