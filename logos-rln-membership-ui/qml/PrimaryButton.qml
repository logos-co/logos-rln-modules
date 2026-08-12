// The primary (accent) call-to-action. LogosButton hard-codes its label at the
// caption size with no font hook, so this self-contained button reproduces the
// primary/hover/pressed/disabled palette with an sc()-scaled label.
// API: text, enabled (inherited Item.enabled also gates the MouseArea), clicked().
import QtQuick
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: root

    property string text: ""
    property real radius: M.sc(Theme.spacing.radiusXlarge)

    signal clicked()

    implicitWidth: M.sc(200)
    implicitHeight: M.sc(50)

    Rectangle {
        anchors.fill: parent
        radius: root.radius
        color: !root.enabled ? Theme.palette.disabled
             : (mouse.pressed || mouse.containsMouse) ? Theme.palette.primaryHover
             : Theme.palette.primary
        border.width: M.sc(1)
        border.color: !root.enabled ? Theme.palette.border : Theme.palette.primaryPressed

        LogosText {
            anchors.centerIn: parent
            width: parent.width - 2 * M.sc(Theme.spacing.small)
            horizontalAlignment: Text.AlignHCenter
            elide: Text.ElideRight
            text: root.text
            font.pixelSize: M.sc(Theme.typography.secondaryText)
            font.weight: Theme.typography.weightMedium
            color: root.enabled ? Theme.palette.text : Theme.palette.textMuted
        }
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
        onClicked: root.clicked()
    }
}
