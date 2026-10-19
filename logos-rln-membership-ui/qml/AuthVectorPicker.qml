// One-of picker over M.AUTH_VECTORS (the auth vectors this GUI can drive
// against an allocator): a row of buttons, the chosen one filled. Shared by
// the wizard's allocator step (scaled 2x) and the expert Register tab (1x).
// LogosButton exposes no font hook, so each caption is a scaled overlay.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

RowLayout {
    id: picker
    objectName: "authTypeSelector"

    // The chosen vector id (M.AUTH_VECTORS[*].id). Two-way: set it to
    // preselect, read it after the user picks.
    property string authType: "none"
    property bool enabled: true
    // 1 in the expert view, M.UI_SCALE in the wizard.
    property real scale: 1

    signal picked(string authType)

    function sz(x) { return Math.round(x * scale) }

    spacing: sz(Theme.spacing.small)

    Repeater {
        model: M.AUTH_VECTORS

        LogosButton {
            id: option
            required property var modelData
            readonly property bool selected: picker.authType === modelData.id
            objectName: "authType-" + modelData.id
            Layout.fillWidth: true
            implicitHeight: picker.sz(34)
            text: ""
            enabled: picker.enabled
            opacity: selected ? 1.0 : 0.6
            onClicked: {
                picker.authType = modelData.id
                picker.picked(modelData.id)
            }
            LogosText {
                anchors.centerIn: parent
                text: (option.selected ? "● " : "○ ") + option.modelData.label
                font.pixelSize: picker.sz(Theme.typography.secondaryText)
                font.weight: option.selected ? Theme.typography.weightBold : Theme.typography.weightMedium
                color: option.selected ? Theme.palette.primary : Theme.palette.text
            }
        }
    }
}
