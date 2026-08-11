// Clipboard without C++: the QML sandbox's only sanctioned copy path is a
// TextEdit's copy(), so an invisible one holds the payload. The label flips
// Copy -> Copied for a moment as feedback. LogosButton exposes no font hook,
// so its internal caption is suppressed and a scaled overlay label drawn over
// it (a plain Text passes clicks through to the button) to match the 2x scale.
import QtQuick
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosButton {
    id: root

    property string payload: ""

    implicitWidth: M.sc(84)
    implicitHeight: M.sc(30)
    text: ""
    enabled: payload !== ""
    onClicked: {
        scratch.text = payload
        scratch.selectAll()
        scratch.copy()
        resetTimer.restart()
    }

    LogosText {
        anchors.centerIn: parent
        text: resetTimer.running ? "Copied" : "Copy"
        font.pixelSize: M.sc(Theme.typography.secondaryText)
        font.weight: Theme.typography.weightMedium
        color: root.enabled ? Theme.palette.text : Theme.palette.textMuted
    }

    TextEdit {
        id: scratch
        visible: false
    }

    Timer {
        id: resetTimer
        interval: 1600
    }
}
