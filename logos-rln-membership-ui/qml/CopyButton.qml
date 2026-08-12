// Copies `payload` via a hidden TextEdit's copy() — the QML sandbox's only
// clipboard path without C++. LogosButton exposes no font hook, so its caption
// is suppressed and a scaled overlay label (click-transparent Text) drawn on top.
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
