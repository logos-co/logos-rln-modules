// Text-link affordance for tertiary navigation (Back, Advanced setup):
// design-system text with a click surface — deliberately chrome-free where
// a boxed button would compete with the single primary CTA.
import QtQuick
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosText {
    id: root

    signal clicked()

    font.pixelSize: M.sc(Theme.typography.secondaryText)
    color: Theme.palette.textMuted

    MouseArea {
        anchors.fill: parent
        anchors.margins: -M.sc(Theme.spacing.tiny)
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
