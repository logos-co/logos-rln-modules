// The simple-view row element: one full-width, low-height rounded rectangle —
// IDENTICAL footprint (height, width, radiusLarge) across all three kinds so
// rows never shift between states:
//   "progress"   — ONE bar the size of the pill: three Syncing→Claiming→
//                  Registering rounded segments (no outer container) fill it —
//                  sync uses the real chunk fraction, claim/register sweep,
//                  upcoming is a faint accent track, completed settles to the
//                  deep accent. The stage label is a caption ABOVE the bar
//                  (StepProgress), not inside a segment; on a failed segment
//                  the bar becomes a clean tinted row with the plain-language
//                  line + an inline Retry (all within the fixed row height;
//                  auto-retry runs underneath).
//   "membership" — a pill: petname (left) + rate "N msg/epoch" (right) + a
//                  subtle state badge for non-active states; clickable →
//                  membership detail.
//   "ghost"      — a dashed "+ New Membership" wireframe → start a new one.
// The progress kind is a pure view over OnboardingFlow's phase properties.
//
// Segmented bar: every segment shares height / corner-radius / gap and differs
// only by state, in ONE accent hue expressed via lightness — faint idle track
// → LINEAR sync fill (real chunk fraction) → feathered ease-in-out shimmer for
// claim/register → deep settled completion (a soft colour settle + pop, never a
// snap).
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: root

    property string rowKind: "membership"

    // rowKind === "progress": the OnboardingFlow controller.
    property OnboardingFlow flow: null

    // rowKind === "membership": the display fields.
    property string commitment: ""
    property string membershipState: "active"
    property var rateLimit: undefined

    signal clicked()
    signal retryRequested()   // progress: the failed segment's Retry

    implicitHeight: M.sc(48)
    Layout.fillWidth: true

    // ---- shared tempo + segment geometry (progress) ------------------------
    // ONE base duration drives every loop so the shimmers pulse in sympathy;
    // the determinate sync fill and the completion settle are derived from it.
    readonly property int baseDur: 1200
    readonly property int fillDur: Math.round(baseDur / 3)    // 400 — LINEAR determinate fill
    readonly property int settleDur: Math.round(baseDur / 6)  // 200 — loading→complete transition
    readonly property int segGap: M.sc(6)
    readonly property int segRadius: M.sc(4)
    // Completion is a DEEPER, settled version of the ONE accent hue — not a
    // second colour — so the finished bar reads as one calm family.
    readonly property color doneColor: Qt.darker(Theme.palette.primary, 1.4)

    // ---- segment state helpers (progress) ----------------------------------
    // Segment 1 folds wallet provision/open/create into "syncing".
    function syncState() {
        if (!flow) return "upcoming"
        if (flow.walletPhase === "error" || flow.syncPhase === "error") return "error"
        if (flow.syncPhase === "done") return "done"
        if (flow.walletPhase === "idle") return "upcoming"
        return "active"
    }
    function fundState() {
        if (!flow) return "upcoming"
        return flow.fundPhase === "error" ? "error"
             : flow.fundPhase === "done" ? "done"
             : flow.fundPhase === "running" ? "active" : "upcoming"
    }
    function regState() {
        if (!flow) return "upcoming"
        return flow.regPhase === "error" ? "error"
             : flow.regPhase === "done" ? "done"
             : flow.regPhase === "running" ? "active" : "upcoming"
    }
    // The label + retry for the current (active or errored) stage. shortErr
    // is the CONCISE error headline shown in the clean error row (no
    // ellipsis, always fits); the technical reason is fine print in
    // StepProgress below the row.
    readonly property var activeSeg: {
        var segs = [
            { st: syncState(), active: "Syncing with Logos Blockchain...", done: "Synced!",
              shortErr: "Setup failed", retry: "Retry" },
            { st: fundState(), active: "Claiming faucet tokens...", done: "Tokens Received!",
              shortErr: "Couldn't get tokens", retry: "Retry" },
            { st: regState(), active: "Registering membership...", done: "Registered!",
              shortErr: "Registration failed", retry: "Try again" }
        ]
        for (var i = 0; i < segs.length; i++)
            if (segs[i].st === "error" || segs[i].st === "active") return segs[i]
        // all done (or none started): show the last done label.
        for (var j = segs.length - 1; j >= 0; j--)
            if (segs[j].st === "done") return segs[j]
        return segs[0]
    }

    // The current stage's caption. StepProgress shows this ABOVE the bar (on a
    // stable background) so the segments stay label-free and the shimmer reads
    // cleanly.
    readonly property string stageLabel: activeSeg.st === "done" ? activeSeg.done : activeSeg.active

    // How full a segment renders: done/error = full, upcoming = empty, and
    // the ACTIVE segment fills proportionally — sync by the real chunk
    // fraction (advances with lastSynced), claim/register full (the shimmer
    // conveys indeterminate work). idx 0 = sync.
    function segFill(idx, s) {
        if (s === "done" || s === "error") return 1.0
        if (s !== "active") return 0.0
        if (idx === 0 && flow && flow.syncTarget > flow.syncStart)
            return Math.max(0.04, Math.min(1.0,
                (flow.lastSynced - flow.syncStart) / (flow.syncTarget - flow.syncStart)))
        return 1.0
    }

    // ---- progress (in-progress): pill-height row of segments ---------------
    // No outer container — the rounded segments are the ONLY elements, so
    // nothing nests non-concentrically. The stage caption lives ABOVE the bar
    // (StepProgress); here the segments are pure visual state indicators.
    Item {
        anchors.fill: parent
        visible: root.rowKind === "progress" && root.activeSeg.st !== "error"

        Row {
            anchors.fill: parent
            spacing: root.segGap

            Repeater {
                model: root.rowKind === "progress"
                       ? [root.syncState(), root.fundState(), root.regState()] : []

                Item {
                    id: seg
                    required property int index
                    required property string modelData
                    width: (parent.width - 2 * root.segGap) / 3
                    height: parent.height

                    readonly property bool segDone: modelData === "done"
                    readonly property bool segFilling: modelData === "active" && index === 0
                    readonly property bool segLoading: modelData === "active" && index > 0

                    // A completed step pops once as it lands — punctuation for
                    // the colour settle, never a snap.
                    onModelDataChanged: if (modelData === "done") pop.restart()

                    // Idle track: a FAINT accent tint (not near-black) so the
                    // full track previews the shape of the journey.
                    Rectangle {
                        anchors.fill: parent
                        radius: root.segRadius
                        color: Theme.colors.getColor(Theme.palette.primary, 0.18)
                    }

                    // Determinate / settled fill. Sync grows LINEARLY from the
                    // real fraction; claim/register hold a translucent base
                    // swept by the shimmer; done settles to the deep accent.
                    // Focus is carried by the fill/shimmer motion — no hard
                    // ring (which read as accidental on the middle segment).
                    Rectangle {
                        id: fill
                        height: parent.height
                        width: parent.width * root.segFill(seg.index, seg.modelData)
                        radius: root.segRadius
                        clip: true
                        transformOrigin: Item.Center
                        color: seg.segDone ? root.doneColor : Theme.palette.primary
                        opacity: seg.segLoading ? 0.35 : 1.0

                        Behavior on width { NumberAnimation { duration: root.fillDur; easing.type: Easing.Linear } }
                        Behavior on color { ColorAnimation { duration: root.settleDur } }
                        Behavior on opacity { NumberAnimation { duration: root.settleDur; easing.type: Easing.InOutQuad } }

                        // Indeterminate shimmer: a WIDE, feathered highlight
                        // (transparent→peak→transparent, same hue) sweeps
                        // across on the shared base tempo — light passing over
                        // a surface, no hard band edges. Clipped to the fill.
                        Rectangle {
                            id: shimmer
                            visible: seg.segLoading
                            height: parent.height
                            width: parent.width * 0.9
                            x: -width
                            gradient: Gradient {
                                orientation: Gradient.Horizontal
                                GradientStop { position: 0.0; color: Theme.colors.getColor(Theme.palette.primaryHover, 0.0) }
                                GradientStop { position: 0.5; color: Theme.colors.getColor(Theme.palette.primaryHover, 0.5) }
                                GradientStop { position: 1.0; color: Theme.colors.getColor(Theme.palette.primaryHover, 0.0) }
                            }
                            SequentialAnimation on x {
                                running: seg.segLoading
                                loops: Animation.Infinite
                                NumberAnimation {
                                    from: -shimmer.width
                                    to: seg.width
                                    duration: root.baseDur
                                    easing.type: Easing.InOutSine
                                }
                            }
                        }

                        // The completion pop (see onModelDataChanged).
                        SequentialAnimation {
                            id: pop
                            NumberAnimation { target: fill; property: "scale"; from: 1.0; to: 1.03; duration: Math.round(root.settleDur / 2); easing.type: Easing.OutQuad }
                            NumberAnimation { target: fill; property: "scale"; to: 1.0; duration: Math.round(root.settleDur / 2); easing.type: Easing.InQuad }
                        }
                    }
                }
            }
        }
    }

    // ---- progress (error): a clean error-tinted row at the same footprint --
    // No segment fills here — the concise headline sits on a clean tinted
    // background (never on top of a green/red fill) with a compact Retry; the
    // technical reason stays as fine print below the row (StepProgress).
    Rectangle {
        anchors.fill: parent
        visible: root.rowKind === "progress" && root.activeSeg.st === "error"
        radius: M.sc(Theme.spacing.radiusLarge)
        color: Theme.colors.getColor(Theme.palette.error, 0.15)
        border.width: M.sc(1)
        border.color: Theme.palette.error

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: M.sc(Theme.spacing.medium)
            anchors.rightMargin: M.sc(Theme.spacing.small)
            spacing: M.sc(Theme.spacing.small)

            LogosText {
                Layout.fillWidth: true
                text: root.activeSeg.shortErr
                color: Theme.palette.text
                font.pixelSize: M.sc(Theme.typography.primaryText)
                font.weight: Theme.typography.weightMedium
            }
            // The design-system LogosButton has no label-size hook, so the
            // internal caption is suppressed and a scaled overlay label drawn
            // over it (a plain Text passes clicks through to the button).
            LogosButton {
                implicitHeight: M.sc(30)
                implicitWidth: M.sc(104)
                text: ""
                onClicked: root.retryRequested()
                LogosText {
                    anchors.centerIn: parent
                    text: root.activeSeg.retry
                    font.pixelSize: M.sc(Theme.typography.secondaryText)
                    font.weight: Theme.typography.weightMedium
                    color: Theme.palette.text
                }
            }
        }
    }

    // ---- membership: pill --------------------------------------------------
    Rectangle {
        anchors.fill: parent
        visible: root.rowKind === "membership"
        radius: M.sc(Theme.spacing.radiusLarge)
        color: pillMouse.containsMouse ? Theme.palette.backgroundElevated : Theme.palette.surfaceRaised
        border.width: M.sc(1)
        border.color: Theme.palette.borderSubtle

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: M.sc(Theme.spacing.medium)
            anchors.rightMargin: M.sc(Theme.spacing.medium)
            spacing: M.sc(Theme.spacing.small)

            LogosText {
                text: M.petname(root.commitment)
                font.pixelSize: M.sc(Theme.typography.primaryText)
                font.weight: Theme.typography.weightMedium
                elide: Text.ElideRight
            }
            StateBadge {
                visible: root.membershipState !== "active"
                membershipState: root.membershipState
                implicitHeight: M.sc(26)
                implicitWidth: M.sc(92)
            }
            Item { Layout.fillWidth: true }
            LogosText {
                text: M.rateText(root.rateLimit)
                color: Theme.palette.textSecondary
                font.pixelSize: M.sc(Theme.typography.secondaryText)
            }
        }

        MouseArea {
            id: pillMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.clicked()
        }
    }

    // ---- ghost: + New Membership -------------------------------------------
    // The MouseArea IS the section container (children are non-interactive),
    // so a click anywhere on the ghost reliably fires.
    MouseArea {
        id: ghostMouse
        anchors.fill: parent
        visible: root.rowKind === "ghost"
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()

        Canvas {
            id: dash
            anchors.fill: parent
            onPaint: {
                var ctx = getContext("2d")
                ctx.reset()
                ctx.strokeStyle = ghostMouse.containsMouse
                    ? Theme.palette.textSecondary : Theme.palette.borderSubtle
                var lw = M.sc(1)
                ctx.lineWidth = lw
                ctx.setLineDash([M.sc(5), M.sc(4)])
                var r = M.sc(Theme.spacing.radiusLarge)
                ctx.beginPath()
                ctx.roundedRect(lw / 2, lw / 2, width - lw, height - lw, r, r)
                ctx.stroke()
            }
            Connections {
                target: ghostMouse
                function onContainsMouseChanged() { dash.requestPaint() }
            }
        }
        LogosText {
            anchors.centerIn: parent
            text: "+ New Membership"
            color: ghostMouse.containsMouse ? Theme.palette.textSecondary : Theme.palette.textMuted
            font.pixelSize: M.sc(Theme.typography.secondaryText)
        }
    }
}
