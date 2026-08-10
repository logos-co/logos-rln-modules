// Memberships list: the module's public view (commitments only, no secrets)
// for the registry — readable without unlocking the keystore. Refreshes on
// tab activation and on demand; click a row for the full identifiers the
// table truncates.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

Item {
    id: view

    required property var bridge
    required property string registryId

    property var rows: []
    property bool loading: false
    property string error: ""
    property var selected: null

    function refresh() {
        loading = true
        error = ""
        M.call(bridge, M.RLN_MODULE, "get_memberships", [registryId], function (r) {
            view.loading = false
            if (r.error) {
                view.error = M.errorText(r.error)
                view.rows = []
                view.selected = null
                return
            }
            // Precompute display strings: the default table cell renders
            // rowItem[role] || "" — a numeric leaf_index of 0 must not
            // disappear, so numbers become strings here.
            view.rows = (r.memberships || []).map(function (m) {
                var full = m.credential ? m.credential.identity_commitment : ""
                return {
                    commitment: M.truncateHex(full, 12, 8),
                    full_commitment: full,
                    state: m.state || "unknown",
                    rate: String(m.rate_limit),
                    leaf: String(m.leaf_index),
                    membership_hash: m.membership_hash || "",
                    failed_reason: m.failed_reason || "",
                    submitted_at: m.submitted_at || 0
                }
            })
            view.selected = null
        })
    }

    onVisibleChanged: if (visible) refresh()

    Component {
        id: stateCell
        Item {
            StateBadge {
                anchors.verticalCenter: parent.verticalCenter
                membershipState: rowItem ? String(rowItem.state || "unknown") : "unknown"
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.spacing.small

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spacing.small

            LogosButton {
                implicitWidth: 110
                implicitHeight: 36
                text: "Refresh"
                enabled: !view.loading
                onClicked: view.refresh()
            }
            LogosSpinner {
                visible: view.loading
                implicitWidth: 20
                implicitHeight: 20
                thickness: 2
                dotSize: 4
            }
            LogosText {
                text: view.rows.length + " membership" + (view.rows.length === 1 ? "" : "s")
                color: Theme.palette.textSecondary
                font.pixelSize: Theme.typography.secondaryText
            }
            Item { Layout.fillWidth: true }
        }

        LogosText {
            visible: view.error !== ""
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: view.error
            color: Theme.palette.error
            font.pixelSize: Theme.typography.secondaryText
        }

        LogosTable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: view.rows
            loading: view.loading
            emptyText: "No memberships for this registry — register one from the Register tab."
            onRowClicked: function (rowIndex, rowItem) { view.selected = view.rows[rowIndex] }
            columns: [
                LogosTableColumn {
                    title: "Commitment"
                    role: "commitment"
                    minWidth: 180
                    fillWidth: true
                },
                LogosTableColumn {
                    title: "State"
                    role: "state"
                    minWidth: 120
                    preferredWidth: 130
                    cellDelegate: stateCell
                },
                LogosTableColumn {
                    title: "Rate limit"
                    role: "rate"
                    minWidth: 80
                    alignment: Qt.AlignRight | Qt.AlignVCenter
                },
                LogosTableColumn {
                    title: "Leaf"
                    role: "leaf"
                    minWidth: 60
                    alignment: Qt.AlignRight | Qt.AlignVCenter
                }
            ]
        }

        LogosFrame {
            visible: view.selected !== null
            Layout.fillWidth: true

            ColumnLayout {
                anchors.left: parent.left
                anchors.right: parent.right
                spacing: Theme.spacing.tiny

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.typography.secondaryText
                    text: "commitment  " + (view.selected ? view.selected.full_commitment : "")
                }
                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textSecondary
                    text: "membership_hash  " + (view.selected ? view.selected.membership_hash : "")
                }
                LogosText {
                    visible: view.selected !== null && view.selected.failed_reason !== ""
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.error
                    text: "failed_reason  " + (view.selected ? view.selected.failed_reason : "")
                }
                LogosText {
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "submitted  " + (view.selected ? M.formatTimestamp(view.selected.submitted_at) : "")
                }
            }
        }
    }
}
