// The expert Payer tab: who pays for a funded registration and what it
// costs. Since lez module 3.0.0 the registry module owns its wallet and pays
// every registration from its own account (wallet_status().payer); since
// 4.0.0 the chain takes the native asset only and there is no faucet. So
// this tab is READ-ONLY — it shows the payer to fund out of band, its native
// balance, and the registry's price/bounds — and never moves funds.
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosScrollView {
    id: view

    required property var bridge
    required property string registryId

    property string walletState: ""
    property string walletDetail: ""
    property string network: ""
    property string payer: ""
    property string balance: ""
    property string pricePerUnit: ""
    property string minRate: ""
    property string maxRate: ""

    property bool busy: false
    property string status: ""
    property bool statusIsError: false

    function report(text, isError) {
        status = text
        statusIsError = isError === true
    }

    // wallet_status never touches the chain; get_native_balance and
    // get_registry_bounds answer "" (empty_reply) until the wallet is ready.
    function refresh() {
        busy = true
        report("", false)
        M.call(bridge, M.LEZ_RLN_MODULE, "wallet_status", [], function (r) {
            if (r.error) { view.busy = false; view.report(M.errorText(r.error), true); return }
            view.walletState = String(r.state || "")
            view.walletDetail = String(r.detail || "")
            view.network = String(r.network || "")
            view.payer = String(r.payer || "")
            if (view.payer === "") { view.busy = false; return }
            M.call(bridge, M.LEZ_RLN_MODULE, "get_native_balance", [view.payer], function (rb) {
                view.balance = rb.error ? "" : String(rb.balance !== undefined ? rb.balance : rb.value !== undefined ? rb.value : "")
                var cfg = M.registryConfigHex(view.registryId)
                if (cfg === "") { view.busy = false; return }
                M.call(bridge, M.LEZ_RLN_MODULE, "get_registry_bounds", [cfg], function (rg) {
                    view.busy = false
                    if (rg.error) return
                    view.pricePerUnit = String(rg.price_per_unit !== undefined ? rg.price_per_unit : "")
                    view.minRate = String(rg.min_rate_limit !== undefined ? rg.min_rate_limit : "")
                    view.maxRate = String(rg.max_rate_limit !== undefined ? rg.max_rate_limit : "")
                })
            })
        })
    }

    Component.onCompleted: refresh()

    ColumnLayout {
        width: view.availableWidth
        spacing: Theme.spacing.medium

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Payer"

            ColumnLayout {
                spacing: Theme.spacing.small

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "The registry module pays every funded registration from this account "
                        + "(price × rate limit + a fee reserve, in the native asset). Fund it from "
                        + "any wallet; the onboarding wizard shows the exact amount while it waits."
                }

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText { text: "Wallet"; color: Theme.palette.textSecondary }
                    LogosText {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: view.walletState === "" ? "—"
                            : view.walletState + (view.walletDetail !== "" ? " — " + view.walletDetail : "")
                        color: view.walletState === "ready" ? Theme.palette.success
                             : view.walletState === "failed" ? Theme.palette.error : Theme.palette.text
                    }
                    LogosText { text: "Network"; color: Theme.palette.textSecondary }
                    LogosText { text: view.network !== "" ? view.network : "—" }
                    LogosText { text: "Account"; color: Theme.palette.textSecondary }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.spacing.small
                        LogosText {
                            objectName: "payerAccount"
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            font.family: "monospace"
                            text: view.payer !== "" ? view.payer : "—"
                        }
                        CopyButton { payload: view.payer }
                    }
                    LogosText { text: "Native balance"; color: Theme.palette.textSecondary }
                    LogosText { text: view.balance !== "" ? view.balance : "—" }
                }

                RowLayout {
                    spacing: Theme.spacing.small
                    LogosButton {
                        implicitWidth: 110
                        implicitHeight: 40
                        text: "Refresh"
                        enabled: !view.busy
                        onClicked: view.refresh()
                    }
                    LogosSpinner {
                        visible: view.busy
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Registry price"

            ColumnLayout {
                spacing: Theme.spacing.small

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText { text: "Price per unit"; color: Theme.palette.textSecondary }
                    LogosText { text: view.pricePerUnit !== "" ? view.pricePerUnit + " native per msg/epoch" : "—" }
                    LogosText { text: "Rate limit"; color: Theme.palette.textSecondary }
                    LogosText { text: view.minRate !== "" ? view.minRate + " – " + view.maxRate + " msg/epoch" : "—" }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "A registration costs rate limit × price plus the transaction fee. "
                        + "Read from the registry's ConfigState; \"—\" until the wallet is ready."
                }
            }
        }

        LogosText {
            visible: view.status !== ""
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.pixelSize: Theme.typography.secondaryText
            color: view.statusIsError ? Theme.palette.error : Theme.palette.textSecondary
            text: view.status
        }
    }
}
