# logos-rln-membership-ui — RLN Membership GUI (ui_qml)

Basecamp GUI for the sibling
[`../logos-rln-module`](../logos-rln-module): fund via
the wallet + faucet, register a membership, and view memberships on a CAIP-10
registry. `select_membership` (the plaintext credential release) is
deliberately not exposed in a GUI.

## Modes

`Main.qml` routes by a startup probe (`get_memberships`, local-only, 8s
timeout, any error → onboarding so the splash never hangs):

- **Onboarding wizard** (default with no usable membership): five explicit
  steps — Welcome, Password (one password for wallet storage + keystore,
  checked via `unlock_keystore` before the slow steps), Wallet setup
  (provision + open/create + sync with live progress; mnemonic shown once,
  non-blocking), Get tokens (computed faucet claim with the 180s countdown),
  Activate (register + confirmation poll). `OnboardingFlow.qml` is the
  non-visual controller; step bodies live in a StackLayout so Back keeps
  state.
- **Status card** (default once a usable membership exists — pending counts):
  best row, live badge, on-chain-clock expiry context, Re-register / New
  membership / Advanced.
- **Advanced** (`AdvancedView.qml`): the original three-tab expert UI,
  verbatim and live-proven; the registry field lives only here and
  propagates up. "Exit advanced" re-probes.

**Two implementations, keep in sync:** the wizard controller deliberately
duplicates the Advanced views' wire flows (those views stay byte-identical
because their logic is entangled with their widgets). Every duplicated phase
in `OnboardingFlow.qml` carries a `mirrors <View>.<fn> — keep in sync`
comment; change either side only in pairs. Pure formulas live once in
`membership.js`.

## Pattern

A **QML-only `ui_qml` module**, the packaging logos-basecamp expects for
module GUIs (see basecamp's `docs/spec.md` "UI App", `src/UIPluginManager.cpp`;
reference implementation `logos-package-manager-ui`):

- `metadata.json` — `"type": "ui_qml"`, `"view": "qml/Main.qml"`; the
  `dependencies` are the backend modules basecamp auto-loads (with THEIR
  dependencies) before mounting the view.
- The view runs in-process in a sandboxed `QQuickWidget` engine: network
  denied, filesystem limited to this module's directory, QML imports limited
  to Qt's modules plus the host-provided `Logos.Theme` / `Logos.Controls` /
  `Logos.Icons` (design system — **not** bundled here, by design).
- All backend access goes through the host-injected `logos` bridge
  (`LogosQmlBridge` from logos-view-module-runtime):
  `logos.callModuleAsync(module, method, [args], callback)`. Replies are the
  modules' JSON strings (double-encoded by the bridge; `qml/membership.js`
  normalizes that plus the two error shapes).

## Wire surface used

| GUI action | call |
|---|---|
| Unlock / lock keystore | `liblogos_rln_module.unlock_keystore(password)` / `lock_keystore()` |
| Register (generates the identity in-module) | `liblogos_rln_module.register(registry_id, rln_identifier_hex, rate_limit, options_json)` with `options_json = {"funding_holding_account_id": …}`; the credential never leaves the module |
| Confirmation poll | `liblogos_rln_module.get_membership_state(registry_id, rln_identifier_hex)` every 10s until the pending window settles |
| Memberships list | `liblogos_rln_module.get_memberships(registry_id)` (public view, works locked) |
| One-click wallet | `liblogos_rln_module.provision_wallet_home({"sequencer_addr":…})` → wallet-home under the module's basecamp data dir, then `open` when `storage_exists`, else `create_new` + `save` |
| Open / create wallet | `logos_execution_zone.open(config_path, storage_path)` / `create_new(config_path, storage_path, password)` + `save()` (create shows the mnemonic ONCE) |
| Sync | `get_current_block_height()` (head discovery) → `sync_to_block(head)` retried until it returns 0 **and** `get_last_synced_block()` reaches the head (progress-polled) |
| Faucet claim | `create_account_public()` → `liblogos_lez_rln_module.get_token_balance` until `exists:false` → `claim_tokens(config_hex, holding_hex, amount)` → balance-polled until the credit lands (hard timeout) |
| Claim sizing | `liblogos_lez_rln_module.get_registry_bounds(config_hex)` → suggested amount = default rate × `price_per_unit` × 1.2 (editable) |

State changes also push via the module's `membership_state_changed` event when
the host bridge supports `LogosQmlBridge.onModuleEvent`/`moduleEventReceived`
(see the module's `docs/wire-binding.md` "Events" section); a received event
only wakes an immediate re-read through the same `get_membership_state` call
above (advisory, never a data source on its own). Polling remains the
portable fallback every host can rely on — its cadence widens to 60s once
events are armed, staying at 10s otherwise.

The registry field is prefilled with the shared-faucet testnet registry
(descriptor under `../deployments/shared-faucet/`); the registry id's 64-hex
segment doubles as the config account id for faucet calls (the rln module's
`resolve_account_id` passes 64-hex through).

The Wallet tab's primary flow is one click: "Use basecamp wallet" asks the
membership module to provision `wallet-home/` under its own host-stamped
persistence dir (under basecamp: `<data-tree>/module_data/
liblogos_rln_module/wallet-home/`), because the sandboxed QML
cannot create files and the wallet module cannot provision its own config.
The returned paths feed the same open/create flow. The collapsed
"Advanced: use existing wallet files" section keeps the manual path fields
for externally staged wallets — the wallet module runs outside the QML
sandbox and reads whatever paths it is given. Stage fixtures with
`tools/deployments/stage.sh <deployment-dir> <wallet-home>` (then Open with
`<wallet-home>/wallet_config.json` + `<wallet-home>/storage.json`, copying
`storage.json.seed` → `storage.json` for the shared seed wallet).

Two silent-failure gotchas the Wallet tab designs around: an **unsynced
wallet** submits transactions that are accepted (tx hash and all) but never
apply — sync is retried until the wallet itself reports success at the
discovered head; and a **claim exceeding the faucet's remaining balance** is
likewise accepted and never funds the holding — the credit is polled with a
~3 min timeout and a clear error instead of spinning.

## Tests

`nix build 'path:.#integration-test'` runs both `tests/*.mjs` files:

- `ui-tests.mjs` — 5 hermetic static-chrome checks (no bridge → the
  deterministic onboarding fallback).
- `flow-tests.mjs` — 14 deterministic state-machine scenarios driven by a
  scripted **mock bridge**. `Main.qml`'s `bridgeOverride` (null in
  production) is injected via the inspector's `evaluate` command with a JS
  object whose `callModuleAsync` replies from a fixture table matching the
  real wire shapes; `OnboardingView.flowController` exposes the flow's phase
  properties for assertions, and test-tunable poll/retry intervals on the
  flow let the claim/register timers and transient-retry backoff fire in
  milliseconds. Covers the golden path, keychain fallback + remember, the
  advanced↔simple transition regressions, registry-edit guarding,
  new-membership sync-reset, the completion→list handoff with the one-shot
  "You're in!" celebration (first membership only; a second membership and a
  relaunch read "Your Memberships"), the sync/claim/register error branches,
  and the transient-transport auto-retry (recovery + non-transient-not-retried)
  — no daemon, no faucet spend.

For exhaustive per-branch state-machine coverage the right tool is a Qt
Quick Test (`tst_OnboardingFlow.qml`) C++ harness; it needs a new C++ test
target + CMake in this currently QML-only module and is deliberately out of
scope here (the mock-bridge harness covers the happy path + key cases).

## Build & run

```sh
nix run 'path:.'                     # mount the view in logos-standalone-app
nix build 'path:.#lgx'               # the .lgx bundle basecamp installs
nix build 'path:.#integration-test'  # runs tests/*.mjs (5 hermetic + 14 flow)
```

(`path:` because plain `.` resolves through the parent git repo and would
hide files not yet in the index.)

To load the real backend stack alongside the standalone app:

```sh
nix run 'path:.' -- --modules-dir <dir with installed modules> \
    --load liblogos_rln_module
```

In basecamp: install this module's `.lgx` (plus the wallet, rln and
membership `.lgx` bundles) through the package manager Modules view; the
"RLN Membership" entry appears in the sidebar. Full flow: Wallet tab (open or
create → sync → claim) → Register tab (unlock →
register; the funding field is pre-filled by the claim) → Memberships tab.
