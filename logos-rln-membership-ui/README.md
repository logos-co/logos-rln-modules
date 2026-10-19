# logos-rln-membership-ui — RLN Membership GUI (ui_qml)

Basecamp GUI for the sibling [`../logos-rln-module`](../logos-rln-module):
acquire a membership on a CAIP-10 registry — funded by the registry module's
own payer, or **through a membership allocator** (the RLN Membership
Allocation Protocol, LIP-158) with a pluggable auth vector — and view
memberships. `select_membership` (the plaintext credential release) is
deliberately not exposed in a GUI.

It doubles as the reference for how an application module configures the
allocation path: the allocator step's fields map one-to-one onto the
delegated `RegistryOptions` that `liblogos_rln_module.register_membership`
takes (see "Configure an allocator" below).

## Modes

`Main.qml` routes by a startup probe (`get_memberships`, local-only, 8s
timeout, any error → onboarding so the splash never hangs):

- **Onboarding wizard** (default with no usable membership): Welcome,
  Password (the credential keystore, checked via `unlock_keystore`; skipped
  when the OS keychain auto-unlock succeeds), then one of two work steps:
  - **Funded** (`StepProgress.qml`): one `ensure_membership` call; the
    membership module runs its own provisioning pass (selects the network,
    waits for its payer to hold price + fee reserve, registers) and the UI
    polls `get_membership_state`, rendering the structured `provisioning`
    object — the step caption, and while `awaiting_funding` a "send
    `required` to `payer`" block with copy buttons — until the membership is
    active.
  - **Allocator** (`StepGifter.qml`, reached from the Welcome link): the
    user enters the allocator's peer id and multiaddr, picks the auth vector
    it accepts, and one delegated `register_membership` does the rest.
  `OnboardingFlow.qml` is the non-visual controller; step bodies live in a
  StackLayout so Back keeps state.
- **Status card** (default once a usable membership exists — pending counts):
  best row, live badge, on-chain-clock expiry context, Re-register / New
  membership / Advanced.
- **Advanced** (`AdvancedView.qml`): the three-tab expert UI (Register /
  Memberships / Payer); the registry field lives only here and propagates
  up. "Exit advanced" re-probes.

**Two call sites, one builder:** the wizard (`OnboardingFlow.registerDelegated`)
and the expert tab (`RegisterView.doRegister`) both build their options
through `membership.js` (`registryOptions` / `delegatedOptions`), so the
wire shape lives once. The remaining duplicated phases carry a
`mirrors <View>.<fn> — keep in sync` comment; change them in pairs.

## Pattern

A **QML-only `ui_qml` module**, the packaging logos-basecamp expects for
module GUIs (see basecamp's `docs/spec.md` "UI App", `src/UIPluginManager.cpp`;
reference implementation `logos-package-manager-ui`):

- `metadata.json` — `"type": "ui_qml"`, `"view": "qml/Main.qml"`; the
  `dependencies` are the backend modules basecamp auto-loads (with THEIR
  dependencies) before mounting the view. They are hard dependencies:
  basecamp shows a missing-deps popup and does not mount the view when one
  is not installed, and a sandboxed view cannot load modules itself — so the
  two producer modules are listed even though a given user needs one.
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

Modules: `liblogos_rln_module` 0.13.0 (`ensure_membership` + the
`provisioning` object; 0.12.0 lacks them), `liblogos_lez_rln_module` 5.1.0
(native asset only; the module owns its wallet and payer), `rln_gifter_module`
0.3.0, `libp2p_module`, and the producers `keycard_capture_module` 0.2.0 /
`eth_sign_module` 0.1.0 (both in `logos-rln-gifter`).

| GUI action | call |
|---|---|
| Unlock / lock keystore | `liblogos_rln_module.unlock_keystore(password)` / `lock_keystore()`; `unlock_keystore_auto()` first (OS-keychain custody), `remember_keystore_password()` after a manual unlock |
| Pick the registry | `liblogos_lez_rln_module.wallet_status().network` → `membership.js` `KNOWN_REGISTRIES` (the lez module's built-in network table); an Advanced edit pins it |
| Funded registration | `liblogos_rln_module.ensure_membership(registry_id, [{"key":"rate_limit","value":"…"}])` → a live membership's state view, or `{"state":"unknown","provisioning":{step, detail, payer, required, price, fee_reserve, balance}}`; then the confirmation poll |
| Delegated registration | `liblogos_rln_module.register_membership(registry_id, rln_identifier_hex, options_json)` with `options_json` = `M.delegatedOptions(...)`: `[{"key":"rate_limit","value":"100"} (the registry minimum: `rln_gifter_module` clamps to its `maxRateLimit`, default 100, without reporting it, and a higher ask would surface as `rate_limit_mismatch`),{"key":"delegated","value":"true"},{"key":"gifter_peer_id",…},{"key":"gifter_multiaddr",…}` + for a non-open vector `{"key":"auth_type",…},{"key":"auth_provider",…}` (+ `auth_args`)`]`; reply = the public Membership view, `state:"pending"`; the credential never leaves the module |
| libp2p node for the delegated path | `rln_gifter_module.libp2p_call({"method":"createNode","args":[…]})` then `start` — relayed because `libp2p_module`'s own replies null through the bridge |
| Vector gates | `keycard_capture_module.card_status()` polled until `present`; `eth_sign_module.address()` shown so the allocator's operator can allowlist it |
| Confirmation poll | `liblogos_rln_module.get_membership_state(registry_id, rln_identifier_hex)` every 10s (60s once events are armed, except while a provisioning pass runs) until the pending window settles — `{registry_id, state}` + `membership_hash`/`leaf_index`/`rate_limit` once known, `provisioning` while the module's pass runs |
| Memberships list | `liblogos_rln_module.get_memberships(registry_id)` (public view, works locked); a `failed` row carries `failed_reason` + `retryable` |
| Live expiry context (detail card) | `liblogos_lez_rln_module.get_membership(config_hex, commitment)` — on-chain clock vs grace-period start, never local time |
| Payer tab | `liblogos_lez_rln_module.wallet_status()`, `get_native_balance(payer)`, `get_registry_bounds(config_hex)` — read-only; there is no faucet and no token any more |

Every membership call is scoped by `(registry_id, rln_identifier_hex)`; this
GUI is a management tool, not an RLN application, so it passes the fixed
zero `M.DEFAULT_RLN_ID` as its scope identifier (`ensure_membership` is
registry-wide by definition). Failures on the `liblogos_rln_module` methods
are the in-band envelope `{"error":{"class","kind","message"}}` — `class`
(`not_ready` | `transient` | `budget_exhausted` | `permanent`) decides whether
the UI auto-retries (`M.isTransientError`), `kind` picks the hint shown
(`M.ERROR_HINTS`). Membership `state` is the LIP `MembershipStatus`
vocabulary (`M.MEMBERSHIP_STATES`: `active`, `grace_period`, `pending`,
`expired`, `erased_awaits_withdrawal`, `failed`, `erased`, `slashed`,
`unknown`); `pending`/`active`/`grace_period` count as usable (status card),
every other settled state offers Re-register, and a string outside the list
renders with the neutral badge. The wire is documented in the module's
`rust-lib/liblogos_rln_module.lidl` and `docs/wire-binding.md`.

State changes also push via the module's `membership_state_changed` event when
the host bridge supports `LogosQmlBridge.onModuleEvent`/`moduleEventReceived`;
a received event only wakes an immediate re-read through the same
`get_membership_state` call (advisory, never a data source on its own).
Polling remains the portable fallback every host can rely on.

## Configure an allocator

The allocator step is what an application's own module would do to use
membership allocation instead of the user's funds. Three things, all per
call, nothing persisted in the RLN module:

1. **Who the allocator is** — its libp2p peer id and a routable multiaddr,
   exactly what its operator published (`allocator.json` from
   `logos-rln-gifter/tools/allocator/run-allocator.sh`, or the `serve`
   output). The peer id is the trust anchor: the libp2p handshake is the only
   authentication of the allocator, so there is no default.
2. **How the allocator checks you** — the auth vector, one of
   `membership.js` `AUTH_VECTORS`:

   | vector (`auth_type`) | producer (`auth_provider`) | what the user does | what the operator configures |
   |---|---|---|---|
   | Open allocator (none) | — | nothing | `serve` without `authVerifiers` — pays for anything, test setups only |
   | Keycard (`keycard-attestation`) | `keycard_capture_module` (PC/SC, card on the reader) | taps a genuine Keycard | `authVerifiers["keycard-attestation"]` → `keycard_auth_module`, `config.trusted_cas` |
   | Ethereum key (`eth-allowlist`) | `eth_sign_module` (a key the module owns under its data dir) | hands the shown address to the operator | `authVerifiers["eth-allowlist"]` → `eth_auth_module`, `config.allowlist` |

   An app adds its own vector as one more row: a producer module its clients
   load (the `rln_auth_vector` `produce_auth` contract) and a verifier module
   the allocator loads. Optional `auth_args` (a JSON string) rides to the
   producer verbatim.
3. **The registry** — the allocator serves exactly one; the client's
   `registry_id` must name the same config account, or the registration
   sits `pending` and fails after the confirmation window.

The module mints the identity inside `register_membership` and asks the
producer for a payload bound to that commitment, which is why a pre-made
payload (`auth_payload`) cannot be used from here — see
`logos-rln-gifter/docs/running-an-allocator.md` §4–§5.

For a headless driver the controls carry object names: `flowController`
(the `OnboardingFlow` item), `allocatorPathLink`, `gifterPeerIdField`,
`gifterMultiaddrField`, `authTypeSelector` (buttons `authType-<id>`),
`authArgsField`, `registerDelegatedButton`, `ethAddressText`,
`fundingBlock` / `fundingPayer` / `fundingRequired`, `payerAccount`.

## Tests

`nix build 'path:.#integration-test'` runs both `tests/*.mjs` files:

- `ui-tests.mjs` — 5 hermetic static-chrome checks (no bridge → the
  deterministic onboarding fallback).
- `flow-tests.mjs` — deterministic state-machine scenarios driven by a
  scripted **mock bridge**. `Main.qml`'s `bridgeOverride` (null in
  production) is injected via the inspector's `evaluate` command with a JS
  object whose `callModuleAsync` replies from a fixture table matching the
  real wire shapes; `OnboardingView.flowController` exposes the flow's phase
  properties for assertions, and test-tunable poll/retry intervals let the
  timers and transient-retry backoff fire in milliseconds. Covers the funded
  golden path through the provisioning pass, the `awaiting_funding` screen,
  keychain fallback + remember, the advanced↔simple transition regressions,
  registry-edit guarding and network detection, the idempotent re-run, the
  completion→list handoff with the one-shot "You're in!" celebration, the
  LIP state vocabulary, the refused / failed / never-resolving error
  branches, the transient-transport auto-retry, and the three allocator
  vectors — asserting the exact delegated options array each one emits. The
  mock's `ensure_membership` / `register_membership` are strict (arity,
  32-byte scope id, the RegistryOptions array, delegated key consistency)
  and every method the wire dropped (`lez_core`, the faucet) answers an
  error, so a call-site regression fails loudly.

## Build & run

```sh
nix run 'path:.'                     # mount the view in logos-standalone-app
nix build 'path:.#lgx'               # the .lgx bundle basecamp installs
nix build 'path:.#integration-test'  # runs tests/*.mjs (5 hermetic + 20 flow)
```

The hermetic target waits a fixed 15 s for the app's inspector and fails on a
slow host before any test runs; `CLAUDE.md` describes running the same
suites against a manually launched app.

(`path:` because plain `.` resolves through the parent git repo and would
hide files not yet in the index.)

To load the real backend stack alongside the standalone app:

```sh
nix run 'path:.' -- --modules-dir <dir with installed modules> \
    --load liblogos_rln_module
```

(The standalone app stamps no persistence path, so `eth_sign_module`'s key —
and the RLN module's own stores — are per-run there; basecamp is the real
host.)

In basecamp: install this module's `.lgx` (plus the rln, lez-rln, libp2p,
gifter and the two producer `.lgx` bundles) through the package manager
Modules view; the "RLN Membership" entry appears in the sidebar.
