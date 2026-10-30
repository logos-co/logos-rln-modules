# logos-rln-membership-ui (measured pre-0780862, 2026-07; wire rln 0.15.0 / lez 7.0.0 since 0.9.0)

- Every module call must go through `call()` in `qml/membership.js` — never
  `bridge.callModuleAsync` directly. `call()` applies the `| 0` coercion
  that keeps JS numbers int32-tagged; without it they cross the bridge as
  QVariant(double) and the Rust modules' generated dispatch (`as_i64()`,
  None on a float) turns the argument into a silent 0 — a zero rate_limit.
  The full mechanism is documented at the coercion site in membership.js.
  (The one exception, `OnboardingFlow.libp2pCall`, carries only strings.)
- The membership module's methods are `register_membership` (the spec's
  `register` is a C/C++ keyword generated clients cannot carry; there is no
  `register` alias) and, for the funded path, `ensure_membership` (registry-
  wide; its options accept ONLY `rate_limit`). Every `register_membership`
  call site must build its options_json through `registryOptions()` /
  `delegatedOptions()` in `qml/membership.js` — the module wire takes the
  RegistryOptions array of `{key,value}` string pairs, and a hand-built flat
  object is rejected as invalid_argument. Two call sites exist by design
  (wizard `OnboardingFlow.registerDelegated`, expert `RegisterView.doRegister`)
  and share `delegatedOptions`.
- The wire has NO faucet and NO token since lez module 4.0.0, and the UI never
  calls `lez_core`: since lez module 7.0.0 the registry module opens and
  drives the `lez_core` wallet itself (3.0.0-6.x bundled their own). It pays
  from `wallet_status().payer`, and
  the module's provisioning pass (the `provisioning` object on
  `ensure_membership` / `get_membership_state`) says how much to send where.
  Render the funding block from its structured fields (`payer`, `required`,
  `price`, `fee_reserve`, `balance`), never by parsing `detail`.
- Retry decisions switch on the error envelope's `class` (`transient` →
  `M.isTransientError`), never on `kind` alone; pass the whole error
  object, not `err.kind`. A membership's leaf renders through `M.fmtLeaf`
  only: since rln 0.15.0 a live membership may carry `leaf_pending:true`
  with a placeholder `leaf_index` of 0 (the registry module did not report
  one: it knows the leaf only of a registration it sent),
  and 0 is also a real leaf. New membership states go into
  `M.MEMBERSHIP_STATES` (+ `StateBadge.qml`'s colour ladder); any string
  outside the list must still render, never crash the card.
- The allocator step is the reference client configuration for membership
  allocation: new auth vectors are one more `M.AUTH_VECTORS` row (`id` =
  the gifter's `auth_type` verbatim, `provider` = the producer module,
  `gate` = what the UI waits for). No default allocator peer id — the peer
  id is the trust anchor and must come from the operator.
- The mock in `tests/flow-tests.mjs` is the wire's regression net: methods
  the wire dropped answer an error there, so keep its `DEAD_METHODS` list
  current when the lidls change, and keep `resetExpr` in step with the
  flow's properties (it must also clear `membershipView.rows`: the
  celebration rule compares against the count the list last showed).
- Two harness traps that cost a day. (1) `nix build .#integration-test`
  waits a FIXED 15 s for the app's inspector; on a loaded host the
  standalone app boots in ~8 s and the first bridge request (no backend)
  then blocks the event loop for its 8 s timeout, so the hermetic target
  fails before any test runs — the untouched 0.7.4 tree fails identically.
  Run the suites against a manually launched app instead: build
  `path:.#default` and `path:.#test-framework -o result-mcp`, start
  `logos-standalone-app -p <module>/lib -platform offscreen` (or
  `nix run 'path:.' -- -platform offscreen`, which survives a nix GC of the
  app's store path) with `QML_INSPECTOR_PORT` set, wait for the port, then
  `QML_INSPECTOR_PORT=… LOGOS_QT_MCP=./result-mcp node tests/<file>.mjs`
  (the framework attaches to a running app when not given `--ci`). Never
  fire a second bridge request at startup: `detectNetwork()` runs only
  after a successful probe for this reason. (2) A `StackLayout` sizes
  itself to its TALLEST child, hidden ones included, and overrides an
  `implicitHeight` binding; `OnboardingView` pins both step stacks through
  `Layout.preferredHeight/minimumHeight/maximumHeight` to the shown step,
  or the CTA lands below the 768 px test viewport and synthesized clicks
  miss it.
