# logos-rln-membership-ui (measured pre-0780862, 2026-07)

- Every module call must go through `call()` in `qml/membership.js` — never
  `bridge.callModuleAsync` directly. `call()` applies the `| 0` coercion
  that keeps JS numbers int32-tagged; without it they cross the bridge as
  QVariant(double) and the Rust modules' generated dispatch (`as_i64()`,
  None on a float) turns the argument into a silent 0 — a zero-token claim,
  a zero rate_limit. The full mechanism is documented at the coercion site
  in membership.js.
- The membership module's method is `register_membership` (wire 0.7.0 —
  the spec's `register` is a C/C++ keyword generated clients cannot carry);
  there is no `register` alias on the module. Every `register_membership`
  call site must build its options_json through `registryOptions()` in
  `qml/membership.js` — the module wire takes the RegistryOptions array of
  `{key,value}` string pairs, and a hand-built flat object (the pre-0.6.0
  shape) is rejected as invalid_argument. Two call sites exist by design
  (wizard `OnboardingFlow.submitRegistration`/`registerDelegated`, expert
  `RegisterView.doRegister`) — change them in pairs.
- Retry decisions switch on the error envelope's `class` (`transient` →
  `M.isTransientError`), never on `kind` alone; pass the whole error
  object, not `err.kind`. New membership states go into
  `M.MEMBERSHIP_STATES` (+ `StateBadge.qml`'s colour ladder); any string
  outside the list must still render, never crash the card.
