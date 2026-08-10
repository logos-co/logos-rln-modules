# logos-rln-membership-ui (measured pre-0780862, 2026-07)

- Every module call must go through `call()` in `qml/membership.js` — never
  `bridge.callModuleAsync` directly. `call()` applies the `| 0` coercion
  that keeps JS numbers int32-tagged; without it they cross the bridge as
  QVariant(double) and the Rust modules' generated dispatch (`as_i64()`,
  None on a float) turns the argument into a silent 0 — a zero-token claim,
  a zero rate_limit. The full mechanism is documented at the coercion site
  in membership.js.
