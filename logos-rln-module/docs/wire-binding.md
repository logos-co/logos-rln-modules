# RLN Module — logos-core wire binding

The contract for a consumer-side shim that implements the RLN-API spec surface
(e.g. Nim procs in logos-delivery) by calling `liblogos_rln_module`
over logos-core. The layering:

```
consumer (e.g. WAKU2-RLN-RELAY relay code)
    │  spec functions: Membership register(scope, …), bool verify_proof(…), …
shim (implements the spec API in the consumer's language)
    │  logos-core wire: the methods below (string args → QString-JSON reply)
liblogos_rln_module
```

The shim is intended to be **stateless**: every piece of state the spec
functions need (epoch, allocations, root windows, credentials) lives in the
module. The one thing the shim MUST still supply is the scope — every call
passes its `(registry_id, rln_identifier_hex)` explicitly (spec: the Module
holds no default).

## Call conventions

- Every method takes positional string/int args. Replies come in two dialects,
  split by the method's declared return type:
  - **`result` methods** — the RLN-API surface (`start`, `stop`,
    `generate_proof`, `verify_proof`, `get_registry_parameters`) — return a
    real `LogosResult`. On the consumer (lp) wire that is the envelope
    `{"success": bool, "value": <reply>, "error": <string>}`; on failure
    `error` is the JSON-encoded typed object `{"class":…,"kind":…,
    "message":…}`. Parse defensively: envelopes may arrive double-encoded
    (a JSON string containing the envelope), a known SDK wire quirk. These
    methods are **not** QML-bridge-safe (`LogosResult` nulls through the UI
    bridge) — they are for module/shim consumers, and the GUI never calls
    them.
  - **`tstr` methods** — the membership-management surface — return a QString
    carrying compact JSON; failures are the in-band envelope
    `{"error": {"class":…,"kind":…,"message":…}}` (QML-bridge-safe).
- JSON replies use serde_json ⇒ **alphabetical keys** in both dialects.
- Binary values are lowercase hex, **32-byte little-endian** for field
  elements. Hex inputs tolerate a `0x` prefix.
- A `MembershipScope` is the arg pair `(registry_id, rln_identifier_hex)`:
  the CAIP-10 registry id and the application's 32-byte identifier.
  **Every call passes its scope explicitly — the Module holds no default**;
  an empty `registry_id` or `rln_identifier_hex` fails `invalid_argument`.
- `signal` (spec `Bytes`) travels as `signal_hex` — the raw bytes hex-encoded.

## Error envelope

The typed error object is identical in both dialects:

```json
{"class": "<class>", "kind": "<kind>", "message": "<detail>"}
```

For `result` methods it arrives JSON-encoded in `LogosResult.error` (with
`success: false`); for `tstr` methods it arrives in-band under a reserved
top-level `error` key. `class` is the spec's `RlnErrorKind`, carried
explicitly so the shim switches on it with no mapping table of its own:

| `class` | Spec value | Meaning | Underlying `kind`s |
|---|---|---|---|
| `not_ready` | `RLN_ERR_NOT_READY` | retry once ready | `not_ready`, `locked` |
| `transient` | `RLN_ERR_TRANSIENT` | MAY retry | `transient`, `provider_failure` |
| `budget_exhausted` | `RLN_ERR_BUDGET_EXHAUSTED` | retry next epoch | `budget_exhausted` |
| `permanent` | `RLN_ERR_PERMANENT` | retrying as-is cannot succeed | everything else |

`kind` refines the class for diagnostics; new kinds may appear over time —
switch on `class`, log `kind`.

## Methods

| Spec function | Method (args) | Dialect | Success reply (the `value` for result methods) |
|---|---|---|---|
| `start(config)` | `start(config_json)` | result | `{"started":true,"epoch_size_sec":N,"registries":[…]}` |
| `stop()` | `stop()` | result | `{"stopped":true}` |
| `register(scope, rate_limit, options)` | `register(registry_id, rln_identifier_hex, rate_limit, options_json)` | tstr | public Membership view (below), `"state":"pending"` on a fresh submit |
| `get_membership_state(scope)` | `get_membership_state(registry_id, rln_identifier_hex)` | tstr | `{"state":…}` + `membership_hash`/`leaf_index`/`rate_limit` when known |
| `generate_proof(scope, signal, timestamp)` | `generate_proof(registry_id, rln_identifier_hex, signal_hex, timestamp)` | result | RateLimitProof (below) + `"message_id"`, `"epoch"`, `"membership_hash"`; epoch derives from `timestamp` (Unix s), must be within now ± `max_epoch_gap`. Fails `permanent` (kind `permanent`) for an epoch below the membership's persisted allocation floor (backwards clock / widened `max_epoch_gap`) or an `epoch_size_sec` its allocations are not bound to — re-register to recover |
| `verify_proof(scope, signal, proof)` | `verify_proof(registry_id, rln_identifier_hex, signal_hex, proof_json)` | result | `{"verdict":str}` (see the verdict table); `rate_limit_violation` also carries `"recovered_secret":hex` |
| `get_epoch_quota(scope)` | `get_epoch_quota(registry_id, rln_identifier_hex)` | result | `{"epoch_index":N,"rate_limit":N,"remaining":N}` — one epoch observation, purely local; `epoch_index` is a NUMBER (`floor(unix/epoch_size)`, what a QuotaProvider's `epochIndex` consumes); no usable membership → `rate_limit`/`remaining` both 0 (the wall-clock-fallback cue — never an exhausted budget) |
| registry parameters read (optional ext.) | `get_registry_parameters(registry_id, rln_identifier_hex)` | result | `{"epoch_size_sec","max_rate_limit","min_rate_limit","max_total_rate_limit","price_per_unit"}` |
| select (multiple-membership ext.) | `select_membership(registry_id, rln_identifier_hex, selector_json)` | tstr | public Membership view |
| list (helper) | `get_memberships(registry_id)` | tstr | `{"memberships":[…]}` |

The public **Membership view** (spec `Membership` + status):
`{"credential":{"identity_commitment":hex},"leaf_index":N,"membership_hash":hex,
"rate_limit":N,"registry_id":caip10,"rln_identifier":hex,"state":str,…}` — no
secret ever appears. A `"failed"` state carries `"failed_reason":str` and
`"retryable":bool` (spec: a failed submission SHALL report whether it is
retryable).

**Scope semantics.** `register` is idempotent **per scope** (spec): the scope's
live membership short-circuits; a different application registering on the
same registry mints its own membership (isolated slashing blast radius).
`get_membership_state` / `generate_proof` / `get_registry_parameters` resolve
the membership *backing* the scope: records registered under the scope's
`rln_identifier` (or carrying none — pre-scope legacy records back every
application) are preferred; with no usable match, any of the registry's
memberships backs the scope, per the spec's "a membership MAY back any
application whose scope names its registry". More than one candidate is
`ambiguous_selection` — use `select_membership`.

### Time budgets

Most calls answer in milliseconds. The exceptions a shim must pass explicit
lp timeouts for (the logos-core default is ~20 s):

| Method | Budget | Why |
|---|---|---|
| `register` | 90 s | a fresh registration first does a synchronous registry-bounds pre-check (one registry read, ≤70 s worst case) before it mints, durably persists, and returns; only the on-chain submission is background. The idempotent short-circuit (a live local membership for the scope) returns in milliseconds |
| `generate_proof` | 90 s | warm: served from the background-maintained Merkle-path cache, no registry read; cold miss: one registry read (Merkle path, ≤70 s worst case) + proving (~seconds) |
| `get_registry_parameters` | 90 s | one registry read (≤70 s worst case) |
| `get_membership_state` | 90 s | one registry read |
| `get_merkle_proof` / `get_valid_roots` | 90 s | one registry read |
| `verify_proof` | 5 s | pure local computation |
| `get_epoch_quota` | 5 s | pure local state |

## Events

A third channel, pushed over the lp event stream rather than returned by any
method call — no `result`/`tstr` envelope, no class/kind, just positional
args.

| Event | Args (positional order) | Fires when |
|---|---|---|
| `membership_state_changed` | `registry_id, rln_identifier, membership_hash, state, previous` | a membership's registry-observed state actually CHANGES — `pending`→`active`, `pending`→`failed`, `active`→`grace_period`/`expired`, observed→`erased` — never for a mere re-observation of the same state |

- `rln_identifier` is the registering scope's `rln_identifier_hex`, empty for
  a pre-scope legacy record; consumers filter on `(registry_id,
  membership_hash)`.
- `previous` is the state the record held immediately before this
  transition — one of the `MembershipStatus` wire strings below.
- Emitted from the confirmation poller's background tick (module docs point
  1/2) and from `get_membership_state`'s self-healing merge write, for
  whichever side observes the transition first.

**Consumer surface**: the module's proxy exposes the standard logos-core
event mechanism — `logos.<module>.on("membership_state_changed", [](const
QVariantList& args) { … })` in C++ (backed by the `eventResponse(QString,
QVariantList)` Qt signal every provider forwards through), `args` positional
in the table order above. From QML (`LogosQmlBridge`,
logos-view-module-runtime): arm with
`logos.onModuleEvent("<module>", "membership_state_changed")`, receive via
the `moduleEventReceived(moduleName, eventName, data)` signal — `data` is
the positional args as a native JS array, and unlike the call-reply path it
does NOT pass through the LogosResult-nulling serializer.
This implements the spec's optional "membership state subscriptions"
extension (RLN-MEMBERSHIP-MANAGEMENT) — **additive, not required**: a
consumer MUST NOT depend on it being wired up. Polling `get_membership_state`
remains the portable path every consumer can rely on.

## MembershipStatus wire strings

| Wire string | Spec enum |
|---|---|
| `unknown` | `MEMBERSHIP_UNKNOWN` |
| `pending` | `MEMBERSHIP_PENDING` |
| `failed` | `MEMBERSHIP_FAILED` |
| `active` | `MEMBERSHIP_ACTIVE` |
| `grace_period` | `MEMBERSHIP_GRACE_PERIOD` |
| `expired` | `MEMBERSHIP_EXPIRED` |
| `erased` | `MEMBERSHIP_ERASED` |

`MEMBERSHIP_ERASED_AWAITS_WITHDRAWAL` is never reported by the `logos`
namespace (its registry keeps no recoverable deposit).

## RateLimitProof

`generate_proof` returns every spec-struct field plus the canonical form:

```json
{
  "proof": "<canonical hex — the authoritative bytes>",
  "root": "<32B hex>", "external_nullifier": "<32B hex>",
  "share_x": "<32B hex>", "share_y": "<32B hex>", "nullifier": "<32B hex>",
  "message_id": N, "epoch": N, "membership_hash": "<hex>"
}
```

- The **canonical** `proof` is zerokit's `RLNProof` LE serialization:
  128-byte compressed Groth16 proof ‖ mode tag (`0x00` Single) ‖ y ‖ root ‖
  nullifier ‖ x ‖ external_nullifier (all 32-byte LE) — 289 bytes total. The
  spec struct's `proof[128]` is bytes `0..128`; its `share_x` is the
  circuit's signal hash `x`, `share_y` is `y`.
- `verify_proof` accepts **either** shape: the object above (canonical bytes
  trusted, decoded fields ignored), or the spec's decomposed struct — `proof`
  as the bare 128-byte Groth16 hex plus the five field values — which is what
  a shim reassembles from fields carried in its own network message format.
  Both land in the identical verified representation.
- Frozen byte-exact vectors (identity derivation, external nullifier, signal
  hash, public values, layout): `rust-lib/src/proof.rs`,
  `proof::tests::frozen_interop_vectors`.

## Epoch semantics

- `epoch = floor(unix_seconds / epoch_size_sec)`, a `u64` index on this wire
  (the `"epoch"` reply field and `get_epoch_quota`'s `epoch_index`). Inside
  the crypto it is the spec's `epoch[32]`: the index as a 32-byte
  little-endian integer (logos-delivery's `toEpoch`), and
  `external_nullifier = poseidon(hash_to_field_le(epoch[32]),
  hash_to_field_le(rln_identifier))` — byte-identical to logos-delivery's
  `generateExternalNullifier`. (Note: NOT nwaku's keccak-based construction.)
- `epoch_size_sec` is a **required `start()` parameter** with no default:
  until `start()` configures it, `generate_proof` / `verify_proof` /
  `get_epoch_quota` (and the `get_registry_parameters` echo) fail
  `not_ready` rather than improvise an epoch base. It is an
  **application parameter** — every
  proof generator and verifier of a deployment must configure the same value.
- `verify_proof` enforces application binding + epoch freshness: the proof's
  external nullifier must match the scope's expected value for the current
  epoch ± `max_epoch_gap`; anything else is `{"verdict":"invalid"}`. Consumers
  do not implement their own epoch checks. **Double-signal detection across
  messages is now the Module's job, not the consumer's** (a spec change): the
  Module keeps an in-memory nullifier log (per epoch, retained at least
  `max_epoch_gap` epochs, never on disk) and, when a proof reuses a nullifier
  under a different `share_x`, reconstructs the offender's identity secret from
  the two colliding shares and returns it as `recovered_secret`.

### verify_proof verdicts

A proof that fails any validity check (zk-invalid, root not in window, stale or
cross-application binding) is `invalid`. A proof passing every check is then
judged against the nullifier log:

| `verdict` | Meaning | Suggested consumer action |
|---|---|---|
| `valid` | First valid proof for this nullifier | Accept the message |
| `invalid` | Failed a validity check (bad zk / root / binding) | Reject the message |
| `duplicate` | Nullifier already seen under the SAME `share_x` — a retransmission of an already-accepted message | Drop as already-seen (not a violation) |
| `rate_limit_violation` | Nullifier reused under a DIFFERENT `share_x` — a double-signal; `recovered_secret` (hex) is the offender's own identity secret, reconstructed from the two shares | Reject the message; `recovered_secret` is the slashing evidence |

## RegistryOptions (`options_json`)

The spec's flat `{key, value}` options translate to a JSON object:

- **`logos` namespace, direct**: `{"funding_holding_account_id": "<account>"}` —
  the holding that pays `rate_limit × price_per_unit`.
- **`logos` namespace, delegated** (RLN Membership Allocation Protocol):
  `{"delegated": "true", "gifter_peer_id": …, "gifter_multiaddr": …,
  "auth_type"?, "auth_payload"?, "auth_provider"?, "auth_args"?}` — all
  values are strings, per the spec's flat `char*` pairs. register drives
  `rln_gifter_module` with the module-generated commitment.

  The auth surface is fully vector-agnostic — this module knows **no vector
  by name**. `auth_type` names the gifter auth vector verbatim in the wire's
  **open** `authentication_type` vocabulary (e.g. `"keycard-attestation"`);
  its payload comes from exactly ONE of `auth_payload` (raw hex, sent
  verbatim) or `auth_provider` — a module implementing the
  `rln_auth_vector` producer contract, which the gifter client calls with
  the commitment (`auth_args` forwarded verbatim). Omitting `auth_type`
  entirely makes an unauthenticated request for an open gifter. An
  application shipping its own allocation-auth strategy as
  `rln_auth_vector` plugin modules therefore needs **zero changes** here or
  in the gifter — configuration only. Example (keycard):
  `{"auth_type": "keycard-attestation", "auth_provider":
  "keycard_capture_module"}`.

  Rejected as `invalid_argument` **before a credential is minted** (the
  gifter client's own rules, checked early): payload material without
  `auth_type`; a named vector with no payload source, or with both at once;
  a non-hex `auth_payload`; auth options on the funded (non-delegated) path;
  a JSON boolean for `delegated` (or any non-string auth value) rather than
  silently coerced.

## start() config

```json
{
  "epoch_size_sec": 600,
  "registries": ["logos:testnet:<64-hex>"]
}
```

Listed registries get their valid-root windows warmed immediately
(`epoch_size_sec` is required — see Epoch semantics). There is no
default-scope key: every other method takes its
`(registry_id, rln_identifier_hex)` scope explicitly. `stop()` tears the
maintenance workers down: sleeping workers join within a ~200 ms grace; a
worker blocked in one in-flight registry read (≤80 s) is detached and
self-exits after that single read without scheduling further work — the
one bounded deviation from the spec's "cancelled cleanly". `start()`
respawns and reconfigures — both idempotent.
