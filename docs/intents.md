# `rln.*` intents

The Basecamp intent vocabulary for RLN membership. Version 1 (2026-10).

An intent is a capability name an app requests without naming who services it:
`logos.request("rln.membership.ensure", params, cb)` from a ui_qml app, and
Basecamp resolves the name to one installed provider that declared it, asks
the user, hands the provider the request, and routes the single
`{ok, data, error}` result back. Basecamp's own design is in
`logos-basecamp/docs/app-to-app-intents.md`; this document is what its §7
asks for — a published definition of the names, so two apps that never met
agree on what a request means.

## What an intent is for here, and what it is not

Intents exist for **user-mediated** actions that cross an app boundary.
Everything else stays what it is:

- Core modules (`delivery_module`, `liblogos_rln_module`,
  `liblogos_lez_rln_module`, `rln_gifter_module`) keep calling each other
  through LogosAPI. Nothing in this document changes proof generation,
  validation, quota or the delivery seam.
- A ui_qml app reads state directly:
  `logos.callModuleAsync("liblogos_rln_module", "get_membership_state", …)`
  and `logos.onModuleEvent("liblogos_rln_module", "membership_state_changed")`
  need no consent and must not be wrapped in an intent. There is no
  `rln.membership.status` and there will not be one.
- Over-quota sends are not an intent. `delivery_module` queues them
  (`messageQueued`) and sends when the epoch budget refills; nothing there
  is a decision for a human.

What *is* user-mediated is acquiring a membership: it spends the user's
balance, or asks them to fund an account, or asks a gifter to pay on their
behalf. That is the one capability below that does work; the other is
navigation to the place where that work can be watched.

## Vocabulary

| Intent | Requester | Provider | Hand-off | Status |
|---|---|---|---|---|
| `rln.membership.ensure` | any app that sends under RLN | `rln_membership_ui` | no | defined; provider pending (see Status) |
| `rln.membership.manage` | same, from a "Manage membership" affordance | `rln_membership_ui` | yes | defined; provider pending |
| `wallet.send` | `rln_membership_ui` | any wallet app | no | consumed, not defined here |
| `rln.gifter.pick` | `rln_membership_ui` | a gifter-directory app | no | name reserved; no provider, no definition yet |

Names follow Basecamp's grammar (2–4 lowercase segments). `rln` is this
stack's namespace; `logos.*` and `basecamp.*` are reserved by the platform.

### `rln.membership.ensure`

"Give this node a membership it can prove with on this registry, for this
scope." The provider runs whatever that takes — nothing, a funded
registration, a gift — with the user in the loop, and answers as soon as the
RLN module owns the outcome.

**Params** (Basecamp checks types against the chosen provider's
`metadata.json` declaration; undeclared extra fields pass):

| name | type | required | meaning |
|---|---|---|---|
| `registry_id` | string | yes | CAIP-10 `logos:<reference>:<64-hex>`. Malformed → `bad_request` |
| `rln_identifier` | string | no | 64-hex application scope (delivery passes `rlnState().rlnIdentifier`). Absent or empty: the **registry-wide** membership, which backs every application on the registry |
| `rate_limit` | number | no | messages per epoch; the provider clamps to the registry's bounds, out of range → `bad_request` |
| `gifter` | object | no | `{peer_id, multiaddr, auth_type?, auth_provider?}`. An app that knows a gifter (community config) offers the gift path. The provider shows it; it never applies it without the user |
| `reason` | string | no | one line the provider renders as *untrusted* text next to the host-attested `requesterName` ("Chat wants to send messages") |

**Result `data`** on `ok: true`:

```
{
  "registry_id":    "logos:…",
  "rln_identifier": "<hex64 or empty for registry-wide>",
  "state":          "active" | "grace_period" | "pending" | "unknown",
  "usable":         true | false,            // active | grace_period
  "membership_hash": "<hex>",                // when a record exists
  "leaf_index":     N, "rate_limit": N,      // when known
  "provisioning": {                          // when state is "unknown"
    "step":   "waiting_for_wallet" | "awaiting_funding" | "registering" | "done" | "refused",
    "detail": "<human sentence>",
    "payer": "<hex64>", "required": "<decimal>", "price": "<decimal>",
    "fee_reserve": "<decimal>", "balance": "<decimal>"   // awaiting_funding only
  }
}
```

`state` uses the RLN module's MembershipStatus wire strings. The provisioning
object is the one `get_membership_state` returns, verbatim; the funding
numbers are decimal strings because they are u128 on the chain.

**Answer policy.** `respond` fires exactly once per request, at the first
moment the RLN module owns the outcome. Funding can take hours and
Basecamp's dispatched-request backstop is ten minutes, so the provider never
holds a request open across a funding wait.

| Situation | Response |
|---|---|
| A live membership already backs the scope | `ok:true`, `state` as read |
| Registration submitted (funded, or gifted) | `ok:true, state:"pending", membership_hash` — the requester watches `membership_state_changed` |
| Parked on `awaiting_funding` and the user chooses "fund later" (or no wallet app answered `wallet.send`), or nine minutes elapse | `ok:true, state:"unknown", provisioning{…}` — the module keeps waiting; the requester shows `required` → `payer` and a `manage` affordance |
| Invalid params | `ok:false, error:"bad_request"` |
| The user leaves the wizard | `ok:false, error:"cancelled"` |
| Provisioning `refused`, registration `failed`, the registry module's wallet `failed`, or a request arrives while another is open | `ok:false, error:"failed"` |

`ok: true` therefore means "handled; `data` is a truthful snapshot", not
"usable now". Requesters branch on `data.usable` and `data.state`.

**Why a provider, not a direct call.** A chat UI could call
`register_membership` itself. It must not: the call spends the user's
balance or commits them to a gifter, the chat app has no screen in which to
explain that, and naming the membership UI by module name is the coupling
intents exist to remove. A machine without a provider answers
`unavailable`, and Basecamp offers the install when the catalog has one.

### `rln.membership.manage`

A hand-off (`"handoff": true`): "take me where I can see and manage my
membership". Params `registry_id` and `rln_identifier`, both optional and
validated exactly as above. Answers `ok:true, { state }` on arrival; the
user stays in the provider. Not web-reachable: a deep link's params are
attacker-controlled, and `registry_id` replacing the provider's default is
exactly the field that must not come from a URL.

### `wallet.send` (consumed)

When parked on `awaiting_funding`, the membership UI requests
`wallet.send` with `{ to: provisioning.payer, amount: required − balance,
memo: "RLN membership" }` and falls through to its manual "send `required`
to `payer`" screen on `unavailable` or `cancelled`. The payload shape is
whatever the wallet app publishes; this stack does not define
`wallet.send`, and declaring `uses` for it costs only Basecamp's 400 ms
floor when nobody provides it.

### `rln.gifter.pick` (reserved)

"Choose who pays for this membership." Today the membership UI hard-codes a
gifter's peer id and multiaddr and takes overrides by hand. A directory app
could provide this and return `{ peer_id, multiaddr, auth_type,
auth_provider }`. The name is reserved so no other meaning is attached to
it; nothing provides it and its params are not yet defined.

## Requester recipe

For a ui_qml app that sends through `delivery_module`:

1. `metadata.json`: `"uses": [ { "intent": "rln.membership.ensure" },
   { "intent": "rln.membership.manage" } ]` — entries are objects; a bare
   string array declares nothing.
2. On a send failing for RLN reasons (`messageError` whose message names a
   missing membership; a typed reason is a delivery-module follow-up), read
   the scope: `logos.callModuleAsync("delivery_module", "rlnState", …)` gives
   `registryId` and `rlnIdentifier`.
3. `logos.request("rln.membership.ensure", { registry_id, rln_identifier,
   reason: "…" }, cb)`.
4. In `cb`: `unavailable` → tell the user a membership app is needed
   (Basecamp has already offered the install); `ok && data.usable` → retry
   the send; `ok && data.state === "pending"` → arm
   `logos.onModuleEvent("liblogos_rln_module", "membership_state_changed")`
   and retry on `active`; `ok && data.state === "unknown"` → show
   `provisioning.required` and `provisioning.payer`, plus a button that
   requests `rln.membership.manage`.

## Provider recipe and the module surface it needs

`rln_membership_ui` declares in `metadata.json`:

```json
"provides": [
  { "intent": "rln.membership.ensure",
    "params": [
      { "name": "registry_id",    "type": "string", "required": true  },
      { "name": "rln_identifier", "type": "string", "required": false },
      { "name": "rate_limit",     "type": "number", "required": false },
      { "name": "gifter",         "type": "object", "required": false },
      { "name": "reason",         "type": "string", "required": false } ] },
  { "intent": "rln.membership.manage", "handoff": true,
    "params": [
      { "name": "registry_id",    "type": "string", "required": false },
      { "name": "rln_identifier", "type": "string", "required": false } ] } ],
"uses": [ { "intent": "wallet.send" } ]
```

and handles `onIntentRequested(requestId, intent, params, requesterName)`
with one `logos.respond(requestId, ok, data, error)` per request, all four
arguments always.

The RLN module surface a provider works from (`liblogos_rln_module` ≥ 0.12.0,
`liblogos_lez_rln_module` ≥ 5.0.0), all reachable from QML:

| Need | Call |
|---|---|
| is the scope already backed; what is the pass doing | `get_membership_state(registry_id, rln_identifier)` — `"unknown"` carries `provisioning` |
| a registry-wide membership (no `rln_identifier` in the request) | `ensure_membership(registry_id, options_json)` — spawns the same provisioning pass `start()` runs; `start()` itself is a `result` method and is unreachable from QML |
| a scoped or gifted membership | `register_membership(registry_id, rln_identifier, options_json)` with `rate_limit`, or the `delegated` / `gifter_*` / `auth_*` keys |
| the account to fund and the amount | `provisioning.payer` / `provisioning.required` (never the `detail` sentence) |
| the payer's balance moving | `liblogos_lez_rln_module.get_native_balance("")` |
| wallet readiness | `liblogos_lez_rln_module.wallet_status()` → `state` |
| pending → active | event `membership_state_changed` |

A pass is one per registry per process: `ensure_membership` reports a
running pass rather than starting another, and a later `start()` naming the
registry supersedes it. Provisioning stands down the moment a live
membership of any scope appears — including one a UI registered by hand
while the pass waited for funding — so a provider never causes a second
registration.

## Compatibility policy

- A definition changes only by **adding** optional params or result fields.
  A breaking change gets a new name (`rln.membership.ensure2` is wrong;
  `rln.membership.acquire` with its own definition is right).
- A provider must tolerate params it does not know (Basecamp passes them
  through); a requester must tolerate result fields it does not know.
- `error` is one of Basecamp's six codes; a provider that answers anything
  else is coerced to `failed`.

## Status

| Piece | State |
|---|---|
| this vocabulary | v1, published here |
| `liblogos_rln_module` 0.12.0: structured `provisioning` fields, `ensure_membership`, any-scope stand-down during the funding wait | done on this repo's `main` once merged |
| `rln_membership_ui` as provider | not started. The 0.7.x UI predates the wallet-owning registry module (it still drives `lez_core` and a faucet that no longer exists) and must be re-based on `wallet_status` / `get_native_balance` / `provisioning` before it can provide anything |
| `delivery_module`: a typed reason on `messageError` (or a `membershipRequired` event) | cross-repo ask |
| `rln_gifter_module`: refuse a registry mismatch at once instead of letting the client wait out the 300 s window | cross-repo ask |
| `logos-rln-e2e`: a scenario that stages a requester fixture and asserts the answer-policy rows | cross-repo ask |
