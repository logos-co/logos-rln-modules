# A delivery node running RLN against a degraded chain RPC

What happens at each point where this stack touches the sequencer when the RPC
is unavailable, slow, or answering while the chain stops advancing — and whether
the node recovers when the RPC comes back.

Derived from the code, not from runs. Every claim carries its file:line so it can
be checked or disproved. Refs read:

| repo | ref |
|---|---|
| logos-rln-modules | working tree, `feat/mix-wire-binding` (1adf114) |
| logos-execution-zone | `2fe8c5ce5` — the rev `logos-lez-rln-module/flake.nix:26` pins |
| logos-delivery | `origin/master` dd888838 |
| logos-delivery-module | `origin/master` 4eb3b5b |
| logos-rln-e2e | `origin/master` 5d3e4a2 |

Two things to know before reading, because both invalidate an obvious first
guess:

- **The wallet is the execution-zone one, not the vendored copy.**
  `logos-lez-rln-module` links `wallet_ffi` from the `logos-execution-zone` flake
  input (`flake.nix:26`, `wallet_ffi` at `:51`). The copy under
  `logos-lez-rln/lssa/wallet` is legacy and differs materially — it has no
  `multi_client.rs`, so the calibration and leader-selection behavior below is
  absent from it. Reading the wrong copy produces a wrong answer about the single
  most important failure mode here.
- **`configureRln` no longer exists.** It was removed from delivery-module by
  `7835f89` ("feat!: RLN comes from the network preset, not from the client",
  #118), which is an ancestor of `origin/master`. RLN is installed from the
  network preset a node's `createNode` config names, and `rln-lez` /
  `rln-registry-id` / `rln-identifier` / `rln-registry-options` are now actively
  **rejected** as client-supplied keys (`tests/api/test_conf.nim:374-378`, "the
  LEZ RLN options are not accepted from configuration"). e2e `origin/master` has
  followed: `delivery_stage_rln_presets` + `rlnState` polling replaced
  `delivery_configure_rln` (`harness/lib/delivery.sh:4-5, 33-59, 130-158`).

## The chain surface

Only `logos-lez-rln-module` talks to the sequencer. It uses exactly these FFI
calls (`logos-lez-rln-module/rust-lib/src/wallet.rs`): `open` / `create_new`,
`import_public_account`, `create_account_public`, `get_current_block_height`,
`sync_to_block`, `get_account_public`, `get_balance`,
`send_generic_public_transaction`, `save`, `free_*`, `test_transport`.

`wallet_ffi_poll_transaction_status` is **not** among them, which matters: the
module never polls a transaction to confirmation, so `TxPoller` and its
no-sleep inner retry loop (`lez/wallet/src/poller.rs:42-60`) are off this path
entirely. Confirmation is observed instead by `logos-rln-module`'s 15s poller
re-reading the membership PDA (`poller.rs:40`).

Underneath, in `logos-execution-zone/lez/wallet`:

- Reads and sends go through `MultiSequencerClient::metered_get` /
  `metered_send_transaction` (`multi_client.rs:248`, `:300`). **No retry.**
- Per-request bound is jsonrpsee's compiled-in 60s default: the builder never
  calls `.request_timeout(...)` (`lib.rs:203`).
- The staged config sets `distribution_limit: 1`
  (`logos-lez-rln/tools/deployments/{provision,stage}.sh`), so `metered_get`'s
  fall-through to the next leader (`multi_client.rs:265-274`) has nowhere to go.
  **There is no failover**, although `sequencers` is an array.
- `client_rotation()` — re-calibrate and re-choose a leader — is reachable only
  from `wallet_ffi_save` (`lez/wallet-ffi/src/wallet.rs:252`), never from a
  failed call. A leader that goes bad mid-run stays the leader.
- The `seq_poll_timeout` / `seq_poll_max_retries` / `seq_tx_poll_max_blocks`
  knobs the staged config writes (30s / 10 / 15) configure only `TxPoller`,
  which this path does not use. They are inert here; the real bound is the 60s.

## The delivery seam

The delivery library reaches RLN through a **C callback vtable**, not a socket:
`LogosDeliveryRlnPlugin` with four entries — `get_membership_state`,
`get_epoch_quota`, `generate_proof`, `validate_proof` — installed by the host
through `logosdelivery_rln_set_plugin`
(`logos_delivery/waku/rln/rln_lez/transport.nim:187-201`,
`library/liblogosdelivery_rln.h:44-46`). Each Nim call allocates a `Pending`
with a `ThreadSignalPtr`, fires the callback, and awaits the signal with a
timeout (`awaitResult`, `transport.nim:99-111`); the reply crosses back via
`logosdelivery_rln_response` (`transport.nim:216-229`). The host half is
`logos-delivery-module/src/rln_bridge.{h,cpp}`, installed from
`DeliveryModuleImpl::installRlnPlugin` (`delivery_module_plugin.cpp:1079-1105`)
when the preset resolves an enabled `RlnPresetEntry`.

Backend selection is `node_factory.nim:339` — `rlnPluginRegistered()` asks
whether the host installed a plugin; `:341-345` refuses a config that asks for
both plugin and EVM; `:352-362` mounts the LEZ backend, `:363-378` the EVM one.

Budgets, and there is **no retry at any layer of this seam**:

| op | Nim budget (`transport.nim:96-97`) | bridge budget (`rln_bridge.cpp:87-89`) |
|---|---|---|
| `get_membership_state` | 80s (`RlnRegistryReadTimeout`) | 70s |
| `generate_proof` | 80s | 70s |
| `validate_proof` | 10s (`RlnLocalTimeout`) | 10s |
| `get_epoch_quota` | 10s | 10s |
| module `start` / `stop` | not routed through the library | 20s, synchronous |

`callFail` (`rln_bridge.cpp:143-155`) classifies a failure: `isRefusal` —
`unknown_method`, `invalid_args`, `dispatch_failed` — is **Permanent**,
everything else including a timeout or a dropped transport is **Transient**. It
fabricates a reply in the op's own dialect rather than leaving the request
hanging (`transportFail`, `:126-136`).

Module `start` only dispatches — the real `startBackend()` runs on a dedicated
`rlnBringUpThread` spawned from `createNode`
(`delivery_module_plugin.cpp:695-715`) — so a slow module start cannot stall the
delivery node. `stop` is the opposite: synchronous, up to 20s, on whichever
thread calls it (`:735-756`).

## Behavior per touchpoint

`recovers?` means: once the RPC is healthy again, does the node return to working
order **on its own**, with no restart and no operator action?

| # | touchpoint | on RPC unavailable | on slow RPC | recovers? |
|---|---|---|---|---|
| 1 | Wallet open / calibration (`wallet_ffi_open` → `MultiSequencerClient::new`) | open fails; `Readiness::Failed` latched, no retry | 3 calibration attempts, each bounded by the 60s request timeout | **NO** — see defect 1 |
| 2 | `ensure.rs` wallet wait | sees `"failed"` → terminal `Err`, records `Refused`, never re-enters | patient up to `WALLET_WAIT = 300s`, then terminal | **NO** — see defect 1 |
| 3 | `ensure.rs` funding wait | balance read returns `None`, not 0; waits with backoff, **no deadline, by design** (`ensure.rs:271-330`) | same | **yes** |
| 4 | Registration submit (`send_generic_public_transaction`) | sync failure → record `Failed` + error surfaced; async failure, if retryable, leaves the record `Pending` for the poller (`lifecycle.rs:132-137`) | serialised by `SEND_LOCK` (`wallet.rs:295-307`); nonces come from confirmed state | **yes** |
| 5 | Confirmation polling (`logos-rln-module` poller, 15s / 60s) | `Err` → `None`, record untouched: "an unreachable registry proves nothing about the submission" (`poller.rs:70-97`) | unchanged cadence | **yes** |
| 6 | Valid-root refresher (`roots.rs`, 10s) | refresh error logged and skipped; window ages past `STALE_AFTER_SECS = 60` and then reports `None` (`roots.rs:92-99, 132-134`) | a latency near the interval makes staleness intermittent | **yes** |
| 7 | `validate_proof` | window stale → `NotReady`. **Never a false `invalid`** | as unavailable, intermittently | **yes** (module side) |
| 8 | `generate_proof` | path-cache hit needs no chain I/O at all, so proving **keeps working**; a miss re-fetches on the request path and fails with `ProviderFailure` | miss costs up to the 70s provider budget | **yes** |
| 9 | Message-id slot accounting | slot is reserved only *after* the path fetch succeeds (`lib.rs:1290-1305`), so a chain-read failure cannot burn one | same | n/a |
| 10 | `get_membership` | tri-state: an RPC error returns an empty reply → `ProviderFailure`, and is **never** collapsed into `registered:false` (`logos-lez-rln-module/lib.rs:817-888`) | up to 70s | **yes** |
| 11 | Delivery receive path | every module failure — `NotReady`, transient, timeout, decode — becomes `ValidationResult.Ignore`: **the message is silently dropped** | same, intermittently | **yes**, but see defect 2 |
| 12 | Delivery send path, membership unusable | a negative membership result is **not cached**: every send attempt does a fresh 80s-budget round trip, sequentially, stalling the whole queue | same | see defect 3 |
| 13 | Delivery admission quota | `get_epoch_quota` is now a real 10s cross-module call per `admit()`; failure degrades to a wall-clock fallback, but the 10s wait happens first | 10s per admission attempt | **yes** |
| 14 | Stuck FFI call | the module runs `concurrency: "multi"` so a stuck handler leaks one worker instead of freezing the module (`README.md:86-90`) | one leaked worker per stuck call | partial |

## Confirmed by running it

Defect 1 is not a code-reading inference any more. `logos-rln-e2e`'s
`delivery-rln-degraded` scenario boots a node with its wallet pointed at a fault
proxy in `refuse` mode, and the two runs differ exactly as predicted.

**Against the unfixed module stack**, the node log carries the literal error this
report traced through `choose_leaders`:

```
[wallet-ffi] Failed to create wallet: Failed to find leader
lez-rln wallet: create_new at .../wallet-n1/storage.json returned no handle
```

`Statistics not found, choosing empty` above it confirms the cold-start branch,
and `wallet_status` then reports
`{"state":"failed","detail":"create_new ... returned no handle"}` — latched,
within a second, with the chain merely unreachable. Note it is `create_new`, not
`open`: the fresh-home path, which is what every multi-node run uses.

**With the fix**, the same outage produces:

```
lez-rln wallet: opening the wallet: create_new ... returned no handle   (once)
... 8 further attempts at the 5s cadence ...
lez-rln wallet: opened on attempt 9 after 40s
lez-rln wallet: derived the payer 7f193352…
```

and the scenario's assertions pass in order: the wallet stays `pending` with the
open error as its detail for the whole dwell; the provisioning pass reports
`{'step': 'waiting_for_wallet'}` rather than `refused`; lifting the fault is
enough on its own — no restart and no second `start()` — for the wallet to reach
`ready`, the membership to register and go **active at leaf 0**, and the registry
read path to warm in 1s.

With the delivery leg on (delivery-module pinned at `v0.3.0-rc.2`, `d321c1c`,
whose bundle comes prebuilt from the logos cache — no checkout, no source build)
the same run continues to `rlnState Ready (scope matches the staged preset)` and
a delivery node listening with RLN up from its preset, for 104 chain requests
end to end.

Two things the run settled that the code could not:

- **`start()` does not depend on the chain.** Called while the sequencer was
  unreachable it still returned `started:true`, because it only dispatches the
  provisioning pass. So a node genuinely does come up "healthy" into an outage —
  which is what makes defect 1's signature so quiet.
- **The RPC cost of one node's bring-up and one registration is 84-89 requests**
  across runs: ~56 `getLastBlockId`, ~20 `getAccount`, 3 `getBlockRange`, 3-6
  `getAccountBalance`, 1 `sendTransaction`, 1 `getProofsAndRoot`. That is the
  amplification baseline to size against a hosted endpoint's rate limits, and
  `getLastBlockId` outnumbering every state read by more than 2:1 is worth a look
  on its own — one send transaction against fifty-odd head polls.

The run also prints the provisioning pass's own account of the wait, which is
the clearest statement of the funding contract anywhere in the stack:

```
awaiting_funding: ced9540f… needs 647400000 native
                  (1000000 price + 646400000 fee reserve); it holds 0
```

and afterwards `payer holds 4926319728 native after paying for the membership` —
73.7M of 5e9 spent, the fee reserve dominating the price by ~650x exactly as
`FEE_RESERVE`'s comment says.

## The fix against the rest of the ladder

`fix/wallet-open-retry` was run across every scenario that exercises the module
stack without extra setup, with `RLN_MODULES_CHECKOUT` pointing at the fix on top
of `main` — the PR's content, not the branch it was written on. Re-run in full
after `main` moved to 5a64fd7 (the epoch-gap merge, which touches the same crate
as `ensure.rs`); the table is the post-rebase result.

| rung | target | verdict | time |
|---|---|---|---|
| `harness/selftest.sh` | — | PASS | 357s |
| `delivery` | none | PASS | 202s |
| `register` | local | PASS | 379s |
| `keystore` | local | PASS | 421s |
| `live-registry` | local | PASS on `fix/testnet-tests-program-owner`; FAIL on this branch alone — pre-existing, unrelated (below) | 490s |
| `delivery-rln` | local | PASS | 414s |
| `delivery-rln-degraded` | local | PASS | 420s |
| `delivery-rln-soak` | local | PASS | 938s |

The two chainless rungs were the ones worth watching, because the fix changes
exactly their situation: with no reachable sequencer the wallet no longer settles
into `Failed`, so a wallet-dependent call waits out `READY_WAIT = 30s` instead of
erroring at once. Both pass, and `selftest`'s probes still return promptly (its
dummy arguments are refused at the argument check, before any wallet wait).

The soak is the load evidence: 600 timed sends at p50 230ms / p95 245ms,
1505 `generate_proof` and 790 `validate_proof` per node across three saturation
epochs, and its own verdict — "exactly 100 slots per node, every epoch refilled,
nothing lost". The retry loop costs nothing on the happy path, which is what you
would expect from a change that only runs when an open fails.

### `live-registry` is broken independently of this fix

Five of its six `testnet_*` tests fail in the shared helper at
`logos-lez-rln-module/rust-lib/src/testnet_tests.rs:216`:

```
panicked at src/testnet_tests.rs:216:52: owner words
```

That line is `result["program_owner"].as_array().expect("owner words")`, and the
helper's doc says "program_owner arrives as 8 LE u32 words". The live sequencer
now answers with a **base58 string**:

```
getAccount -> keys: ['balance','data','nonce','program_owner']
              program_owner: str  "11111111111111111111111111111111"
```

So this is a LEZ `getAccount` wire change, not a regression — and that is
demonstrated, not argued: the same scenario run against a **pristine `main`
worktree with the fix absent** fails identically, same panic, same
`1 passed; 5 failed`. Three things also place it outside this fix by
construction: the commit touches only `wallet.rs` and `ensure.rs`;
`testnet_tests.rs` is byte-identical to `main`; and the helper reaches the chain
through its own raw `rpc()` call, not through the module. Only these tests
noticed because everything in production reads accounts via `wallet_ffi`, which
already handles the current shape.

A second, smaller thing surfaced while setting that control up: `live-registry`
cannot run from the flake pin alone. Without `RLN_MODULES_CHECKOUT` it dies at
`stage-sources.sh failed`, because it stages the crate out of the read-only
pinned `/nix/store` path. So the scenario effectively requires a checkout, which
nothing declares.

The repair is local to the test helper: decode the string with the file's own
`b58_decode32` instead of folding 8 words. Done on
`fix/testnet-tests-program-owner` (off `main`, separate from the wallet fix), and
`live-registry` goes from 1 passed / 5 failed to **6 passed** against a local
devnet. `testnet_config_account_matches_deployment_and_bounds_decode` is among
them, and it asserts the owner *is* the registration program — so the decode
yields the right 32 bytes, not merely a value that fails to panic.

## Defects, ranked

### 1. A node that boots while the sequencer is unreachable never recovers

The chain: `MultiSequencerClient::new` runs inside wallet construction
(`lez/wallet/src/lib.rs:203`, inside the private `async fn new` at `:183`).
**Both** entry points funnel through it — `new_update_chain` (`:144`, what
`wallet_ffi_open` blocks on) and `new_init_storage` (`:163`, what
`wallet_ffi_create_new` blocks on, via `Self::new` at `:171`) — so this bites a
brand-new home exactly as hard as an existing one. That matters because a node
given only a staged `wallet_config.json` takes the *create* path, which is what
`daemon_self_paying` sets up and therefore what every multi-node e2e run does. It calibrates each endpoint — `calibration_limit:
3` in our staged config — and then `choose_leaders`
(`multi_client.rs:613-626`) **filters out every client with no statistics
entry** and returns `None` when that empties the list. `setup` bails "Failed to
find leader", so `wallet_ffi_open` fails.

`bring_up` then calls `fail(&e)` and **returns**
(`logos-lez-rln-module/rust-lib/src/wallet.rs:377-382`). `fail` sets
`Readiness::Failed` (`:340-345`). There is no retry loop and nothing re-arms it,
so `wallet_status` reports `"state":"failed"` for the life of the process.
`ensure.rs:222-251` treats `"failed"` as terminal, returns at once, records
`Refused` — and `ensure::run` is entered from `start()` and nowhere else.

The delivery node meanwhile **starts normally** (module `start` only dispatches),
and each send then fails on its own. So the operator signature is not "the node
refused to start" but "the node is up and every message fails", permanently,
after the chain has been healthy again for hours.

Made harder to reason about: statistics are persisted to `statistics.json` in the
wallet home. On a **warm** home the endpoint goes to `actualization_list` rather
than `calibration_list` (`multi_client.rs:122-127`), a failed actualization
leaves the previous healthy statistics in place, a leader *is* chosen, and the
wallet **opens** — after which individual calls merely fail at 60s each. The same
outage therefore produces two different node behaviors depending on whether a
statistics file survived. e2e always uses a fresh `E2E_RUN_DIR`, so it always
gets the harsher branch; a redeployed production node gets the other.

**Fix.** Two edits, both matching discipline the code already applies elsewhere:

- `wallet.rs` — retry a transient `open_or_create` with capped backoff while
  staying `Readiness::Pending`, and keep latching `Failed` only for the permanent
  causes (no home, no sequencer configured, payer-key import failure). The
  consumer contract already draws this line: "`pending` means keep waiting,
  `failed` means waiting longer will not help" (`wallet.rs:808-812`). An
  unreachable sequencer is currently filed under the wrong one.
- `ensure.rs` — give the wallet wait the shape the funding wait one function
  below already has deliberately: **no deadline**, on the same reasoning it
  states for funding ("a deadline cannot make funding happen sooner"). A
  `"failed"` wallet stays terminal; only `"pending"` becomes patient.

### 2. A receiving node silently drops messages, and cannot tell why

`toRlnError` (`transport.nim:238-247`) faithfully decodes the wire's
`not_ready` / `transient` / `budget_exhausted` / `permanent` classes — and then
the provider immediately throws the distinction away:
`.valueOr: return err($error)` (`transport.nim:311-320`). The validator
(`relay.nim:216-227`) maps any error to `pubsub.ValidationResult.Ignore`.

So a cold root window (`NotReady`, entirely expected in the first seconds after
start and after any 60s gap in root refreshes), a 10s bridge timeout, a transport
drop and a malformed reply are one outcome: the message is dropped for this
delivery, the peer is not penalised, and nothing distinguishes "I could not
check this proof" from "I checked it and it was fine but I am dropping it
anyway". Only a real verdict is acted on — `Valid` → `Accept`,
`Invalid`/`Duplicate`/`RateLimitViolation` → `Reject` (`:230-243`).

This is the module's careful `NotReady`-never-`invalid` discipline
(`roots.rs:92-99`) being discarded one layer up. The module goes to real trouble
to say "ask me again shortly" and the library hears "no".

### 3. An unusable membership costs a full 80s round trip per send attempt

`publish.nim:49-95`: only a **positive** membership result is cached
(`membershipVerified = true`, latched, never reset — `rln_lez.nim:29-30`). A
negative one is not cached and not backed off, so every send attempt repeats the
`getMembershipState` round trip on an 80s budget. Those awaits are sequential in
`SendService`'s `for task in tasksToSend` loop, so one stalled attempt holds up
every other queued task, and `MaxTimeInCache` is only 1 minute (2 for
`AnonymityLevel.Preferred`) — a single 80s stall can consume a task's entire
delivery deadline in one tick of a 1s loop.

Combined with defect 1 this is the actual failure shape of an
RPC-unavailable boot: not "sends fail", but "sends fail slowly, one at a time,
blocking each other".

### 4. Smaller notes

- **No failover, despite the shape of the config.** `sequencers` is an array,
  but `distribution_limit: 1` means one leader and no fall-through, and
  `client_rotation` is only reachable from `wallet_ffi_save`. A second endpoint
  in the config buys nothing today.
- **`onRlnProofRejected` is a no-op for LEZ.** It acts only on the EVM group
  manager's local merkle cache; on the LEZ path `node.rln` is nil, so the
  background path pre-warm never happens (the proof-clear and re-admit still
  do).
- **`onFatalErrorAction` is dead plumbing on the LEZ path.**
  `WakuRlnLezConfig` carries the field (`rln_lez/config.nim:13`) and mount
  threads it through (`node_factory.nim:356`), but nothing in `rln_lez.nim`,
  `transport.nim` or the LEZ branch of `relay.nim` ever invokes it. The
  `quit(QuitFailure)` on a failed Ethereum reconnect
  (`rln_evm/group_manager.nim:693`) is EVM-only and unreachable for us — which
  is the good news in this entry.
- **A slow module `stop` blocks its caller** for up to 20s, unlike `start`.
- **In the harness, not the product: `wallet_fund` races the pass it enables.**
  It transfers and then waits for the payer to hold the *full* amount, which
  assumes nothing spends it meanwhile. On a node whose provisioning pass is
  already parked at `awaiting_funding`, something does: the pass registers the
  moment the balance lands, and the balance never reads back at the full amount.
  Measured at ~4.93e9 of 5e9 — the difference being exactly the registration the
  funding was for — while the node log said `confirmed Active at leaf 0`. It
  fails against a node that is working perfectly. `delivery-rln`'s
  `E2E_FUND_LATE` path (`scenarios/delivery-rln/run.sh:545`) calls `wallet_fund`
  in precisely this position and carries the same race; it wins on timing rather
  than by construction, so it is a latent flake there. The fix in either place is
  to stop asserting on a balance threshold and let the membership going active be
  the proof.
- **The 60s/70s/80s stack is coherent but tight.** jsonrpsee bounds one request
  at 60s, the bridge gives 70s, the Nim side 80s. One retry anywhere inside
  would exceed all three.

## What the code cannot answer — these need a run

1. What `rlnState` reports *during* the outage, with the bridge up and the wallet
   not yet open. The scenario brings delivery up only after recovery, where it
   reads `Ready`, so this is still unmeasured — and it decides whether an
   operator has any signal at all for defect 1 before the fix lands.
2. Whether the leaked worker per stuck FFI call (touchpoint 14) ever exhausts
   anything under a sustained outage, or stays a slow leak of no consequence.
3. Whether sends really do keep working through an outage on the strength of the
   path cache alone (touchpoint 8) — the cache has no time TTL, only leaf-index
   invalidation (`path_cache.rs:50-55`), so the prediction is that a registered
   node keeps sending indefinitely while its peers stop being able to validate
   after 60s.
4. The real RPC call count per phase. Nothing here is a measurement, and a
   hosted endpoint with rate limits and a ~15s cold-start latency
   (`harness/targets/testnet.sh`) makes amplification matter.

## Reproducing this

`harness/lib/fault.sh` + `harness/tools/faultproxy.py` (in logos-rln-e2e) put a
JSON-RPC fault proxy between one node's wallet and the sequencer:
`pass` | `refuse` | `blackhole` | `delay:<ms>` | `error5xx`, switched mid-run by
writing a control file, and scopable to matching JSON-RPC methods so that
"reads answer, my transaction never lands" is expressible as
`fault_mode blackhole '*sendTransaction*'`.

Only the node under test is proxied. `chain_head` and every provisioning helper
keep dialling `$E2E_SEQUENCER` directly, so the harness can still see the chain
during an outage it induced. The seam that makes this work per-node is
`sequencer_addr` (and each `sequencers[].sequencer_addr`) in that node's
`wallet_config.json`: the module will not re-point an existing config from
`LEZ_RLN_SEQUENCER`, so rewriting the file is the only thing that lands.

In `pass` mode the proxy logs every request, which answers question 4 above as a
side effect.

## Limits of testing this locally

- The standalone sequencer leaves `CLOCK_50` at zero, so anything clocked by
  chain time — membership pending windows, expiry, renewal — is not exercised
  locally at all, degraded RPC or not (`docs/contract.md`, "Known
  local-vs-testnet gaps").
- `--target testnet` is currently non-functional repo-wide: `deployments/` is
  deliberately empty since the registry went native-asset-only, and
  `harness/targets/testnet.sh` dies without a committed descriptor. Everything
  above has to be provoked locally until a descriptor exists again.
- A proxy reproduces transport faults, not sequencer-internal ones. Reorgs and
  state divergence are out of its reach and out of scope here.

## Provenance

Touchpoints 1-10 and defect 1 were read directly and are quoted from the refs in
the table at the top. Touchpoints 11-13 and defects 2-3 come from a subagent's
read of logos-delivery / logos-delivery-module `origin/master`; the file:line
references are its evidence and have not each been re-opened by hand. One earlier
pass on that same question mapped the Ethereum `rln_evm_backend` instead of the
LEZ bridge because the local working trees are behind their remotes — worth
knowing if any of it looks wrong.
