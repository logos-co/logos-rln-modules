# nim-poc — the RLN module stack from Nim, without logos-core

A standalone Nim CLI that registers an RLN membership (and runs a proof
round-trip) against the real `liblogos_rln_module` + `liblogos_lez_rln_module`
Rust libraries and the real lez wallet — with **no logos-core process
anywhere**. It exists as a working reference for wiring the RLN stack into
logos-delivery (or any Nim consumer).

Validated end-to-end against the hosted testnet
(`https://testnet.lez.logos.co/`, deployment
`logos-rln-e2e/deployments/testnet-shrink-verify`): faucet claim → funded
register → pending → active → generate_proof → verify_proof `valid` →
re-verify `duplicate`.

## How it works

logos-core's entire contribution to this stack is (a) loading the module
plugins and calling five C functions on them, and (b) serving the `lp_*`
consumer ABI the modules use to call each other. Both are small enough to
replace in-process:

```
┌───────────────────────────── register_poc (Nim) ─────────────────────────────┐
│  main thread                        lp worker pool (4 threads)               │
│  ─ dlopen both module cdylibs       ─ runs every lp_invoke_async completion  │
│  ─ set_emit / set_context           ─ (poller calls, register submit)        │
│  ─ dispatch calls (JSON strings)                                             │
│                                                                              │
│  lp_shim.nim: exports lp_client_create / lp_invoke / lp_invoke_async /       │
│  lp_string_free / lp_token_save …  and routes by target module name:         │
│    "liblogos_lez_rln_module" ──► that cdylib's own logos_module_dispatch     │
│    "lez_core"                ──► wallet_shim.nim over libwallet_ffi          │
└──────────────────────────────────────────────────────────────────────────────┘
        ▲ undefined lp_* resolve        ▲ same                     │
┌───────┴────────────────┐  ┌───────────┴────────────┐  ┌──────────▼─────────┐
│ liblogos_rln_module    │  │ liblogos_lez_rln_module│  │ libwallet_ffi      │
│ .dylib (cdylib build   │  │ .dylib (same)          │  │ (lez wallet, built │
│ of the real rust-lib)  │  │                        │  │ at the repo's pin) │
└────────────────────────┘  └────────────────────────┘  └────────────────────┘
```

Files:

| file | role |
|---|---|
| `module_host.nim` | dlopen loader + the two reply dialects (`callTstr` / `callResult`) |
| `lp_shim.nim` | the exported `lp_*` C ABI, routing, and the async worker pool |
| `wallet_shim.nim` | `libwallet_ffi` bindings + the 3 `lez_core` wire methods + serial sync |
| `register_poc.nim` | the CLI (`probe` / `claim` / `register` / `full`) |
| `smoke.nim` | offline go/no-go: dlopen, symbol resolution, keystore write, nested lp chain |

## Build

```sh
./build.sh
```

builds, in order: the generated module sources (`nix run
./logos-rln-module#generate` if absent), both module rust-libs as cdylibs
(`cargo rustc --release --crate-type cdylib`, plus
`-Wl,-undefined,dynamic_lookup` on macOS), `libwallet_ffi` from the
`logos-execution-zone` rev in this repo's `flake.lock`, and the two Nim
binaries into `build/`. Requires nix, the repo's Rust toolchain, Nim ≥ 2.0.

Run the offline smoke first on a new machine:

```sh
build/smoke <rln.dylib> <lez.dylib> /tmp/rln-poc-smoke   # prints SMOKE PASS
```

## Runbook (testnet)

The registry id is `logos:<ref>:<64-hex config account>` — the config
account PDA in hex (base58 from a deployment descriptor decodes to it). For
the committed test deployment:
`logos:testnet:2fdff09aec02fe4f03157c77bddfa36bd3fd4c8ac546558daf4fe174647e5542`.

```sh
REG=logos:testnet:2fdff09aec02fe4f03157c77bddfa36bd3fd4c8ac546558daf4fe174647e5542
FUND=<a public account held by your wallet, base58 or 64-hex>

# 1. connectivity dry-run: provision wallet-home, open+sync wallet, read bounds
build/register_poc --registry=$REG --mode=probe

# 2. faucet-funded registries only: create+fund the token account
build/register_poc --registry=$REG --funding=$FUND --mode=claim

# 3. the real thing (register + poll to active + proof round-trip)
build/register_poc --registry=$REG --funding=$FUND --mode=full
```

Notes:

- `--data-dir` (default `./poc-data`) is the host-owned persistence root.
  The RLN keystore lives under `<data-dir>/liblogos_rln_module/` (guarded by
  `rln_keystore.lock`, fail-closed — never share the dir with a running
  logos-core instance). `provision_wallet_home` creates
  `…/wallet-home/wallet_config.json` on first run and never rewrites it.
- First run **creates a wallet** and prints the mnemonic; to reuse an
  existing funded wallet, copy its `storage.json` into
  `<data-dir>/liblogos_rln_module/wallet-home/` before the first run.
- The wallet syncs serially to head before anything else; a transaction
  from an unsynced wallet is accepted by the sequencer but never applies.
- `register` returns `state:"pending"` immediately; the module's own
  confirmation poller (15 s tick) flips it to `active` within its 300 s
  window, and the CLI polls `get_membership_state` until then. The
  `membership_state_changed` events it prints arrive on the module's poller
  thread through the emit callback.
- Timestamps cross the wire as **strings** (lidl `tstr`), rate limits as
  **JSON integers** — the dispatch layer's `as_i64()` silently reads a float
  as 0.

## Failure triage

| symptom | cause / fix |
|---|---|
| dlopen fails `symbol not found … _lp_client_create` | the host binary doesn't export the `lp_*` set — Nim procs need `{.exportc, cdecl, dynlib.}` (the `dynlib` pragma is what makes the symbol public); on Linux link with `-rdynamic` |
| every provider call fails `provider_failure` | an `lp_invoke` reply wasn't a JSON-encoded *string* — see `lp_result_to_string` in the lez-rln module |
| `register` errors `invalid_argument` mentioning bounds | rate limit outside the registry's `[min_rate_limit, max_rate_limit]` (probe mode prints them) |
| register goes `failed`, `retryable:true`, submit callback logged `empty reply` | the wallet leg failed — read the `wallet_shim:` / wallet stderr just above it |
| tx submitted (`tx_hash` present) but state stuck `pending` until the window lapses | wallet was not synced to head at submit time — the run logs `sync status at submit time` |
| all wallet reads return `""` / probe can't reach the chain | wrong or stale `wallet_config.json` (the module never rewrites it — delete `wallet-home/wallet_config.json` to re-provision), or the testnet LB is cold (first RPC can take ~15 s) |
| `generate_proof` fails `not_ready` right after activation | the registry root window is still warming (started by `start()`, 10 s cadence); the CLI retries this automatically |
| `wallet_ffi_open` fails / storage rejected | `storage.json` written by an incompatible wallet version — this PoC builds wallet-ffi at the repo's pinned lez rev on purpose |

## Notes for the logos-delivery integration

What this PoC proves carries over directly; the delivery-side work is
adaptation, not invention:

- **The seam**: delivery's `RlnInterface` concept (PR #4130,
  `logos_delivery/waku/rln/api/`) matches this module's method table 1:1 —
  `module_host.nim`'s `callTstr`/`callResult` plus `lp_shim.nim` is the
  backend such an implementation wraps. The natural insertion point in the
  node is a `GroupManager` subclass (or the `RlnInterface` backend), leaving
  gossipsub validators and the send path untouched.
- **Blocking dispatch**: every dispatch here is synchronous and can block
  for seconds-to-minutes (`register`'s registry read leg alone has a 70 s
  timeout; the submit 190 s). In-node these must run off the chronos loop —
  a dispatch thread + `ThreadSignalPtr` completion, like nwaku's zerokit
  proof calls; this PoC's plain-blocking CLI sidesteps that deliberately.
- **Threading contract**: wire `set_emit_callback`/`set_context` once from
  one thread (that thread becomes the modules' lp owner); serve
  `lp_invoke_async` completions from other threads, never inline in a
  dispatch (`register`'s submit callback takes a store lock the dispatch
  holds — inline completion deadlocks it).
- **Config**: the chain-shaped `RlnConf` fields (eth RPC, contract,
  chainId, creds) have no counterpart here — the module wants a persistence
  dir, a sequencer URL (once, via `provision_wallet_home`), `start()`'s
  `epoch_size_sec` (an application constant every generator and verifier
  must share, within the registry's bounds — delivery's old
  `epochSizeSec=1` default violates the testnet's min of 100), and a
  keystore password from the app layer.
- **Packaging**: the module cdylibs and `libwallet_ffi` are ordinary
  artifacts a build can pin the same way delivery already pins zerokit's
  `librln` (Makefile target + `--passL`, or nix inputs — this repo's flake
  exposes the rust-libs; `build.sh` shows the exact commands).
- **Version discipline**: wallet-ffi/lez must match this repo's
  `flake.lock` pin pair (`logos-execution-zone` + the wallet module rev) —
  storage formats and the wallet C ABI drift between lez versions.
