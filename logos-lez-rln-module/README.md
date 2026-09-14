# logos-lez-rln-module — the RLN registry provider (Rust)

`liblogos_lez_rln_module`, built on logos-rust-sdk / logos-module-builder. It
serves the membership stack's chain access: registry reads (roots, merkle
proofs, membership PDA + lifecycle state, registry bounds), the Register tx,
and the faucet funding flow (`claim_tokens`/`get_token_balance`). Its two
consumers are the membership module's registry provider and the membership
UI's funding flow; identity/credential generation lives in the membership
module, so this module never handles secrets. The chain logic lives in-crate
(`rust-lib/src/rln_core.rs`, plain Rust); there is no C ABI.

v2.0.0 dropped the C++-era frozen wire surface: `generate_identity`,
`compute_rate_commitment`, `is_member_registered`, `mint_tokens`, the two
`start_*_broadcast` methods and the `valid_roots`/`merkle_proof` events
(the membership module polls the getter methods instead).

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives logos-module-builder
  (lidl scaffold + Qt cdylib glue). No module dependencies since 3.0.0.
- `rust-lib/liblogos_lez_rln_module.lidl` — the module contract (9 methods, no
  events).
- `rust-lib/src/wallet.rs` — the wallet this module owns: bring-up, the home it
  adopts or provisions, and the three chain operations it used to make over lp.
- `rust-lib/src/lib.rs` — the provider implementation (the handlers).
- `rust-lib/src/rln_core.rs` — the RLN core (tree/proof/register/funding logic),
  depending only on the shared `rln-layouts` crate.
- `rust-lib/generated/provider_gen.rs` — gitignored scaffold the nix build
  regenerates in-derivation; `nix run .#generate` materialises it for local
  `cargo check`/tests (see "Staged sources").

## Staged sources (not committed)

mkLogosModule's `rustCrateSrc` stages only the crate dir (plus
`logos-rust-sdk-src`) into the nix sandbox, so path-deps must live inside the
module tree. Two inputs the crate references are NOT in git:

- `logos-rust-sdk-src/` — logos-co/logos-rust-sdk at the rev the locked
  builder pins (the rev its codegen comes from).
- `rust-lib/generated/provider_gen.rs` — the provider scaffold, emitted by
  that builder's lidl-gen at the protocol
  version it stamps (`LOGOS_PROTOCOL_VERSION_STRING` of its logos-protocol
  input).

Materialise both — they cannot drift from what the nix build compiles — with:

```sh
nix run .#generate        # ./stage-sources.sh is a wrapper kept for callers
```

Re-run it after any flake.lock or `.lidl` change.

`rln-layouts` (the shared borsh wire crate) is a normal cargo git dependency
on logos-co/logos-lez-rln, pinned by rev in `rust-lib/Cargo.toml`; bump the
rev together with any layout change (generally alongside a redeploy).

## Build

```sh
nix build 'path:.#default'   # path: scheme — the dir is untracked in-repo
# plugin: result/lib/liblogos_lez_rln_module_plugin.dylib
nix build 'path:.#lgx'       # .lgx bundle for LEZ_RLN_LGX
```

## Live-registry tests (testnet)

`src/testnet_tests.rs` validates rln_core's chain-facing logic — ConfigState
offsets, PDA derivation, valid roots, merkle-proof construction (recomputed
via poseidon), clock decode, membership reads — against a DEPLOYED
registration program. Read-only, off by default (each test skips unless
gated), no new crate deps (`curl` subprocess speaks the sequencer's
JSON-RPC `getAccount` — the same read the wallet serves this module at
runtime):

```sh
LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_ -- --nocapture
LEZ_RLN_TESTNET_DEPLOYMENT=shared-5ade-v2 LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_
```

The registry comes from `../deployments/<name>/deployment.json`. These
catch what unit pins can't: layout drift against the pinned guest image,
PDA-derivation divergence, tree-encoding drift, chain-clock unit changes.

## Design constraints (read before changing)

- **`concurrency` is `multi`** (since 2.1.0; it was `single` until a blocked
  handler was observed wedging the whole module: single-mode dispatch runs ON
  the subprocess event loop, so one stuck call froze QtRO replica acquisition
  itself until SIGKILL). Under multi the Qt glue runs each call on its own
  worker; a stuck handler leaks one worker instead of starving every caller.
  All state lives in lock-guarded statics; the impl struct has no fields.
- **The wallet is this module's own, in-process** (`rust-lib/src/wallet.rs`),
  since 3.0.0. It links the LEZ `wallet` crate rather than calling the
  `lez_core` module, because a host has exactly one `lez_core` wallet handle,
  `open`/`create_new` both refuse while one is open, there is no close, and
  nothing reads back the gas limit a wallet was opened with. A registration
  needs ~9.1M cycles against a stock 2,000,000 default, so losing that race
  meant every registration refused with a bare "Incorrect fee". The crate
  keeps `#![deny(unsafe_code)]`: the Rust crate, never the C ABI.
- **It cannot pay its own way, and that is structural.** A fee is reserved
  from a *native* balance, the payer must sign so the wallet has to hold its
  key, and native balance enters an account only at genesis, over the bridge,
  or by transfer from something already funded. `LEZ_RLN_PAYER_KEY` hands in
  one funded key — imported, so it grants that one account and wipes nothing,
  unlike a mnemonic restore. A wallet home staged by
  `tools/deployments/stage.sh` needs none of that: adopting one through
  `LEE_WALLET_HOME_DIR` brings its payer derivation with it.
- **Bring-up runs on its own thread.** `on_context_ready` fires on the host's
  Qt main thread, and opening a wallet calibrates sequencers and then syncs
  the chain. Handlers wait on a condvar for a bounded window and answer an
  empty string if it has not settled; the status method is how a consumer
  tells "still coming up" from "broken".
- **The wallet sits behind a read-write lock.** Reads and sends take a shared
  guard; deriving an account or syncing takes an exclusive one — the honest
  model, since the wallet serves no reads while a sync runs. The state lock is
  released before any call: holding it across a round trip would serialize
  every handler, the wedge the `single` -> `multi` bump was made to escape.
- **`REG_IN_FLIGHT` dedup in `register_member`**: callers can fire
  register_member twice within seconds for the same membership. An on-chain
  idempotency pre-check cannot see a tx that is still confirming (60-90s on
  testnet), and the double submit reuses the payer nonce — the second tx is
  silently dropped and, on a virgin tree, poisoned the submitting wallet's
  nonce sequence. The in-session (config_account, id_commitment) map returns
  the first submission's reply to duplicates.
- **Funding methods** (`claim_tokens`/`get_token_balance`) mirror the
  tx-account order + signing flags of the deployed programs exactly: claim
  `[config, payment_def, dest(signer)]` under the registration program;
  `get_token_balance` is tri-state (`""`=error, `{exists:false}`=absent,
  `{exists:true,…}`=present) so the faucet poller can distinguish "unreachable"
  from "not credited yet".
