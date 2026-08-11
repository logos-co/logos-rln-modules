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
  (lidl scaffold + typed `logos_execution_zone` client + Qt cdylib glue).
- `rust-lib/liblogos_lez_rln_module.lidl` — the module contract (7 methods, no
  events).
- `rust-lib/deps/logos_execution_zone.lidl` — hand-maintained dependency
  contract for the wallet module, wired via `dependency_overrides`.
- `rust-lib/src/lib.rs` — the provider implementation (wallet lp client + the
  7 handlers).
- `rust-lib/src/rln_core.rs` — the RLN core (tree/proof/register/funding logic),
  depending only on the shared `rln-layouts` crate.
- `rust-lib/generated/provider_gen.rs` — checked-in scaffold for local
  `cargo check`/tests; the nix build regenerates it. Regenerate manually with:
  `logos-lidl-gen rust-lib/liblogos_lez_rln_module.lidl --provider \
   --dep logos_execution_zone=rust-lib/deps/logos_execution_zone.lidl \
   -o rust-lib/generated/provider_gen.rs`

## Staged sources (not committed)

mkLogosModule's `rustCrateSrc` stages only the crate dir (plus
`logos-rust-sdk-src`) into the nix sandbox, so path-deps must live inside the
module tree. One staged copy is required and is NOT in git:

- `logos-rust-sdk-src/` — logos-co/logos-rust-sdk at the rev pinned in
  `stage-sources.sh` (the rev the builder's codegen comes from).

Refresh it — rsync plus a diff verification that fails on drift — with:

```sh
./stage-sources.sh
```

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
# registry selection (default shared-faucet):
LEZ_RLN_TESTNET_DEPLOYMENT=shared-5ade-v2 LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_
```

The registry comes from `../deployments/<name>/deployment.json`. These
catch what unit pins can't: layout drift against the pinned guest image,
PDA-derivation divergence, tree-encoding drift, chain-clock unit changes.

## Design constraints (read before changing)

- **`concurrency` is `single`, deliberately.** Dispatch runs on the module's
  own event loop and the blocking `lp_invoke`'s QtRO wait loop pumps that
  same loop, so wallet round-trips do not deadlock; multi-concurrency has
  never been validated against this module's callers.
- **The wallet lp client is created in `on_context_ready` (main Qt thread)**
  and never lazily in handlers: the creating thread owns the client and must
  run a Qt event loop (lp owner-thread contract). `wallet_call` picks sync
  `lp_invoke` on the owner thread and `lp_invoke_async` + channel off it.
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
