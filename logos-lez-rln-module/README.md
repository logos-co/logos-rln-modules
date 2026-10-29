# logos-lez-rln-module — the RLN registry provider (Rust)

`liblogos_lez_rln_module`, built on logos-rust-sdk / logos-module-builder. It
serves the membership stack's chain access: registry reads (membership PDA +
lifecycle state, registry bounds) and the Register tx. Its two
consumers are the membership module's registry provider and the membership
UI's funding flow; identity/credential generation lives in the membership
module, so this module never handles secrets. The chain logic lives in-crate
(`rust-lib/src/rln_core.rs`, plain Rust); there is no C ABI.

v2.0.0 dropped the C++-era frozen wire surface: `generate_identity`,
`compute_rate_commitment`, `is_member_registered`, `mint_tokens`, the two
`start_*_broadcast` methods and the `valid_roots`/`merkle_proof` events
(the membership module polls the getter methods instead).

v7.0.0 follows the program's tree off chain. The registration program keeps
no merkle tree; it numbers registrations in the config's `next_leaf_index`
(claimed by `Register`, carried by the `Registered` event, not stored in the
membership account) and emits `Registered`/`Extended`/`Slashed`/`Erased`
events, from which a zone service builds the depth-20 tree. Roots and proofs
come from that service, which the membership module queries over libp2p
(`logos-rln-module/docs/zone-query.md`), so `get_valid_roots` and
`get_merkle_proofs` are gone here. The leaf index is this module's to answer,
because it sent the registration: it records each send's claim
(`leaf_claims.json` in its persistence dir), `register_member` replies carry
it, and `get_membership` answers the latest claim once the membership exists.
Configs are the 120-byte layout: no `merkle_program_id`, `next_leaf_index`
appended. Of the registries in `networks.json` only testnet's
`testnet-zone-events` is on this program; the others were deployed by the
on-chain-tree program, and until they are redeployed `check_registry` reports
them as `wrong_generation`.

The same release goes back to the `lez_core` wallet module instead of
bundling `wallet_ffi`: a Register now costs ~52k gas, inside the shared
wallet's stock 2M limit. The module opens that wallet itself when nothing else has (a
delivery node has no wallet app), pays from any funded account in it, and
publishes one to fund when none is — see "Design constraints". Every reply
shape is unchanged; `LEZ_RLN_PAYER_KEY` is ignored.

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives logos-module-builder
  (lidl scaffold + Qt cdylib glue). Depends on `lez_core` (the wallet module)
  since 7.0.0, as it did before 3.0.0; `rust-lib/deps/lez_core.lidl` is the
  subset it calls, from which the typed client is generated.
- `rust-lib/liblogos_lez_rln_module.lidl` — the module contract (8 methods,
  no events).
- `rust-lib/src/wallet.rs` — the `lez_core` wallet as this module uses it:
  bring-up (where the wallet lives, opening or adopting it, for which
  network), the payer pick, and the chain operations, each a `lez_core` call
  behind the `Core` trait (a fake in the tests).
- `rust-lib/networks.json` + `rust-lib/src/networks.rs` — the built-in table of
  known networks (CAIP-2 reference → sequencer + registries), embedded at
  compile time. Add one from an e2e descriptor with
  `tools/add-network.sh <reference> <deployment.json>`.
- `rust-lib/src/fee_state.rs` — `get_fee_state` (since 4.2.0): the
  sequencer's `getFeeState` quote, read with `ureq` (rustls, so http and
  https) from the sequencer the wallet's config names.
- `rust-lib/src/lib.rs` — the provider implementation (the handlers).
- `rust-lib/src/rln_core.rs` — the RLN core (tree/proof/register/funding logic),
  depending only on the shared `rln-layouts` crate.
- `rust-lib/generated/provider_gen.rs` — gitignored scaffold the nix build
  regenerates in-derivation; `nix run .#generate` materialises it for local
  `cargo check`/tests (see "Staged sources").

## Configuration

| Variable | Meaning |
|---|---|
| `LEE_WALLET_HOME_DIR` | The wallet home to open in `lez_core`; default `lez_core`'s own `wallet_dir()`. |
| `LEZ_RLN_SEQUENCER` | Sequencer URL for a home this module provisions. |
| `LEZ_RLN_NETWORK` | A network from `rust-lib/networks.json`, by reference (e.g. `devnet`). Alone it provisions the home from the table; beside `LEZ_RLN_SEQUENCER` it only labels the home so a registry on another network is refused. |
| `LEZ_RLN_PAYER` | The account that pays (base58 or hex); must be an account the wallet holds. Default: the best-funded public account. |
| `LEZ_RLN_PAYER_KEY` | Ignored since 7.0.0 (`lez_core` cannot import a key); logged once if set. |

Which chain a home talks to, first match wins:

1. the home's existing `wallet_config.json` — adopted, never rewritten;
2. `LEZ_RLN_SEQUENCER` (plus `LEZ_RLN_NETWORK` as an optional label);
3. `LEZ_RLN_NETWORK` alone, looked up in the table;
4. `use_network(reference)` — `liblogos_rln_module.start` calls it with the
   reference of its first `logos` registry id. Until then `wallet_status` is
   `pending` ("no network selected …"), not `failed`.

Cases 2-4 write `network.json` beside the config whenever the network has a
name; a home bound that way is never re-pointed, and `use_network` refuses any
other reference. A home without one (staged, or `LEZ_RLN_SEQUENCER` alone) is
operator-configured and accepts any reference unchecked.

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
offsets, PDA derivation, clock decode, membership reads — against a DEPLOYED
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
- **The wallet is `lez_core`'s** (since 7.0.0; 3.0.0 to 6.x linked
  `wallet_ffi` and ran their own). A host has exactly one `lez_core` wallet
  handle, `open`/`create_new` both refuse while one is open, and there is no
  close — whoever opens first chooses the config, gas limit included. That
  was fatal while a registration needed ~9.1M gas against the stock 2M; with
  the tree off chain a Register costs ~52k and a slash ~650k, so any config
  serves, and the config this module writes declares no `gas_limit`.
- **This module opens the wallet, because nothing else will.** A delivery
  node has no wallet app. Bring-up asks `lez_core.wallet_dir()` (or takes
  `LEE_WALLET_HOME_DIR`), plans the network exactly as before, then `open`s
  the storage or `create_new`s it. A refusal is ambiguous (already open, or a
  failed open — same code), so `get_sequencer_addr` decides: a wallet open
  on this home's sequencer is adopted, one on another chain is `failed`,
  none at all is retried. No sync: the wallet serves no reads while one
  runs, a fresh one takes tens of minutes, and account reads and nonces come
  from the sequencer anyway.
- **The payer is any funded account in that wallet.** `LEZ_RLN_PAYER` if it
  names one the wallet holds; otherwise the best-funded public account,
  re-picked on every payment and every `get_native_balance("")`, so funding
  any account is noticed without a restart. With nothing funded,
  `wallet_status().payer` names one account to fund — recorded in this
  module's persistence dir (`payer.json`) so it stays put. Native balance
  enters an account only at genesis, over the bridge or by transfer: funding
  is the operator's one step.
- **Bring-up runs on its own thread.** `on_context_ready` fires on the host's
  Qt main thread and only creates the `lez_core` client; everything after is
  a call to another module. Handlers wait on a condvar for a bounded window
  and answer an empty string if it has not settled; the status method is how
  a consumer tells "still coming up" from "broken". The state lock is
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
