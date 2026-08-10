# logos-rln-modules

The Logos RLN module stack: rate-limiting-nullifier membership for Logos
applications, backed by the on-chain RLN registry deployed from
[logos-lez-rln](https://github.com/logos-co/logos-lez-rln).

- **`logos-lez-rln-module/`** — `liblogos_lez_rln_module`, the RLN registry provider:
  chain reads (roots, merkle proofs, membership state, registry bounds), the
  Register transaction, and the faucet funding flow. See its README.
- **`logos-rln-module/`** — `liblogos_rln_module`, the
  membership management module (RLN-MEMBERSHIP-MANAGEMENT spec): credential
  generation + keystore, registration lifecycle, proof generation and
  verification. Talks to the registry only through the lez-rln module's wire.
- **`logos-rln-membership-ui/`** — the membership UI (QML) driving the two
  modules from Logos Basecamp.

## Prerequisites

- **Nix with flakes enabled** — the only hard requirement; every build
  (modules, `.lgx` bundles, UI tests, codegen) runs through the flakes.
  First builds compile zerokit and the Qt module glue, so the Logos attic
  cache helps a lot; CI gets it via `logos-co/setup-nix-cache-action`,
  which needs the `ATTIC_TOKEN_CI` / `ATTIC_TOKEN_PUBLIC` repo secrets.
- **git + network on first build** — the staging scripts clone the pinned
  `logos-rust-sdk` (cached under `~/.cache/logos-rln-modules/`), and cargo
  fetches `rln-layouts` from the pinned logos-lez-rln rev.
- **Rust (stable)** — only for bare-cargo dev loops (`cargo test` in a
  module's `rust-lib/`) after staging; the nix builds bring their own
  pinned toolchain.
- **A [logos-lez-rln] checkout** — only for the chain-facing tests: the
  module-stack e2e (`logos-rln-module/tests/e2e_register_testnet.sh`) and
  the lez module's live-registry tests (`LEZ_RLN_TESTNET_TESTS=1`) read
  deployment descriptors from `<checkout>/deployments/`. Both take
  `LEZ_RLN_CHECKOUT` and default to `../logos-lez-rln` next to this repo.
  The e2e additionally expects `jq`, `python3`, `tar`, `curl`, `openssl`,
  and `rsync` on the host.
- **Platforms** — darwin-arm64, linux-amd64, linux-arm64 (the variant set
  the release workflow publishes).

[logos-lez-rln]: https://github.com/logos-co/logos-lez-rln

## Build

Each module is its own flake; the root flake aggregates the two Rust modules:

```sh
nix build .#logos-lez-rln-module-lgx
nix build .#logos-rln-module-lgx
nix run .#inspect-rln-module      # or .#inspect-lez-rln-module
```

The Rust modules build from gitignored staged sources — refresh with
`logos-lez-rln-module/stage-sources.sh` and
`nix run ./logos-rln-module#generate` (both clone-and-go; see each
module's README). Release bundles + package catalog: `tools/publish.sh`.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or
[Apache 2.0](./LICENSE-APACHE-v2), at your option.
