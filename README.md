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

## Build

Each module is its own flake; the root flake aggregates the two Rust modules:

```sh
nix build .#logos-lez-rln-module-lgx
nix build .#logos-rln-module-lgx
nix run .#inspect-module
```

The Rust modules build from gitignored staged sources — refresh with
`logos-lez-rln-module/stage-sources.sh` and
`nix run ./logos-rln-module#generate` (both clone-and-go; see each
module's README). Release bundles + package catalog: `tools/publish.sh`.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or
[Apache 2.0](./LICENSE-APACHE-v2), at your option.
