# logos-rln-module — the RLN Module (Rust)

`liblogos_rln_module`, built on logos-rust-sdk /
logos-module-builder. Implements the RLN Module API (RLN-API) and the
RLN-MEMBERSHIP-MANAGEMENT spec (logos-lips `docs/anoncomms/raw/`): a
registry-agnostic API that manages RLN memberships — registration,
persistence, lifecycle — **and** generates and verifies RLN rate-limit
proofs on behalf of consuming services. Every call is scoped by a
`MembershipScope` (CAIP-10 `registry_id` + 32-byte `rln_identifier`).

Identity credentials are generated inside the module at `register`,
persisted encrypted, and used only inside `generate_proof` — the identity
secret never crosses the module boundary. Proof crypto is zerokit `rln`
(stateless) in-crate; the lez-rln registry provider (the `logos` CAIP-10
namespace) stays a wire client of the sibling
[`../logos-lez-rln-module`](../logos-lez-rln-module) for chain access (PDA
derivation, clock reads, tx submission, Merkle proofs, valid roots), and
delegated registration drives `rln_gifter_module` with the module's own
commitment. No rln-layouts / risc0 dependencies.

## Spec surface → wire methods

The RLN-API C surface maps 1:1 onto module methods (single-string args,
JSON replies; `scope` = the `registry_id` + `rln_identifier_hex` arg pair):

| Spec | Method |
|---|---|
| `start(config)` / `stop()` | `start(config_json)` / `stop()` |
| `register(scope, rate_limit, options)` | `register(registry_id, rln_identifier_hex, rate_limit, options_json)` |
| `get_membership_state(scope)` | `get_membership_state(registry_id, rln_identifier_hex)` |
| `generate_proof(scope, signal, timestamp)` | `generate_proof(registry_id, rln_identifier_hex, signal_hex, timestamp)` |
| `validate_proof(scope, signal, timestamp, proof)` | `validate_proof(registry_id, rln_identifier_hex, signal_hex, timestamp, proof_json)` |
| `get_epoch_quota(scope, timestamp)` | `get_epoch_quota(registry_id, rln_identifier_hex, timestamp)` |
| registry parameters read (optional ext.) | `get_registry_parameters(registry_id, rln_identifier_hex)` |
| membership state subscriptions (optional ext.) | `event membership_state_changed(registry_id, rln_identifier, membership_hash, state, previous)` — see `docs/wire-binding.md` |
| `RlnErrorKind` | the `class` field of every typed error object: `not_ready` \| `transient` \| `budget_exhausted` \| `permanent` |

A validator that only checks messages calls `start` + `validate_proof` and
never registers or unlocks anything. The pinned wire constructions
(`external_nullifier = poseidon(hash_to_field_le(epoch[32]),
hash_to_field_le(rln_identifier))`, where `epoch[32]` is the epoch index as
a 32-byte little-endian integer matching logos-delivery's `toEpoch`;
`x = hash_to_field_le(signal)`; and the
zerokit-canonical `RateLimitProof` bytes) are frozen by
`proof::tests::frozen_interop_vectors`.

The full contract for a consumer-side shim — reply shapes, the error `class`
quartet, state-string mapping, both accepted proof shapes, per-method time
budgets, option keys — is [`docs/wire-binding.md`](docs/wire-binding.md).

## Layout

- `metadata.json` — module manifest: `codegen.rust` drives
  logos-module-builder (lidl scaffold + typed `liblogos_lez_rln_module` client
  + Qt cdylib glue).
- `rust-lib/liblogos_rln_module.lidl` — the module contract
  (17 methods; reply/error conventions documented in the header).
- `rust-lib/deps/liblogos_lez_rln_module.lidl` — hand-maintained dependency
  contract (the consumed subset of the sibling's wire), wired via
  `dependency_overrides`. Same repo: update both files in the same PR.
- `rust-lib/src/lib.rs` — module impl: dispatch glue, error envelope,
  register/proof orchestration, start/stop lifecycle.
- `rust-lib/src/proof.rs` — the RLN proof engine over zerokit (stateless):
  in-module identity generation, witness assembly, generate/verify, the
  canonical `RateLimitProof` serialization, and the frozen interop vectors.
- `rust-lib/src/rate_limit.rs` — epoch derivation + per-(rln_identifier,
  epoch) `message_id` allocation. The store fsync-durably persists an
  allocation BEFORE the proof is returned, and keeps a persisted MONOTONE
  floor + epoch-size binding, so neither a crash, a backwards wall clock,
  nor a reconfigured `max_epoch_gap`/`epoch_size_sec` can reissue a spent
  slot (reuse would leak the identity secret via the Shamir shares) — the
  allocator answers `permanent` instead.
- `rust-lib/src/roots.rs` — the valid-root window: a background-refreshed
  per-registry cache (10s tick; >60s-stale = cold) that `validate_proof`
  serves from with no registry access on the hot path; cold = `not_ready`,
  never a false reject.
- `rust-lib/src/registry_id.rs` — CAIP-10 parse/canonicalize +
  `membership_hash` (the spec's SHA256 construction; frozen test vector).
- `rust-lib/src/sealed_store/` — the keystore: Argon2id → HKDF sub-keys →
  XChaCha20-Poly1305-sealed credentials with identity-binding AAD, an O(1)
  password verifier, per-membership + root-MAC'd allocation counters, and
  fsync-atomic 0600 file I/O. One file per trust class; the format and its
  frozen canonical encodings are documented in `docs/keystore-format.md`.
- `rust-lib/src/lifecycle.rs` — the storage-agnostic membership state
  machine: the frozen wire-state enum, merged-state view (pending→failed
  confirmation window, erased inference), change-gated transition events,
  submit-error recording policy.
- `rust-lib/src/provider.rs` — the spec's Registry Provider Interface as a
  trait + namespace routing; the lez-rln provider is a raw `lp_*` wire
  client of the sibling module (owner-thread-bound, explicit per-call
  timeouts; fire-and-record async submission), plus the lazy gifter client
  for delegated registration (`rln_gifter_module.request` driven with the
  module-generated commitment and the caller's auth-vector selection; the
  vector's producer module binds the auth payload to that commitment).
- `rust-lib/src/poller.rs` — confirmation + lifecycle poller: 15s-tick
  detached thread; pending→active with authoritative leaf/rate re-read, or
  pending→failed past the 300s window; 60s non-terminal state refresh with
  erased inference. That same 60s pass also refreshes each usable
  membership's Merkle proof path into `path_cache.rs`, so `generate_proof`
  normally serves it with zero registry I/O.
- `rust-lib/src/select.rs` — spec `select()`: active/grace_period
  candidates only, by_hash / highest_rate_limit / round_robin (rotation
  state per (registry_id, rln_identifier) scope). Returns the PUBLIC view
  only — no method releases the plaintext credential.
- `rust-lib/src/wallet_home.rs` — `provision_wallet_home()`: stakes out
  `<instance_persistence_path>/wallet-home/` with a write-once
  wallet_config.json (stage.sh's exact shape) so sandboxed UIs get wallet
  files without touching the filesystem; storage.json creation stays the
  wallet module's job.
- `rust-lib/src/keychain.rs` — `unlock_keystore_auto()` /
  `remember_keystore_password()`: macOS-Keychain-backed silent unlock via
  the `security` CLI (stdin batch writes — the secret never hits argv;
  a missing item over existing credentials never invents a secret).
  Injectable backend seam; cargo tests never touch the live keychain.
- `rust-lib/generated/provider_gen.rs` — gitignored scaffold the nix build
  regenerates; for local `cargo check`/tests, materialise it (plus the
  staged SDK source) with:
  `nix run .#generate`

## Design constraints

- **Persistence path is mandatory.** The keystore lives in
  `<instance_persistence_path>/` as three files — `rln_sealed.json`
  (encrypted credentials + header), `rln_allocations.json` (authenticated
  counters), `rln_cache.json` (registry-healed cache) — one per trust
  class (`docs/keystore-format.md`). If the host provides no path, keystore
  ops fail with an `internal` error — there is deliberately no cwd
  fallback (a keystore in an unknown directory is worse than a hard error).
  A pre-0.6.0 `rln_keystore.json` is refused with guidance, never read or
  migrated.
- **Unlock model.** Reads, lifecycle polling, selection, `get_epoch_quota`,
  and `validate_proof` never need the password (identity/cache/counter
  plaintext is locked-readable; verification uses no credential at all).
  `unlock_keystore` is required to `register` (seals the freshly generated
  credential) and to `generate_proof` (unseals it in-module for the
  witness). With zero stored credentials any password unlocks and becomes
  the store password — re-provisioning the header — until the first insert
  freezes the stored verifier; from then on unlock is exactly one Argon2id
  run checked in constant time, independent of entry count.
- **Slot allocation is persist-before-issue, and the allocator is
  monotonic.** `generate_proof` durably records the `(rln_identifier, epoch,
  message_id)` allocation before the proof leaves the module (fsync'd write —
  power-loss-safe, not merely crash-safe, on filesystems that support fsync;
  mounts that cannot sync warn loudly and degrade to crash-safe); two proofs
  on one slot reconstruct the identity secret, so a crash may waste a slot
  but never double-spends one. A persisted, monotonically non-decreasing floor (plus an epoch-size
  binding) refuses — `permanent` — any epoch a backwards clock step, a
  widened `max_epoch_gap`, or a changed `epoch_size_sec` would otherwise
  re-admit after its rows were pruned; recovery from a deliberate epoch-size
  change is a fresh registration. The epoch-size binding is adopted per
  membership at its first reservation. The allocation counters are
  authenticated from birth: attributable tamper quarantines that
  membership, unattributable tamper fails closed and quarantines every
  membership (`docs/keystore-format.md` specifies the format, the tamper
  taxonomy, and the accepted limits). One process per persistence path is
  enforced with an exclusive lock on `rln_keystore.lock`, failing closed;
  the lock is advisory, so network/shared-volume filesystems that don't
  honor OS file locks must enforce single-process at the deployment layer.
  The no-reissue guarantee is likewise per keystore INSTANCE: copying the
  keystore files to a second device forks the allocation counters, and
  concurrent use of both copies discloses the identity secret; migrate a
  keystore by moving it, never by copying. `budget_exhausted` when the
  epoch's `rate_limit` slots are gone.
- **Verification is hot-path-only.** `validate_proof` reads the locally
  maintained valid-root window and performs zero registry calls; a cold or
  stale window answers `not_ready` rather than serving a false reject.
  `start` warms the windows of its configured registries.
- **Wire conventions.** Every reply is a compact JSON object (alphabetical
  keys); failures are `{"error":{"kind":…,"message":…}}`. The sibling
  module's `""`-on-error convention is NOT used here.
- **Provisional leaf_index.** `register` returns the provider's pre-submit
  estimate; the authoritative value is re-read from the registry at the
  pending→active transition (spec MUST). Consumers needing the leaf for
  proofs should read it after the membership reports `active`.

## Staged sources (not committed)

mkLogosModule's `rustCrateSrc` stages only the crate dir plus
`logos-rust-sdk-src` into the nix sandbox:

- `logos-rust-sdk-src/` — logos-co/logos-rust-sdk at the rev this flake's
  `logos-module-builder` input pins (`flake.lock`), not a local variable.
  Bare `cargo build/test/clippy` in `rust-lib/` need it materialised too —
  see below.

Refresh (also regenerates `rust-lib/generated/provider_gen.rs`) with:

```sh
nix run .#generate
```

## Build

```sh
nix build 'path:.#default'   # plugin: result/lib/liblogos_rln_module_plugin.dylib
nix build 'path:.#lgx'       # .lgx bundle
```

## Tests

```sh
cd rust-lib && cargo test
```

Covers: CAIP-10 canonicalization vectors, the frozen membership_hash
vector, the sealed-store adversarial matrix (seal/unseal + AAD tamper,
counter tamper/splice/deletion, crash-window and concurrency storms,
persist-failure waste-not-reissue), the canonical-encoding golden vectors,
the merged-state matrix, and the empty-store verifier flow. Tests derive
keys with reduced Argon2id parameters, so the suite runs in under two
minutes.

### End-to-end registration

The chain-facing e2e — the real module stack (wallet → rln → membership) in
a logoscore daemon, a PAID registration and a full proof loop against a
live chain, plus the R2/R4 architecture diagnostics — lives in
[logos-rln-e2e](https://github.com/logos-co/logos-rln-e2e) as the
`register` scenario. `./run.sh register --target local` there boots a local
sequencer and runs it with zero external infra; `--target testnet` drives
the deployed registry.
