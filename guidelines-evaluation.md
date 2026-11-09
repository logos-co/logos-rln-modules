# Guidelines evaluation — `logos-rln-module` and `logos-lez-rln-module`

Against: *Best Practices for Writing Modules on `logos-rust-sdk`* (the guide with
[Verified]/[Inferred]/[Unverified] markers). Internal working document, untracked — lives only
in the working tree, like `audit-response.md`.

- Tree evaluated: branch `feat/lip-alignment` @ `967f2f0`, **with uncommitted edits** in 9
  `logos-rln-module/rust-lib/src/*.rs` files (`git status` at the time of writing). All
  `file:line` references below are working-tree lines; bare `.rs` paths are relative to
  `<module>/rust-lib/src/`. `logos-rln-membership-ui` is out of scope by request.
- Method: three independent exploration passes (one per module, one over the upstream runtime
  sources) followed by hand re-resolution of every line quoted in §B and §C. A `grep -n` recipe
  for the counts is in §F.

## 0. Scope and the one caveat that reframes the guide

Both modules build against the same upstream revs (from `logos-rln-module/flake.lock`, resolved
with `nix flake metadata`; the vendored `logos-rust-sdk-src` is byte-identical to the builder's
copy):

| Repo | Rev | Where the source is on this machine |
|---|---|---|
| logos-rust-sdk | 270e4cf6 | `logos-rln-module/logos-rust-sdk-src` (vendored) |
| logos-module-builder | 6ef42ea8 | `/nix/store/8y3y7ghgqr2bxr1ll52dywhb7qqjmrmn-8a33c11iz2cxgv7z5j2ghlk8869dl7iv-source` |
| logos-liblogos | 87ae7ce5 (2026-06-26; the copy under the builder's standalone-app chain — a module build never links liblogos. The hosts in play run f63cda38 (e2e logoscore-cli) and 4ef9736a (basecamp), both pre-ModuleStateObserver) | `/nix/store/i7prx9c5md7591pn38rvhc0f7gsnfr31-hmsdhghd11137mbs22qqpvnhg3q0jcx6-source` |
| logos-module | 75833967 | `/nix/store/yaj278w634jlqlixf9a2ghqr7nz90g0b-k8xksiad4cja0bh8blab0lip5kyzbp0i-source` |
| logos-plugin-qt | f33f264a | `/nix/store/dmfjayrbsrnn1yl4z5kfpr5v5365kwsi-047mqpzfybznsq3cfjp1qpa35iajl9yj-source` |
| logos-protocol | 976bc7a9 | `/nix/store/3rw7n6ch18y8xdwvzbd9shnw93dv58jq-source` |
| logos-qt-sdk | 6c9a0de1 | `/nix/store/lg52zg3bkaq99gd8rdq3zw7r1g3d8b3b-5fah9f3bqrya80ggi8jy7sa2d2850wvv-source` |
| logos-container-subprocess | *(unpinned in our lock; via .drv closure)* | `/nix/store/2rxcx54m6wg5k5x5dj3rp6zsy3s4s5z5-zq39vm4cwiwv98sj1ygpxp5a8p7a9blg-source` |
| logos-module-loader-qt | *(unpinned in our lock; via .drv closure)* | `/nix/store/yp880pgrpp68sl1bx4qrw134fi2q39pj-s2cymhzffnlc1kn1nncv18bwngvkxxsa-source` |

**The guide describes a newer SDK/runtime than these modules build with.** At rust-sdk
270e4cf6 the generated trait has exactly one lifecycle hook (`on_context_ready`) — there is no
`about_to_unload`, `Shutdown`, `unload_finished`, `current_caller()`, or `set_module_origin`
(zero hits for any of them across `logos-rust-sdk-src/src` and `lidl-gen/src`). At liblogos
87ae7ce5 there is no `ready` state, no `modules_state` feed, and no `error` state
(`src/logos_core/module_registry.cpp:319-353` — one `loaded` bool). Every rule that leans on
those is marked **N-A (SDK rev)** below rather than MEETS or VIOLATES; re-run this evaluation
when the pins move. **The pins moved on 2026-09-04 (branch `chore/toolchain-0.9`) — §G is the
post-bump status; §A–§F describe the pre-bump tree.**

Dated (DeepWiki, 2026-09-04): the guide matches upstream `main` as of late August 2026.
rust-sdk gained per-call timeouts on the typed client (`80d028ab`, 2026-08-03), the teardown
hooks (`49dbb076`, 2026-08-21, needs protocol 0.5) and `current_caller()` (`0fdf6a98`,
2026-08-22, needs protocol 0.6); liblogos `main` has the `ModuleStateObserver` with
`ready`/`error` states and the `modules_state` feed. Our pins predate all of it: liblogos
87ae7ce5 is from 2026-05-07, protocol 976bc7a9 and rust-sdk 270e4cf6 from 2026-06-30. §E lists
what a pin bump buys.

Both modules were switched from `"single"` to `"multi"` recently: rln at `57d0e6a`
(2026-08-29), lez at `5ce36b7` (2026-09-01). Several findings are fallout from that switch.

## A. Verdict matrix

Legend: **MEETS** / **VIOLATES** / **DEV-R** (deviates with a documented reason) / **N-A**.
The guide's marker is carried per rule: [V]erified, [I]nferred, [U]nverified (now closed in §D
where possible).

| § | Rule | rln-module | lez-rln-module |
|---|---|---|---|
| 1 [V] | Logic/adapter split: `core/` crate with no SDK dep | VIOLATES — single crate, all logic SDK-adjacent (`Cargo.toml:12-14` empty `[workspace]`) | DEV-R — `rln_core.rs` is a module, not a crate, but is SDK-free by import discipline (`rln_core.rs:4-15`), documented `lib.rs:5-7` |
| 1 [V] | Lint gates on core (`forbid(unsafe_code)`, deny `unwrap_used`…) | VIOLATES — none (`grep '^#!\['` → only the two `allow`s inside `mod generated`) | VIOLATES — none; only two narrow `#[allow(dead_code)]` (`rln_core.rs:62,72`) |
| 1 [V] | `include!` at crate root, unqualified names | MEETS (works) — `mod generated {…}` + `pub(crate) use generated::*` (`lib.rs:58-66`); see §C.3, the guide is wrong that this is unsupported | MEETS (same shape, `lib.rs:33-41`) |
| 1 [I] | Workspace-member layout builds | N-A (not used) — §D confirms it would, only with the plugin crate as root | N-A |
| 2 [V] | `[profile.release] panic = "abort"` | MEETS (`Cargo.toml:16-18`) | MEETS (`Cargo.toml:14-16`) |
| 2 [I] | Still never panic in production code | DEV-R/VIOLATES — 16 `unwrap`/`expect` in production, **9 are `.lock()`/`.read()`/`.write()` `.unwrap()`s on 3 statics + one `RwLock`** while a poison-tolerant `lock()` helper exists (`lib.rs:221`) — see B5; the rest are guarded/infallible (`proof.rs:342,373,383`, `select.rs:103`, `keychain.rs:158`) or thread-spawn (`worker.rs:188`) | VIOLATES — `lib.rs` clean; `rln_core.rs` has 7 `expect`s on chain bytes plus one **unguarded OOB path** into `rln_layouts::read_sparse_node` — see B1, B2 |
| 2 [V] | Logging via fallible `writeln!`, prefixed with module name + instance id | VIOLATES — 51 production `eprintln!`, 11 different prefixes, one bare (`lib.rs:1537`), `instance_id` never read | VIOLATES — 49 `eprintln!`, function-name prefixes only, `_ctx` discarded (`lib.rs:814`) |
| 2 [V] | Poison-tolerant locks | DEV — helper at `lib.rs:221-223`, used 40+×; bypassed at `lib.rs:578,592,1033,1143`, `keychain.rs:299`, and the `RwLock` at `lib.rs:1509,1524,1556,1573` | MEETS — helper `lib.rs:153-155` used at 100 % of author sites |
| 2 [I] | No `catch_unwind` at the boundary (inert under abort) | MEETS — none on the trait impl; 3 `catch_unwind`s on pure-Rust worker tick bodies with the reason (`poller.rs:26-28`); `panic_hook.rs:3-7` states abort makes it diagnostic-only | MEETS — none |
| 3.1 [V] | Mode chosen deliberately, code matches | MEETS on code (`metadata.json:9` multi, all receivers `&self`, `RwLock<StoreCell>` with the multi rationale `lib.rs:1500-1502`); **VIOLATES on docs** — `lib.rs:34` "Concurrency is SINGLE … no handler blocks" is stale and false (B4) | MEETS on code (`metadata.json:9`, `&self` at `lib.rs:814…1099`, `README.md:84-92`); **VIOLATES on docs** — `lib.rs:16-18` stale, contradicted by `lib.rs:190-191` in the same file (B4) |
| 3.2 [V] | Single-mode re-entrancy hazard | N-A — both modules are multi | N-A |
| 3.3 [V] | Sync outbound ⇒ multi; a sync call is a yield point | MEETS — registration is async fire-and-record (`provider.rs:494-505`); 5 handlers still block ≤70 s on reads (`lib.rs:723,840,1476,1654,1662`) + `generate_proof` on a path-cache miss (`:1241`), which is the guide's sanctioned posture for multi. CAS re-check after the yield is documented (`lib.rs:845-849`) | MEETS — every call carries an explicit timeout (60 s / 180 s, `lib.rs:45-47`); handler blocks its worker via async+channel (`lib.rs:315-341`); the sync `lp_invoke` branch (`:280-313`) is production-dead in multi |
| 3.3 [V] | Never hold a lock across an SDK call | MEETS — pointer copied out, guard dropped before every `lp_*` (`provider.rs:210-220`, `:264-266`, `:430-448`); workers call first, lock after (`path_cache.rs:39-60`, `roots.rs:154-171`) | DEV — same pattern for `lp_invoke`/`lp_invoke_async` (`lib.rs:259-268` → `:283`/`:317`); **one exception**: `init_wallet_client` holds `WALLET_CLIENT` across `lp_client_create` (`lib.rs:193-213`), load-time only, undocumented nested `WALLET_CLIENT→WALLET_OWNER` order |
| 3.3 [V] | Fine-grained atomics/mutexes, not one coarse lock | DEV-R — 18 single-purpose statics + one deliberately coarse `Store.write` (mutate→fsync→snapshot swap) documented at `store.rs:113-117`, readers served from a separate snapshot | MEETS — 3 statics, all narrow |
| 3.3 [V] | Locks not held across blocking work (the multi-mode spirit) | **VIOLATES** — `on_context_ready` holds the `store` read guard across `poller::ensure_running()` + `keychain::lazy_auto_unlock()` (Argon2id + `/usr/bin/security` spawn), `lib.rs:1573-1580`; `with_backend` holds `BACKEND` across the subprocess (`keychain.rs:153-159`). Neither is commented (B6) | MEETS |
| 3.3 [V] | Caller identity copied at the top | N-A (SDK rev) — no `current_caller()` exists; note that the chain-spending methods therefore have no caller gating at all | N-A (SDK rev) |
| 3.3 [U→V] | `emit_*` as a yield point | MEETS — both emits run after the store write returns and say so (`lib.rs:878-879`, `poller.rs:125-127`). §D shows emit is a queued post, not a nested loop | N-A — no events since 2.0.0 |
| 3.4 [V] | Callback-touched state is `Arc`/`Weak`, no `self` borrow | MEETS — callbacks capture `Weak<Store>` with a late-rejection guard (`lib.rs:487-510`, `:515-565`); raw-pointer boxes reclaimed on both paths (`provider.rs:313-314`, `:404`) | **VIOLATES** — `Box::into_raw` at `lib.rs:316` is never reclaimed when `lp_invoke_async` returns non-OK (`:327-330`) (B7). `REG_IN_FLIGHT` itself is exemplary (`lib.rs:157-182`) |
| 3.4 [V] | Listener threads torn down | N-A — no subscriptions in either module | N-A |
| 4 [V] | Every fallible method declared `result` | DEV-R — 6 `result` (rate-limiting + lifecycle) / 11 `tstr` with in-band `{"error":{class,kind,message}}`; reason: `LogosResult` nulls through the QML bridge (`.lidl:14-35`, `lib.rs:29-32`) | **VIOLATES by contract** — all 7 methods `-> tstr`, `""` on error (`.lidl:19-60`); a frozen wire convention with C++/nim consumers (see `rln-wire-format-freeze`), so a fix is a consumer-coordinated change, not a local one |
| 4 [I] | No default-on-failure returns | DEV-R — three defaults, each spec-mandated and documented (`lib.rs:1425-1432`, `:799-802`, `:1293-1299`); provider-side defaulting explicitly refused (`provider.rs:570-581`) | VIOLATES by contract — `""` at 28+ sites; every `Err(RlnError)` becomes `eprintln!` + `""` (13 sites). The tri-state `FetchOutcome` (`lib.rs:411-417`) shows the authors know where collapsing is destructive (`lib.rs:1041-1047`) |
| 4 [I] | Typed errors (`thiserror`), `?`, `From` | DEV — hand-rolled `ErrorKind` (14) + spec `class()` quartet (`lib.rs:94-158`), sub-enums mapped not stringified; messages are `String`; no `thiserror` | DEV — `RlnError` (`rln_core.rs:116-136`) typed internally, flattened at the wire |
| 5 [V] | `Default` cheap, no SDK calls | MEETS (`lib.rs:1492-1504`) | MEETS — fieldless unit struct (`lib.rs:810-811`) |
| 5 [V] | Init in `on_context_ready` | MEETS — hook, `init_client()` on the main thread, fail-closed on empty persistence path with no cwd fallback (`lib.rs:1545-1583`) | MEETS — `init_wallet_client()` with the owner-thread rationale (`lib.rs:184-191`) |
| 5 [V] | `about_to_unload` teardown, `Shutdown`, `unload_finished` not under a lock | N-A (SDK rev). Substitute: wire `stop()` → `worker::stop()` — 200 ms grace, join finished workers, detach stragglers (`worker.rs:245-268`), documented as "the one bounded deviation" (`docs/wire-binding.md:315-318`) and regression-tested (`worker.rs:427-461`). `stop()` never closes the store's dir lock or frees the lp clients | N-A (SDK rev). `WALLET_CLIENT` is process-lifetime and never destroyed (`lp_client_destroy` exists in the SDK's private `ffi.rs:46` but is not declared by the author) |
| 5 [V/U→V] | Don't assume a dependency is ready from `on_context_ready` | MEETS — no outbound call from `on_context_ready`; the poller/root refresher do the first reads on worker threads | MEETS — only `lp_client_create`, no call |
| 6 [V] | Persist only under `instance_persistence_path` | MEETS — read once (`lib.rs:1550,1570`); `wallet-home/` is a child dir. One deliberate outside write: the macOS login Keychain via `/usr/bin/security` (`keychain.rs:1-30`, env opt-out `:190`) — DEV-R | MEETS — no filesystem writes at all in production |
| 6 [I] | Atomic writes (temp + rename), abort/kill-safe | MEETS, unusually rigorous — 0600 tmp → write → fsync → rename → fsync dir (`fs.rs:14-38`), loose tier documented (`fs.rs:49-50`), dir lock (`fs.rs:125-141`). **Minor**: `wallet_home.rs:62-63` is a third, undocumented fsync-free tier | N-A |
| 6 [V] | Key files by `instance_id` | DEV-R — keyed by the directory + OS lock instead (`README.md:170-178`); keychain account = sha256 of the verbatim dir string, deliberately not canonicalized (`keychain.rs:26-28`) | N-A |
| 6 [V] | No path built from untrusted names | MEETS — all filenames are consts; caller strings are JSON keys only | N-A |
| 6 [V] | Never call `save_token`/`set_module_origin` | MEETS — only the scaffold's `accept_token` calls `save_token` | MEETS |
| 7 [V] | `generated/` never committed | MEETS — ignored (`.gitignore:6-8`), untracked | **VIOLATES** — `rust-lib/generated/provider_gen.rs` is tracked, deliberately (`README.md:29-30`), with nothing checking it against the `.lidl` (B10) |
| 7 [V] | No `build.rs`; regeneration via builder | MEETS — CI materialises it with `nix run …#generate` (`.github/workflows/rln-module.yml:40-41`) | MEETS (no `build.rs`) |
| 7 [V] | Depend only on the SDK's public surface | DEV-R — raw `extern "C"` `lp_*` re-declared (`provider.rs:40-82`) because the SDK's typed client hardcodes `timeout_ms = 0`; **reason verified** against `logos-rust-sdk-src/src/plugin.rs:271,320,412` and the private `ffi` module (`src/lib.rs:49` re-exports no timeout API). Signatures match `ffi.rs:38-61` exactly | DEV-R — same, `lib.rs:50-54`, `:70-94`; `origin = "core"` matches `plugin.rs:62` |
| 7 [V] | Full-path `Mutex` in the plugin crate | MEETS — the scaffold's `use std::sync::Mutex` is private inside `mod generated`; no clash | MEETS |
| 7 [V] | Native deps in `nix.rust.packages` | MEETS (`metadata.json:38-51`) | MEETS (+ `nix.rust.env` for `RISC0_SKIP_BUILD_KERNELS`) |
| 8 [V] | Unit tests on the core | MEETS — 165 `#[test]`, incl. 6 worker liveness/deadlock regressions (`worker.rs:318-461`) and store storm/crash-window/tamper matrices | MEETS on quality — 16 (`lib.rs` 4, `rln_core.rs` 5, `testnet_tests.rs` 7, six env-gated) |
| 8 [V] | `doctests/<module>.test.yaml` via `logos-doctest` | VIOLATES — none in the repo (the SDK ships its own; the e2e coverage lives in `logos-rln-e2e`, a different harness) | VIOLATES — none |
| 8 [V] | `lidl-gen-roundtrip` in CI | VIOLATES — none; drift risk acknowledged and answered by hand (`.lidl:48-60`, `README.md:157-159`) | VIOLATES — none, and the checked-in scaffold makes it matter more |
| 8 [V] | Crash-isolation doctest | N-A — precluded by `panic = "abort"`; and §D shows the host has no `error` state to assert on | N-A |
| 8 [V] | CI runs clippy + tests | MEETS — `clippy --all-targets -D warnings` + `cargo test --skip keychain` (18 keychain tests never run in CI, stated `rln-module.yml:52`) + nix `.lgx` build; job is named "fmt, clippy, test" but never runs `cargo fmt --check` | **VIOLATES** — `rln-module.yml` is path- and dir-scoped to rln-module (`:6-12`, `:49`, `:54`); `release.yml` is `workflow_dispatch` only with no test/clippy step. **Nothing on push/PR builds or tests this module** (B3) |
| 9 [I] | Hazard comments at lock/yield points | MEETS, above-bar (`worker.rs:154-164`, `provider.rs:11-19`, `lib.rs:567-570`, `:845-849`, `:878-879`, `path_cache.rs:1-10`, `store.rs:113-117`) — except the two sites in B6 | MEETS (`lib.rs:151-152`, `:184-191`, `:249-257`, `:332-333`, `:159-167`) — except the lock order in B8 |
| 9 [I] | `# Errors` / `# Panics` / `# Safety` sections | VIOLATES — zero crate-wide; mitigated by `staticlib` + everything `pub(crate)` (no rustdoc consumer). `unsafe impl Send` justified in `//` prose (`provider.rs:137-139`) | VIOLATES — zero; the 4 panicking `pub fn config_field_*` (`rln_core.rs:80-110`) state their precondition only in prose (`:86-87`); `unsafe impl Send for WalletHandle` (`lib.rs:146`) has no `SAFETY:` |
| misc | Version coherence | — | version skew: `metadata.json` 2.1.0 vs `Cargo.toml` 2.0.0 vs `.lidl` 2.0.0 (wire genuinely unchanged per `5ce36b7`) |

## B. Findings, ranked

Severity is judged by the guide's own frame: an abort now costs a module outage with no host
recovery (§D: crash ⇒ `loaded=false`, no error state, no auto-reload).

**B1 — lez: unvalidated chain bytes reach an unchecked indexer; malformed subtree data aborts the module.** [§2, rule I]
`rln_core.rs:216-225` calls `rln_layouts::read_sparse_node(subtree_data, …)`. `subtree_data` is
the raw hex-decoded account body from the wallet (`lib.rs:743-783` → `rln_core.rs:344-350`) and
is never length-validated (`build_merkle_proof` validates `main_data` at `:186-194`, not
`subtree_data`). At the pinned rln-layouts rev `ff02e202` (`git show ff02e202:lez-rln/rln-layouts/src/sparse.rs`),
`read_sparse_node` reads `count` from bytes 0..2 and then indexes `data[2+mid*34 .. +2]` and
`data[entry_start+2 .. +34]` with no `data.len() >= 2 + count*34` check. A truncated or
hostile subtree account → slice OOB → panic → `abort()`. `top_tree_data` (`:210-214`) has the
same shape. *Smallest fix:* one `if data.len() < 2 + count*34 { return Err(DataTooShort) }`
guard before each `read_sparse_node` call (or upstream in rln-layouts, bumping the pin).

**B2 — lez: negative `rate_limit` wraps to a huge u64 and is submitted on-chain.** [§2 arithmetic, rule I]
`register_member(…, rate_limit: i64)` arrives from the wire unvalidated and is cast at
`lib.rs:899` (`rate_limit as u64`). The sibling `claim_tokens` guards its `amount` at
`lib.rs:567-571`. Aggravating: the `REG_IN_FLIGHT` placeholder is inserted at `:882-888`
before the tx is built and only removed on build/send failure (`:905`, `:936`), so a
chain-rejected tx leaves a 300 s dedup entry. *Fix:* `u64::try_from(rate_limit)` +
range-check against the bounds the module itself publishes (`get_registry_bounds`).

**B3 — lez: no CI runs its tests or clippy.** [§8]
`.github/workflows/rln-module.yml:6-12` path-filters to `logos-rln-module/**`; its
`working-directory` is `logos-rln-module/rust-lib` (`:49`, `:54`). `release.yml` lists the
module but is `workflow_dispatch`-only and has no `cargo test`/`clippy` step. The 16 tests and
the tracked scaffold (B10) are therefore unverified on every push/PR. *Fix:* second job or a
matrix over both module dirs.

**B4 — both: crate doc headers still claim `Concurrency is SINGLE` and derive false safety claims from it.** [§3.1]
rln `lib.rs:34-36` ("…so no handler blocks on a sequencer submit") is contradicted by
`metadata.json:9`, the `&self` receivers, commit `57d0e6a`, and the five blocking reads at
`lib.rs:723,840,1476,1654,1662`. lez `lib.rs:16-18` ("dispatch runs on the module's own event
loop … wallet round-trips do not deadlock") is contradicted by `metadata.json:9`, `README.md:84`,
commit `5ce36b7`, and `lib.rs:190-191` in the same file. This is the one comment a reader would
rely on when reasoning about locks. *Fix:* rewrite both headers (rln also `lib.rs:252`-style
remnants; lez `lib.rs:252`).

**B5 — rln: three statics + the store `RwLock` are locked with `.unwrap()` (9 sites) while the crate's own poison-tolerant helper exists.** [§2]
`REGISTER_IN_FLIGHT.lock().unwrap()` at `lib.rs:578` and **inside `Drop`** at `:592`;
`LIFECYCLE` at `:1033`, `:1143`; `AUTO_UNLOCK` at `keychain.rs:299`; `self.store.read()/.write().unwrap()`
at `lib.rs:1509,1524,1556,1573`. `pub(crate) fn lock` (`lib.rs:221-223`) is used 40+ times
elsewhere with the rationale "a poisoned mutex is a bug elsewhere, not a reason to wedge every
future call". Moot under `panic=abort` in release, live in debug/test builds. *Fix:* route
through the helper; add an `RwLock` twin.

**B6 — rln: two locks held across blocking non-SDK work, uncommented.** [§3.3 spirit]
`on_context_ready` holds the `store` read guard across `poller::ensure_running()` (takes `SUP`,
spawns a thread) and `keychain::lazy_auto_unlock()` (Argon2id KDF + `/usr/bin/security`
subprocess + the `Store.write` mutex) — `lib.rs:1573-1580`. `with_backend` holds `BACKEND`
across the backend call, which for the real backend is a subprocess — `keychain.rs:153-159`.
Any concurrent dispatch that needs `store.write()` (e.g. `unlock_keystore`) waits seconds at
load. *Fix:* clone the `Arc<Store>` out of the cell, drop the guard, then run the walk; in
`with_backend`, install-then-clone the backend handle.

**B7 — lez: async-dispatch failure leaks the reply box.** [§3.4]
`lib.rs:316` `Box::into_raw(Box::new(WalletReply { tx }))`; on `rc != LP_OK` (`:327-330`) the
function returns without `Box::from_raw`. The callback never fires, so the box and its `Sender`
leak on every dispatch failure. The sibling module does it right (`provider.rs:312-314`,
"The callback will never fire; reclaim the box"). *Fix:* copy those three lines.

**B8 — lez: one lock held across FFI plus an undocumented lock order.** [§3.3]
`init_wallet_client` (`lib.rs:193-213`) holds `WALLET_CLIENT` across `lp_client_create` and
then takes `WALLET_OWNER` while still holding it; `wallet_call` takes the same pair in the same
order (`:260`, `:277`) so there is no inversion today, but nothing records the invariant. Load
time only, so low risk. *Fix:* create the client outside the lock (check-and-set after), or a
one-line lock-order comment.

**B9 — both: `eprintln!` is the only logging primitive.** [§2, rule V]
51 production sites in rln, 49 in lez, zero `println!`. `eprintln!` panics on a closed stderr,
which under `panic=abort` aborts the module — the exact failure the guide names. Neither module
prefixes with `instance_id` (`RustModuleContext.instance_id` is never read in either); rln uses
11 different subsystem prefixes, lez uses function names. *Fix:* one `log!` macro per crate over
`let _ = writeln!(std::io::stderr(), …)` with a `module:instance` prefix set in
`on_context_ready`.

**B10 — lez: the generated scaffold is committed and nothing checks it against the `.lidl`.** [§7]
`git ls-files logos-lez-rln-module/rust-lib/generated` → `provider_gen.rs`; `README.md:29-30`
says it is a checked-in copy for local `cargo check`. rln-module ignores it instead
(`.gitignore:6-8`) and has CI regenerate it. Combined with B3, `.lidl`↔scaffold drift would go
unnoticed. *Fix:* adopt the rln arrangement (ignore + `nix run …#generate` in CI).

**B11 — both: no lint gates.** [§1]
Neither crate carries `#![forbid(unsafe_code)]` (not applicable — both need `unsafe` for the raw
lp ABI, but it could be `forbid` everywhere except the one FFI module) or any
`deny(clippy::unwrap_used|expect_used|panic|indexing_slicing|arithmetic_side_effects)`. The
rln CI's `-D warnings` does not enable those lints. B1/B2/B5 are exactly what the gates catch.
Turning the five lints on for rln today yields 49 warnings (15 `unwrap`/`expect`, 24
indexing, 10 arithmetic — §F); the non-`unwrap` ones are guarded on inspection, so adoption is
a bounded `#[allow]`-with-reason pass rather than a rewrite.

**B12 — rln: fifth fsync-free write tier.** [§6, rule I] (minor)
`wallet_home.rs:62-63` does `fs::write(tmp)` + `rename` with no fsync and without
`fs::write_atomic_loose`, so it sits in neither of `fs.rs`'s two documented tiers. Write-once
config; a torn write after a crash is recoverable. *Fix:* call `write_atomic_loose`.

**B13 — rln: `stop()` does not release the store dir lock or the lp clients.** [§5] (informational)
`Store::close()` is only reachable from `open_store` (`lib.rs:1528`, `:1559`). Harmless under
process-per-module unload; would matter if unload ever became in-process.

**B14 — both: no `# Errors`/`# Panics`/`# Safety` headings anywhere.** [§9, rule I] (low)
The information exists as prose (dense, above-bar hazard comments in both). With `staticlib`
crates and everything `pub(crate)` there is no rustdoc consumer, so this is a convention gap,
not an information gap. The sharper item is `unsafe impl Send for WalletHandle` (lez
`lib.rs:146`) with no adjacent justification (it lives 40 lines away at `:184-191`).

**B15 — both: chain-spending / secret-touching methods have no caller gating.** [§3.3 caller identity] (structural)
No `current_caller()` at this SDK rev; `metadata.json` declares `"capabilities": []`. Any module
that can reach lez can call `register_member`/`claim_tokens` on the payer's funds. Not a module
defect — an SDK gap to track (§D DeepWiki item for logos-rust-sdk).

## C. Where the guide is wrong or stale for this codebase

1. **SDK-rev mismatch, not an error in the guide** (§0). `about_to_unload`/`Shutdown`/
   `unload_finished`, `current_caller()`, the `modules_state` feed and the `error` state all
   exist on upstream `main` (dated in §0) but not at the pinned revs. `set_module_origin` was
   not found on `main` either. Rules built on them are N-A here until the pins move.
2. **"The host records the module as errored"** (§2, §8 crash-isolation doctest) — true on
   liblogos `main` (`ModuleStateObserver`: crash ⇒ `loaded → error`, reason "module exited
   without being asked to"), **false at 87ae7ce5**: a crash runs `onTerminated` →
   `markUnloaded`, i.e. `loaded=false` (`module_manager.cpp:319-321`,
   `module_registry.cpp:348-353`), indistinguishable from a clean unload. Two facts hold on
   both revs: there is no auto-reload, and the crash path does **not** call
   `refreshDerivedRestrictionsForDependenciesOf` (only the deliberate-unload path does) — a
   confirmed upstream gap, so a crashed module stays an allowed caller of its dependencies.
3. **`mod generated { include!(…) }` is "not a supported pattern"** (§1) — both modules do
   exactly this with `pub(crate) use generated::*;`. The scaffold finds the install hook by
   `extern "Rust"` linkage (`rustgen_provider.rs:498-513`), and the glob re-export restores
   every unqualified name the SDK examples rely on. It is the clean way to scope `#![allow]` to
   the scaffold and should be the recommended shape.
4. **"The scaffold calls `save_token` on every entry point"** (§6) — only
   `logos_module_accept_token` does (`rustgen_provider.rs:577-588`); `dispatch`, `set_context`,
   `set_emit_callback` call `ensure_ready` only.
5. **`emit_*` as a yield point** (§3.3 [U]) — emission is a queued post (§D.1); downgrade the
   rule to: "the scaffold holds a process-wide `EMIT` mutex across the post
   (`provider_gen.rs:37-44`), so concurrent emitters serialize; don't emit under a lock a
   handler also takes".
6. **`create_dir_all` "redundant but harmless"** (§6) — the host creates the dir with
   `QDir::mkpath` and the umask default, no chmod (§D.4). A module that wants a private dir must
   `chmod 0700` it itself. rln-module creates 0600 *files* but never tightens the directory —
   worth a one-line follow-up.
7. **"20 s timeout"** (§3.2) — a call to a multi-mode target spends the timeout up to three
   times (`requestObject` + `waitForFinished` + `resolveDeferred`, §D.3) ≈ 60 s; and a
   worker-thread `lp_invoke` behind a blocked owner loop has **no** timeout at all
   (`Qt::BlockingQueuedConnection`, `logos_thread_marshal.h:43-45`). Both modules already use
   60–190 s explicit timeouts, which is consistent with this.
8. **Workspace layout** (§1 [I]) — viable only with the plugin crate as the root package: the
   builder reads the staticlib name from the root `Cargo.toml` and stages `lib<root>.a`
   (`mkLogosModule.nix:286-292`, `:403-406`), and `[profile.*]` is honoured only at the
   workspace root — moving the staticlib into `core/` would silently drop `panic=abort`.
9. **"Sync call from a single-mode handler self-deadlocks"** is now confirmed end to end.
   Scaffold: `dispatch_impl` holds `INSTANCE.0.lock()` across the handler
   (`rustgen_provider.rs:450-456`; still a blocking lock on rust-sdk `main`, no `try_lock`
   anywhere). Qt: `waitForSource`/`waitForFinished` run
   `loop.exec(ExcludeUserInputEvents | WaitForMoreEvents)`, which excludes only user-input
   events — socket reads, timers and queued metacalls are still delivered, so a second inbound
   QtRO call **is** dispatched on the waiting thread (`qremoteobjectreplica.cpp:312-342`,
   `:426-450`; `m_pendingCalls` is a hash precisely because calls resolve re-entrantly).
   Runtime: the worker-thread marshal has no timeout (still true on protocol `main`), so the
   hang is unbounded. The guide's `try_lock` + `dispatch_failed` suggestion is sound and still
   unimplemented. `logos_module_dispatch` has no `catch_unwind` on `main` either.
10. **`""`-on-error** (§4) — the guide treats it as a bug class; here it is a frozen wire
    contract with external consumers (lez `.lidl:1-10`, memory `rln-wire-format-freeze`). Flag
    it as debt with a consumer-coordinated migration, not as a local violation.

## D. [Unverified] items — closure

Every repo the guide lists as "not yet inspected" is on this machine at the exact rev the
modules build against (§0 table). Verified from source:

| # | Guide item | Verdict | Evidence |
|---|---|---|---|
| D.1 | §10.1 — does `emit_*` re-enter the event loop? | **NO.** Rust `emit_event` → C trampoline (`qt-generator/lidl_gen_cdylib_glue.cpp:230-242`) → `ModuleProxy` listener, which always `QMetaObject::invokeMethod(…, Qt::QueuedConnection)` (`protocol cpp/module_proxy.cpp:24-38`). The only `QEventLoop::exec()` in the whole runtime is the deferred-call resolver (`remote_transport.cpp:351-357`); zero `processEvents`. `lp_provider_emit_event` is a stub returning `LP_ERR_UNSUPPORTED` (`logos_protocol.cpp:416-427`) | closed |
| D.2 | §10.1 — watchdog for a hung (not unloading) module? | **PARTIAL.** Unload grace: SIGTERM + 50 ms polls for 5 s, then SIGKILL + 2 s (`subprocess_container.cpp:262-295`). Crash detection: `async_wait` → `crashed` → `spdlog::critical` → `markUnloaded` (`:228-255`, `:324-330`; `module_manager.cpp:319-321`). **Hang detection: none** — no heartbeat/timer; the `ModuleLoader` vtable has no liveness op (`module_loader.h:25-58`); `get_module_stats` is a passive pull wired to no policy | closed (answer: no) |
| D.3 | §10.2 — `lp_invoke` semantics | Main thread: inline via `runOnOwnerThread` fast path (`logos_thread_marshal.h:36-38`); blocks in `waitForSource(timeoutMs)` (`remote_transport.cpp:489-499`), `waitForFinished(timeoutMs)` (`:136`), and for a multi target `QEventLoop::exec()` with **default flags** (`:343-362`). Worker thread: `Qt::BlockingQueuedConnection` to the owner thread, **no timeout** (`logos_thread_marshal.h:43-45`), owner loop must pump (`:22-25`; regression test `tests/qt-sdk/test_worker_thread_ipc.cpp:104-117`). Handle: thread-safe with owner affinity (`logos_protocol.h:29-31`, `:142-144`); `lp_client_destroy` deletes the QObject on the calling thread (`logos_protocol.cpp:208-218`). Default 20 s (`logos_mode.h:28-31`); spent up to 3× (`logos_api_consumer.cpp:117`, `:131`). Async cb: always on the owner thread, never inline (`logos_protocol.h:176-178`, `remote_transport.cpp:75-90`) | closed except the Qt-internal wait flags |
| D.4 | §10.3 — `InstancePersistence::resolveInstance` | `instance_persistence.cpp:28-94`: `basePath/<name>/<instanceId>` with a containment check (`:80-85`), created by `QDir::mkpath` (`:87-91`) — **umask-default mode, no chmod**. Called in `loadModuleInternal` (`module_manager.cpp:258-262`) before the spawn (`:324`). Delivered as argv `--instance-persistence-path` → QObject property → `logos_module_set_context` (`qt_plugin_format_loader.cpp:75-78`, `host/module_initializer.cpp:72-76`, `lidl_gen_cdylib_glue.cpp:265-268`). **Nothing deletes it**; package uninstall removes only the install dir and refuses paths outside the module dirs (`package_manager_lib.cpp:801-832`); `ReuseOrCreate` re-adopts orphans | closed |
| D.5 | §10.4 — builder link + layout | `LogosModule.cmake:596-630`: plain `target_link_libraries`, explicitly **not** whole-archive ("the Rust install hook is pulled in lazily by a symbol reference"), protocol re-mentioned after the archive, no `-Wl` flags, nothing unwind-related → `panic=abort` staticlibs link fine. `mkLogosModule.nix:381-399`: no `--profile`/`RUSTFLAGS`/`-p`/`--workspace`; `cp -r` of the crate dir (`:370-379`); `Cargo.lock` verbatim (`:389`); `nix.rust.packages.build/runtime` → `nativeBuildInputs`/`buildInputs` (`:232-233`, `:395-396`). Workspace-member layout: see §C.8 | closed |
| D.6 | §10.5 — pre-publication inbound calls | **Rejected after a blocking wait, not buffered.** `acquireDynamic` + `waitForSource(timeoutMs)` → `nullptr` (`remote_transport.cpp:489-499`) → `object_unavailable` / `LP_ERR_UNAVAILABLE` (-4) (`logos_api_consumer.cpp:118-128`, `logos_protocol.h:74`). Only mitigation is a connect-level 50 ms retry for 5 s (`logos_api_consumer.cpp:35-52`). `markLoaded` fires right after the token pipe write (`module_manager.cpp:329-334`), before publication. `logoscore` forwards nothing; module→module goes direct over QtRO | closed except QtRO internals |
| D.7 | §5 — loaded vs ready | **No `ready` state at 87ae7ce5**; one bool (`module_registry.cpp:319-353`). Process per registry name (`subprocess_container.cpp:112`, `:474-477`); already-loaded `loadModule` is a successful no-op (`module_manager.cpp:236-246`) | closed |
| D.8 | §3.1/§4/§6 scaffold claims | Single mode holds `INSTANCE.0.lock()` across the handler (`rustgen_provider.rs:450-456`); multi clones the `Arc`, mutex guards construction only (`:205-214`); `logos_module_dispatch` has no `catch_unwind` (`:524-550`; zero hits SDK-wide); `save_token` only from `accept_token` (`:577-588`); `set_module_origin` does not exist | closed |

### DeepWiki closure (answers received 2026-09-04; each describes that repo's `main`)

| Repo | Answer | Effect on this evaluation |
|---|---|---|
| `qt/qtremoteobjects` | Both `waitForSource` and `waitForFinished` spin a nested `QEventLoop` with `ExcludeUserInputEvents \| WaitForMoreEvents` (`qremoteobjectreplica.cpp:312-342`, `:426-450`). Socket, timer and queued-metacall delivery is not excluded, so a second inbound call **can** be dispatched on the waiting thread; `notifyAboutReply` and the `m_pendingCalls` hash exist for exactly that re-entrant case | Closes D.3/D.6. Single-mode hazard confirmed at every layer (§C.9). Multi modules are unaffected as long as the main thread never calls `lp_invoke` itself — true for both (§A 3.3) |
| `logos-co/logos-container-subprocess` | No liveness or heartbeat for a loaded-but-hung process; only exit (`async_wait`) and the 5 s + 2 s kill deadlines. On crash: `spdlog::critical`, erase bookkeeping, `onTerminated` — nothing else; no restart. Our builder's rev cannot be resolved from that repo | Closes D.2 at the container layer. Rev resolved locally instead: the pinned liblogos lock carries **`logos-container-subprocess@f4860708`** (`default-container`) |
| `logos-co/logos-module-loader-qt` | After `registerObject`, `main()` writes one stdout status line via `reportLoadStatus(true)`, documented as "plugin loaded, not ready" and emitted before the event loop starts. Whether the container consumes it is outside that repo | Closes D.6's readiness half: the container does consume it (`subprocess_container.cpp` `consumeLoadStatusLine`, seen locally) and that is what `markLoaded` keys on; publication is still unobserved at our pin. Our lock carries **`logos-module-loader-qt@331760de`** |
| `logos-co/logos-liblogos` | `main` has `ModuleStateObserver` with `unloaded/loading/loaded/ready/stopping/error`; `ready` is observed via `whenObjectAvailable` after publish; crash ⇒ `loaded → error`; `modules_state` is a consumer module over it. No auto-reload. The crash path does **not** call `refreshDerivedRestrictionsForDependenciesOf` | Reframes §C.1/§C.2 as a rev mismatch; the restriction-refresh gap is a confirmed upstream bug on `main` |
| `logos-co/logos-rust-sdk` | Per-call timeout twins `80d028ab` (2026-08-03; refused, not clamped, outside 1 ms…`c_int::MAX`); teardown hooks `49dbb076` (2026-08-21, protocol 0.5); `current_caller()` `0fdf6a98` (2026-08-22, protocol 0.6). Single-mode `dispatch_impl` still blocks (no `try_lock` repo-wide); no `catch_unwind` repo-wide | Dates §0; drives §E. Both modules' raw `lp_*` re-declaration has an SDK-supported replacement upstream |
| `logos-co/logos-protocol` | `lp_provider_emit_event` still returns `LP_ERR_UNSUPPORTED`; `runOnOwnerThread` still has no timeout; the call + deferred double spend is deliberate and documented (`plain_logos_object.cpp:1257-1265`), while the acquire spend is a separate budget — only `requestModule` shares one budget (`logos_api_consumer.cpp:1290-1321`) | Confirms D.3 and §C.7 on `main`: the 3× worst case for a multi target stands |

### Still open

| Repo | Question |
|---|---|
| `logos-co/logos-module` | Is deleting `basePath/<name>/<instanceId>` the assigned responsibility of any component (package manager, logoscore), or intentionally never done? Is a directory mode tighter than the umask default planned for `InstancePersistence::resolveInstance`? |

## E. What moving the pins buys (and what it costs)

All four items below exist on upstream `main` and none at our pins. A bump is a whole-stack
move through `logos-module-builder` (rust-sdk, protocol, liblogos, qt-sdk travel together), and
two of the four are gated on a protocol version: teardown on 0.5, caller identity on 0.6.
Note also that the pinned liblogos lock carries protocol `d5d58e7e` while the module links
`976bc7a9`; check that pairing when bumping.

1. **Drop the raw `lp_*` ABI in both modules.** `call_sync_with_timeout` /
   `call_json_with_timeout` and the generated `*_with_timeout` twins (rust-sdk `80d028ab`)
   give per-call timeouts through the public surface. That removes all 20 `unsafe` sites in rln
   `provider.rs` and the 10 in lez `lib.rs`, the two hand-maintained `#[cfg(test)]` stub
   modules, and the `WalletHandle`/`ClientHandle` `unsafe impl Send`s — and makes
   `#![forbid(unsafe_code)]` possible crate-wide (§B11).
2. **Real teardown** (`49dbb076`): rln's `stop()` substitute becomes `about_to_unload` and can
   close the store's directory lock and free the lp clients (§B13); lez can destroy
   `WALLET_CLIENT` instead of leaking it by design.
3. **Caller gating** (`0fdf6a98`): `register_member` / `claim_tokens` (lez) and the
   keystore-touching methods (rln) can refuse unknown callers (§B15).
4. **Observable readiness and crashes**: the e2e harness can assert `ready` and `error` from
   the `modules_state` feed instead of inferring them, and the guide's §8 crash-isolation
   doctest becomes writable.

Unchanged by a bump: single-mode dispatch still blocks on re-entrancy, no `catch_unwind` at
the boundary, no hang detection, no auto-reload, the crash path still skips the restriction
refresh, and `lp_provider_emit_event` is still a stub (emission stays on the Qt-glue trampoline).

## F. Reproduction recipes

Production-only `unwrap`/`expect` census (the numbers in §A/§B):

```sh
# counts every .unwrap()/.expect( before the file's `mod tests` declaration
awk 'FNR==1{ if (c>0) print prev, c; c=0; skip=0; prev=FILENAME }
     /^(pub\(crate\) )?mod tests/{skip=1}
     !skip && /\.unwrap\(\)|\.expect\(/{c++}
     END{if(c>0) print prev, c}' \
  logos-rln-module/rust-lib/src/*.rs logos-rln-module/rust-lib/src/sealed_store/*.rs
# → keychain 2, lib 9, proof 4, select 1, worker 1, crypto 1  (18 raw)
#   two of those are #[cfg(test)]-gated items outside `mod tests`
#   (lib.rs:82 publish_test_store, crypto.rs's test-only helper) → 16 production sites
# lez: same command over logos-lez-rln-module/rust-lib/src/{lib,rln_core}.rs → lib 0, rln_core 7
```

Clippy census with the guide's five lints (build output only; `generated/` is present in both):

```sh
cargo clippy --manifest-path <module>/rust-lib/Cargo.toml --lib -- \
  -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic \
  -W clippy::indexing_slicing -W clippy::arithmetic_side_effects
```

Not run for lez-rln in this pass: its `rln-layouts` / `token_core` git dependencies are not in
the local cargo cache (the Nix build vendors them), so a bare `cargo clippy` first clones
`logos-execution-zone` in full. Run it inside `nix develop` or after one `cargo fetch`.

rln-module result (nightly clippy, `--lib`, so `#[cfg(test)]` code is excluded and the
`#![allow(warnings)]` on `mod generated` excludes the scaffold): **49 warnings in `src/`**.

| Lint | Count | Where |
|---|---|---|
| `unwrap_used` / `expect_used` | 15 | `lib.rs` 578, 592, 1033, 1143, 1509, 1524, 1556, 1573 (the B5 lock sites); `keychain.rs` 158, 299; `proof.rs` 342, 372, 381; `select.rs` 99; `worker.rs` 172 |
| `indexing_slicing` | 24 (22 index + 2 slice) | `registry_id.rs` 8, `lib.rs` 6, `hex.rs` 5, `worker.rs` 5 … |
| `arithmetic_side_effects` | 10 | spread over `rate_limit.rs`, `proof.rs`, `select.rs`, `format.rs`, `provider.rs`, `keychain.rs` |

The 15 `unwrap`/`expect` sites match the awk census (16 minus one `expect` clippy classifies
differently). The 34 indexing/arithmetic sites were all found guarded on inspection (§A row
2 [I]); they are the cost of adopting the guide's lint gates as `deny` — 34 rewrites or
justified `#[allow]`s, which is the review discipline §2 asks for.

`read_sparse_node` at the pinned rev:

```sh
git -C /Users/arseniy/Waku/Logos/logos-lez-rln show ff02e202:lez-rln/rln-layouts/src/sparse.rs
```

## G. Status after the 0.9 toolchain bump (2026-09-04)

Branch `chore/toolchain-0.9` = 967f2f0 + 1c45997 (pin) + 3aff8b1 (lez clippy) + f293a6b (origin
fix + doc refresh) + f6ee072 (lez CI). Pins now: builder ed9ebdac, rust-sdk 6462fd15 (crate
0.3.0), protocol 3d132f4b = 0.9.0, cpp-sdk 8d19af07, qt-sdk 5c094543. Hosts are unchanged
(logoscore-cli d015a40c / basecamp 24dfadf, liblogos f63cda38 / 4ef9736a, protocol 0.2.0).
Verified: cargo gates on 1.94.0 (rln 165/165 + clippy clean, lez 16/16 + clippy clean), both
`.lgx` bundles (13 `logos_module_*` exports, static protocol, `logos_protocol_version` 0.9.0
stamped), and seven e2e rungs PASS under the 0.2 host and the delivery v5 fork — `delivery`
(chainless), `keystore`, `register`, `delivery-rln`, `consumer-selftest`, `consumer-register`,
`consumer-gifter` (all `--target local`). The two testnet rungs are blocked by the hosted
sequencer's block-sync timeouts in the unchanged wallet, not by the modules.

### G.1 What the bump changed in the matrix

| Rule / finding | Before (§A/§B) | After the bump |
|---|---|---|
| §0 caveat "guide targets a newer SDK" | reframed a third of the rules as N-A | **Gone.** Every rule now applies at our pins; the remaining N-A rows are host-side (§C.2 still true at runtime: the 0.2 hosts have no `error`/`ready` state) |
| 3.1 stale "Concurrency is SINGLE" headers — **B4** | VIOLATES both | **FIXED** (f293a6b): rln `lib.rs` header, lez `lib.rs` header, lez `wallet_call` doc |
| 7 raw `lp_*` re-declaration — reason "SDK has no per-call timeout" | DEV-R (reason verified true) | **Reason no longer true**: `call_*_with_timeout` and the generated `_with_timeout` twins exist at 6462fd15 (35 in the rln scaffold). Still DEV — now tracked debt with the rationale comments rewritten as historical (rln `provider.rs:5-11`, lez `lib.rs:6-12`, `:51-55`). §E.1 is the follow-up |
| 7 lez `origin = "core"` (was a footnote in §A) | matched the old SDK's own hardcode | **FIXED** (f293a6b) in both raw clients: origin = generated `LOGOS_MODULE_NAME`, mirroring rust-sdk 7d2192c. This was a latent defect the bump surfaced — at 0.6+ a `"core"` origin masks the caller as Unknown and `lp_token_save("core")` overwrites the callee's host anchor. Proven against the 0.1 wallet (keystore/register rungs) and the 0.2 gifter (consumer-gifter rung) |
| 7 `set_module_origin` never called by author code | N-A (did not exist) | MEETS — the scaffold's `ensure_ready` calls it; author code does not |
| 8 lez CI — **B3** | VIOLATES (nothing built/tested lez on push) | **FIXED** (f6ee072): `lez-module.yml` — stage, SDK_REV-vs-flake.lock drift check, `clippy --locked --all-targets -D warnings`, `cargo test --locked`. Unverified until the branch is pushed and the workflow runs |
| 7 lez checked-in scaffold — **B10** | VIOLATES (drift unchecked) | **Partly mitigated**: regenerated at 0.9 and now compile-checked in CI; still no `.lidl`↔scaffold round-trip check |
| 4 `dispatch_failed`/`invalid_args` from the glue | true at the SDK but the old scaffold decayed bad args to `""`/`0` | **Now real**: strict typed decode + upper arity bound in both scaffolds. Zero-arg methods refuse any argument. Callers audited (UI passes `[]`, DM bridge arrays match the `.lidl`) |
| 3.3 caller identity — **B15** | N-A (no `current_caller()`) | **Applicable and unimplemented**: `current_caller()` exists; nothing gates `register_member`/`claim_tokens` or the keystore methods. Caveat: a caller on a 0.2 host may resolve to `Unknown`, so a gate must default-permit `Unknown` until the hosts move |
| 5 `about_to_unload` / `Shutdown` / `unload_finished` — **B13** | N-A (no hook) | **Applicable and unimplemented**: both impls take the generated default (`Shutdown::Synchronous`, no-op). rln still relies on wire `stop()` and never releases the store dir lock or the lp clients; lez never destroys `WALLET_CLIENT` |
| 8 crash-isolation doctest | N-A (abort + no host error state) | Still N-A at runtime: the hosts in play predate `ModuleStateObserver` |
| lez clippy on the builder's toolchain | not run (git deps uncached) | **Run, clean** (3aff8b1: `is_multiple_of` ×2, needless borrow, Markdown bullet; `rust-version = 1.87`). The five extra lints of §F are still not enabled |
| lez version skew | 2.1.0 / 2.0.0 / 2.0.0 | unchanged (`Cargo.toml` still 2.0.0) |

**Observed under the 0.2 host (2026-09-04, delivery-rln vs the delivery impl tips):** every
inbound dispatch into a 0.9 module logs `QMetaObject::invokeMethod: No such method
LogosAPI::currentCallerJson()` — the plugin-qt glue's by-name caller hop, absent on
logos-module-loader-qt 331760de. It degrades exactly as `logos_caller_scope.h:47-53` promises
(caller = `Unknown`, no crash), which closes the one item the wire analysis left unverified, but
it is one warning line per call until the host/loader moves — worth an upstream note
(check `indexOfMethod` before invoking) and worth knowing when reading daemon logs.

### G.2 Findings still open, unchanged by the bump

B1 (lez `read_sparse_node` OOB → abort on malformed subtree bytes), B2 (lez negative
`rate_limit` wraps — the new typed decode refuses a non-integer but a negative i64 still passes),
B5 (rln nine poison-intolerant lock sites), B6 (rln store read guard across the auto-unlock
walk, `BACKEND` across the subprocess), B7 (lez reply-box leak on `lp_invoke_async` non-OK), B8
(lez `WALLET_CLIENT` held across `lp_client_create`, undocumented lock order), B9 (`eprintln!`
everywhere, no instance id — `LOGOS_MODULE_NAME` now exists for the prefix), B11 (no lint gates),
B12 (rln `wallet_home.rs` fsync-free tier), B14 (no `# Errors`/`# Panics`/`SAFETY:`). All were
deliberately kept out of the bump PR to keep it mechanical; none is made worse by it.

### G.3 Ranked next steps

1. **B1 + B2 + B7 + B8** (lez, all small, all in `rln_core.rs`/`lib.rs`): one PR, ~30 lines.
2. **§E.1 — drop the raw `lp_*` ABI** — **DONE** on `chore/drop-raw-lp` (§H). What remains of
   this item is the §B11 lint gates as `deny` with justified `#[allow]`s (49 rln sites, mostly
   guarded indexing).
3. **`about_to_unload`** (B13): rln joins workers, closes the store (releases the dir lock),
   destroys both lp clients; lez destroys `WALLET_CLIENT`. `unload_finished` is not needed
   (synchronous teardown).
4. **Caller gating** (B15) with `Unknown` permitted until the hosts speak ≥0.6.
5. **B5/B6** (rln locks), **B9** (a `log!` macro over fallible `writeln!` with
   `LOGOS_MODULE_NAME:instance_id`), B12, B14.
6. Host-side items stay upstream: the crash path's missing restriction refresh, no hang
   detection, `lp_provider_emit_event` still a stub, single-mode `try_lock`.

## H. The raw `lp_*` ABI is gone, and the delivery tip moved (2026-09-04, evening)

Branch `chore/drop-raw-lp` = `chore/toolchain-0.9` f6ee072 + e61df09, in the scratchpad
worktree `rlnm-lp`. Question answered: **yes, both modules drop the raw lp ABI without
touching logos-delivery.** The drop is entirely on our *outbound* side (how the rln module
calls lez-rln and the gifter, how lez-rln calls the wallet); logos-delivery-module drives our
*inbound* wire, which is byte-for-byte unchanged (`.lidl`, replies, timeouts). Its own raw
slow lane and typed fast lane are DM's code and stay a follow-up there.

### H.1 What changed in the crates

| Before (§A rule 7, §B) | After e61df09 |
|---|---|
| rln `provider.rs`: hand-declared `lp_client_create/lp_invoke_async/lp_string_free`, owner-thread bookkeeping, boxed C trampolines, a stub twin of the extern block | Generated `LiblogosLezRlnModuleClient` `*_async_with_timeout` for the four reads and `register_member`; gifter via `PluginProxy::call_json_async_with_timeout`. Workers block only on an `mpsc` channel (`await_reply`); the SDK fires the callback from the module's event loop, so the loop stays free. The synchronous `*_with_timeout` twins are deliberately unused from workers (they marshal to the main thread and would serialize every call) |
| Fire-and-record contract (`register_async`: an undispatchable submit is a *synchronous* provider_failure) | Kept by `dispatch_recorded`: one mutex orders "callback fired before the SDK call returned" (→ synchronous `Err`, `on_done` not invoked) against a later reply (→ `on_done`). Four register tests pinned this; they failed until the adapter existed |
| Clients created per call / cached weakly | Strong `Arc` statics for the process lifetime (the SDK cache holds `Weak` only), warmed in `on_context_ready`; a client whose construction failed is forgotten so the next call retries |
| lez `wallet_call`: raw `lp_invoke_async` + reply box (B7 leak on non-OK) | `PluginProxy::call_json_async_with_timeout` + channel; `""`-on-error wire convention unchanged. **B7 closed** (no author-owned reply box exists any more) |
| lez B8: `WALLET_CLIENT` held across `lp_client_create` | Narrowed, not closed: creation still happens under the slot mutex, but the main thread's only take of that mutex is `init_wallet_client` in `on_context_ready` (before any worker exists), so the marshal-while-holding deadlock has no second party. Worth a one-line comment |
| 30 `unsafe` sites, two `unsafe impl Send`, two `#[cfg(test)]` extern stub twins | **Zero `unsafe` in author code.** `#![deny(unsafe_code)]` at both crate roots; `#[allow]` scoped to `mod generated` (owns the C ABI), the one `#[no_mangle]` install hook the scaffold contract requires, and a new `#[cfg(test)] mod lp_test_transport` |
| — | The test-transport module is the one new piece of `unsafe`: five `#[no_mangle] extern "C"` lp_* definitions (`lp_client_create` → NULL, invokes → -3). The SDK ships no test stubs, and the old tests only linked because the unreferenced raw externs were dead-stripped; now that the crates reach the SDK's real client path the test binary needs a link target. Upstream ask: a `cfg(test)` transport in logos-rust-sdk |
| rln `rate_limit` widening | A `rate_limit` the wire's i64 cannot carry is the caller's `invalid_argument` now, not a wrapped value (B2's rln half) |

Gates: rln 165/165 + clippy clean, lez 16/16 + clippy clean on 1.94.0. One pre-existing flake
surfaced under load: `worker::tests::stop_detaches_blocked_worker_without_duplicating_it`
(expects 3 respawns, saw 2 once while an e2e run and nix builds shared the box; 3/3 in
isolation) — a count-bounded supervisor test that should become deadline-bounded (new **B16**).

### H.2 The delivery tip, and what it forced on the e2e side

The user's note that `feat/rln-api-structure` merged to logos-delivery master and
`impl-plugable-rln-api-module` kept moving meant the compat gate had to be re-run against the
tips, not our v5 forks. Findings, all upstream facts rather than ours:

- **LD tip 85c2d6f8 does not build as committed**: `library/logos_delivery_api/rln_api.nim`
  imports `logos_delivery/waku/rln/proof`, which the restructure moved to `rln_evm/proof`.
  Fork fix 31bd16ab on `rln/integration-fixes-v6` (worktree `ld-tip`). DM tip df25eda builds
  unchanged (it pins our repo @0079db0 and builder 0.2.5; the pin only feeds the `.lidl` copy).
- **Conf keys renamed**: `rln-relay-{lez,registry-id,identifier,registry-options}` →
  `rln-{lez,registry-id,identifier,registry-options}`; the parser rejects the old spellings
  and DM sniffs `rln-lez` for the bridge auto-enable.
- **Bring-up contract changed (131fc9b1)**: the library no longer registers at startup. After
  `start` it fires `rlnGetMembershipStateRequest` for the configured scope and refuses
  START_NODE unless the state is active/grace_period ("the node does not have a usable RLN
  membership: Unknown"). DM exposes no register wire method, so **registration is the app's
  job, before the node comes up** — which is the membership UI's shape anyway. The old
  "fundless node degrades gracefully" leg is gone by design.

`logos-rln-e2e` `scenarios/delivery-rln/run.sh` follows (commit 9c5ff74): both nodes register
through `liblogos_rln_module` first, each from its own faucet-funded holding (wallet-n2 is
copied before n1 derives its account, so n1's key is not in n2's wallet — the sequencer
rejects that spend with "'user_holding' must be a signer"), wait for active, then bring
delivery up; the witness learns the new op; the assertions become "the gate asks for the
configured scope" plus the library's "RLN membership verified" line on both nodes.

### H.3 Results

| Rung (all `--target local`, delivery = LD tip+fix / DM df25eda, host logoscore-cli d015a40c) | `chore/toolchain-0.9` (baseline) | `chore/drop-raw-lp` |
|---|---|---|
| `delivery-rln` (app-side register both nodes, gate, proof-gated relay, hijack control, witness verdicts duplicate/invalid) | PASS 20260904-211743 (leaves 0/1) | PASS 20260904-213135 (leaves 0/1) |
| `keystore` | PASS (earlier ladder) | PASS 20260904-214348 |
| `register` | PASS (earlier ladder) | PASS 20260904-215549 |
| `consumer-register` (lp_subscribe consumer, tstr dialect) | PASS (earlier ladder) | PASS 20260904-220957 |
| `consumer-gifter` (delegated register through the 0.2 gifter — the `PluginProxy` path) | PASS (earlier ladder) | PASS 20260904-221931 (ACTIVE leaf 0, gifter paid) |
| `consumer-selftest --target none` | PASS | PASS 20260904-222836 |
| `delivery-rln --target testnet`, `chat-basecamp-rln` | blocked: testnet wallet block-sync timeouts | not attempted (same blocker) |

### H.4 Matrix delta and what is left

- Rule 7 (no raw `lp_*`, use the SDK client): DEV-R → **MEETS** in both crates.
- `unsafe` policy: VIOLATES (30 sites, no gate) → **MEETS** (`deny(unsafe_code)`, three scoped allows).
- B7 closed; B2's rln half closed; B8 narrowed; **B16** (flaky count-bounded supervisor test) new.
- Still open, unchanged: B1, B2 (lez half), B5, B6, B9, B11, B12, B14, B13 (`about_to_unload`:
  now also the natural place to drop the two client `Arc`s), B15 (caller gating).
- Delivery-side follow-ups (DM's raw slow lane collapse onto its typed client, the empty-error
  heuristic, a DM builder bump): **DONE** on DM `rln/toolchain-0.9` (§I). The two LD-tip
  breakages above are worth flagging upstream now (the import path, and the docs naming the
  old conf keys).

## I. The delivery-module follow-ups (2026-09-05)

The three items deferred in §H.4 — bump `logos-delivery-module` (DM) to the same builder rev the
rln modules use, collapse its raw `lp_invoke_async` slow lane onto the generated typed client,
and revisit the empty-error heuristic — are done on the DM fork branch `rln/toolchain-0.9`
(three commits on the upstream `impl-plugable-rln-api-module` tip df25eda; worktree
`scratchpad/dm-09`). Acceptance was `delivery-rln --target local` passing with the changed DM.
Nothing in `logos-delivery` (Nim) or in the rln modules changed.

### I.1 What the new toolchain actually offers a C++ consumer

The earlier plan (§E) assumed `_with_timeout` twins on the C++ side, mirroring the rust SDK.
The generator at cpp-sdk 8d19af07 does something else (`cpp-generator/generator_lib.cpp:1519-1587`,
`:1695-1770`; DM's dependency wrappers are the Qt-free `lp` surface, `parseMetadata.nix:153-156`):

- every method takes a trailing `logos::CallError* err = nullptr, int timeout_ms = 0`
  (`<= 0` = protocol default), and
- has a `<name>AsyncResult(args…, std::function<void(logos::AsyncResult<R>)>, int timeout_ms = 0)`
  twin (`cpp/logos_async_result.h`: `{value, CallError error}`), riding
  `LpClient::invokeAsyncResult` → `lp_invoke_async`, which calls back exactly once (a synchronous
  refusal is completed inline as `call_failed`);
- a provider REFUSAL — the canonical `{code, message, origin}` rejection object with code
  `dispatch_failed | invalid_args | unknown_method` — is folded into the `CallError` by the generated
  wrapper (`logosDispatchRejectionJson`), and a non-object reply decodes to `success=false` with the
  message "expected a result object, got …" (`cpp/logos_lp_client.h`, `jsonToStdResult`).

Two protocol facts fixed the design. The sync typed call is marshalled WHOLE onto the lp client's
owner thread (`logos_api_client.cpp:112-119`), and at 0.9 that owner is the Qt main thread
(`logos_protocol.cpp:245-318` constructs Qt-affine clients there). A minutes-long sync register
nested under a short validate_proof on that thread would hold the short reply hostage (nested
event loops unwind LIFO) — which is exactly why DM's raw slow lane was async. So the collapse keeps
the two lanes and only swaps the slow lane's transport: `<name>AsyncResult` + a semaphore on the lane
thread, the same shape as the old raw trampoline.

Builder side, ed9ebdac is the master tip of 2026-09-02 and still untagged (0.2.6 = 2b59cb8e still
pins protocol 0.2.0). DM's flake shape survives it unchanged: `mkLogosModule` takes the same
arguments, still exposes `packages.unit-tests` (CI) and `lgx`/`install-portable`; `logos_test()`
keywords are unchanged; the new `LOGOS_QT_HOST_ROOT` the test framework demands is supplied by the
builder. The builder still does NOT rewrite transitive dylib deps (only `install_name_tool -id`,
`lib/modulePreConfigure.nix:54`) and still joins the test RPATH with ":" — DM's darwin hooks and
its `tests/CMakeLists.txt` RPATH block stay.

### I.2 The three commits

| Commit | Change |
|---|---|
| dd9516d `chore: builder → ed9ebdac` | `flake.nix` pin by rev + re-lock of the builder input only (`logos-delivery` 78777eef and `liblogos_rln_module` 0079db0 untouched — the latter feeds only the `.lidl`, byte-identical on `chore/drop-raw-lp`). Zero source edits. The unit-test stub of the generated client (`tests/stubs/lib/liblogos_rln_module_api.h`) mirrors the new surface and answers one settable `CallError` (default `object_unavailable`). |
| 171b824 `refactor: the slow lane rides the typed client` | `register_membership` / `get_membership_state` / `generate_proof` through `<name>AsyncResult` with the same deadlines as before (190 s / 70 s / 70 s), awaited on the lane thread; fast ops pass the library's 10 s budget as `timeout_ms`. Gone: `lp_client_create/destroy`, the reply trampoline, `<logos_protocol.h>`, and `tests/mocks/mock_logos_protocol.cpp` (linked only because the bridge named `lp_*`). First unit coverage of the serve path: a bridge wired to the stub answers the tstr family in `{"error":{…}}` and the rest in the result envelope. Docs/comments stop naming the pre-rename `rln-relay-lez`. |
| 1d8f1a1 `fix: a provider refusal is permanent` | One classifier from `CallError.code`: `invalid_args | unknown_method | dispatch_failed` → `permanent` / `rln_bridge_dispatch` (a contract mismatch the library used to retry forever); `timeout | transport_error | object_unavailable | call_failed | unauthorized` → `transient` / `rln_bridge_transport` as before. The `success=false`-with-empty-error branch — the 0.2 client's only way to notice a refusal — is kept as a `permanent` `rln_bridge_decode` residue instead of a retryable one. Tests for both shapes and for timeout staying transient. |

### I.3 Results

| Gate / rung | Result |
|---|---|
| `nix build` (plugin) @ dd9516d, `logos-delivery` overridden with the staged tip | PASS — 12 `logos_module_*` exports incl. `about_to_unload`, `accept_inbound_token`, `set_call_caller`, `grant_host_services`; `logos_protocol_version` 0.9.0 stamped; no `lp_*` left undefined (protocol statically linked) |
| `nix build .#unit-tests` @ dd9516d / 171b824 / 1d8f1a1 | PASS 48 / 52 / 55 |
| `nix build` (plugin) @ 1d8f1a1 | PASS, no warnings in `rln_bridge.cpp` |
| `delivery --target none` (3 nodes: lez_core 0.4.0 + both 0.9 rln modules + the 0.9 DM under logoscore-cli d015a40c; relay both ways) | PASS (run 20260905, "3-node co-residency + relay mesh": all 4 modules loaded on 3 daemons, n1→{n2,n3} and n3→{n1,n2} delivered) |
| `delivery-rln --target local` (LD tip+fix 31bd16ab / DM `rln/toolchain-0.9`, rln modules = `chore/drop-raw-lp` e61df09) — **acceptance** | **PASS** (run 20260905-155020: app-side register n1 leaf 0 / n2 leaf 1; `start` + the membership-state gate — the collapsed slow lane's first real call — verified on both nodes inside the per-op budgets; n1 generate_proof → gossipsub → n2 validate_proof "valid" → delivered on attempt 1; witness verdicts duplicate,invalid; hijack control held) |
| testnet rungs | not attempted (same environmental blocker as §H.3) |

Bench notes (the scratchpad was wiped between sessions; every worktree had to be recreated): the
pinned `git+https://…logos-delivery?submodules=1` input cannot be fetched in reasonable time on
this link, so the gates build with `--override-input logos-delivery path:<staged tip>` — the same
tree the e2e runs against — and the LD worktree's submodules were copied from the main checkout
instead of cloned. The nix daemon does not trust this user, so the logos binary cache is ignored and
liblogosdelivery builds from source once per staged tree.

### I.4 What is left on the delivery side

- Upstream: DM `rln/toolchain-0.9` (three commits) onto `impl-plugable-rln-api-module`; the LD tip's
  import break (fork fix 31bd16ab); DM's `logos-delivery` pin (78777eef) is behind the tip it is
  developed against; `docs/rln.md` named the pre-rename key (fixed on the branch).
- Not done, by design: DM's `metadata.json` version (release-time, `docs/versioning.md`); the
  integration test's RLN config still spells the old keys because it runs against the pinned
  (older) library; the DM pytest `tests/e2e`.
- The rln-side list in §H.4 is unchanged.

## J. Standing (2026-09-05, after §G–§I)

Four waves since §A/§B: the 0.9 toolchain bump (§G), the raw `lp_*` drop (§H.1), the e2e
scenario following the delivery tip (§H.2), and the delivery-module follow-ups (§I). This
section is the roll-up; the per-wave detail stays in those sections.

### J.1 The matrix, then and now

| Rule (§A row) | §A verdict | Now | Where |
|---|---|---|---|
| 1 lint gates — `unsafe` half | VIOLATES both | **MEETS** both: `#![deny(unsafe_code)]`, three scoped allows | §H.1 |
| 1 lint gates — clippy half (`unwrap_used`, `indexing_slicing`, …) | VIOLATES both | VIOLATES both (B11; 49 rln sites to annotate) | — |
| 3.1 stale "Concurrency is SINGLE" headers (B4) | VIOLATES both | **MEETS** both | §G.1 |
| 3.3 lez lock held across `lp_client_create` (B8) | DEV | narrowed (load-time only, documented) | §H.1 |
| 3.3 caller identity | N-A (no API) | **open** — API exists, nothing gates the spending/keystore methods (B15) | §G.1 |
| 3.4 lez reply-box leak (B7) | VIOLATES | **MEETS** (no author-owned box exists) | §H.1 |
| 5 `about_to_unload` teardown | N-A (no hook) | **open** — default no-op in both (B13) | §G.1 |
| 7 raw `lp_*` re-declaration | DEV-R | **MEETS** both — SDK clients only | §H.1 |
| 7 lez `origin = "core"` | footnote | **fixed** — `LOGOS_MODULE_NAME` | §G.1 |
| 7 lez checked-in scaffold (B10) | VIOLATES | partly: regenerated at 0.9 + compile-checked in CI; no round-trip check | §G.1 |
| 8 lez CI (B3) | VIOLATES | **MEETS** on the branch (`lez-module.yml`; unverified on a push) | §G.1 |
| 8 doctests / `lidl-gen-roundtrip` in CI | VIOLATES both | VIOLATES both — untouched | — |
| 2 logging via fallible `writeln!` (B9) | VIOLATES both | VIOLATES both — untouched | — |
| everything else in §A | as stated | unchanged | — |

### J.2 Findings scoreboard

| Closed | Narrowed / partial | Open |
|---|---|---|
| B3 (lez CI), B4 (stale headers), B7 (reply-box leak), B2-rln half (`rate_limit` widening → `invalid_argument`) | B8 (lock across `lp_client_create`), B10 (scaffold compile-checked, no round-trip) | B1 (lez OOB → abort), B2-lez (negative `rate_limit`), B5 (rln poison-intolerant locks), B6 (rln locks across blocking work), B9 (`eprintln!`), B11 (lint gates), B12 (fsync-free tier), B13 (`about_to_unload`), B14 (doc headings), B15 (caller gating), **B16** (flaky count-bounded supervisor test, new in §H) |

Ranked as in §G.3, with the done item removed: (1) B1 + B2-lez + B16 — small, one PR;
(2) B13 `about_to_unload` — now also where the two client `Arc`s and the store dir lock get
released; (3) B15 caller gating with `Unknown` permitted while the hosts speak 0.2; (4) B11 as
`deny` + justified `#[allow]`s; (5) B5/B6/B9/B12/B14; (6) doctests + round-trip in CI.

### J.3 Outside the modules

- **Delivery side is caught up**: DM `rln/toolchain-0.9` (builder 0.9, typed slow lane, refusal
  classification) passes `delivery-rln --target local` against the LD tip + fork fix (§I.3). To
  flag upstream: the DM branch itself; the LD tip's `rln_evm/proof` import break (31bd16ab); DM's
  `logos-delivery` pin behind its own tip; the `currentCallerJson` warning per call under the 0.2
  host (§G.1).
- **Host-side**, unchanged and upstream: no `error`/`ready` state on the 0.2 hosts, no hang
  detection, `lp_provider_emit_event` still a stub, single-mode `try_lock` (§C/§D).
- **One DeepWiki question still open** (§D): who deletes `basePath/<name>/<instanceId>`.
- **Blocked**: the two testnet rungs (`delivery-rln --target testnet`, `chat-basecamp-rln`) on
  the hosted wallet's block-sync timeouts, not on any module change.

### J.4 Where the code sits (nothing pushed yet)

| Repo | Branch | State |
|---|---|---|
| logos-rln-modules | `feat/lip-alignment` 967f2f0 | local rebase of origin's 9 commits onto the two custody commits, plus 2 new; origin is 9 ahead / 13 behind by SHA → landing needs a force-push or a fresh branch. `origin/main` has moved (keystore #9); 16 commits of this line are not in main |
| logos-rln-modules | `chore/toolchain-0.9` f6ee072 → `chore/drop-raw-lp` e61df09 | stacked on the above; all local e2e rungs PASS (§H.3) |
| logos-rln-modules (main checkout) | working tree | 16 dirty files — the user's pending polish, never swept into any commit |
| logos-delivery-module | `rln/toolchain-0.9` 1d8f1a1 | 3 commits on upstream df25eda (§I.2) |
| logos-delivery | `rln/integration-fixes-v6` 31bd16ab | upstream tip 85c2d6f8 + the import fix |
| logos-rln-e2e | `feat/delivery-rln-acceptance` 9c5ff74 | 1 ahead of origin (the tip-contract scenario) |

## K. Upstream moved again — the delivery forks re-based (2026-09-07)

Request: "check latest changes to logos-delivery-module / logos-delivery
`impl-plugable-rln-api-module` and rebase/rework our forks to make sure they
work". Acceptance kept from §I: `delivery-rln --target local` PASS.

### K.1 What moved upstream

**logos-delivery `impl-plugable-rln-api-module`** (tip 66850a13). The branch was
REBASED: all 21 RLN commits re-hashed onto a newer main that carries the mix
sender-anonymity work (#4180, #4199), the Nimble/chronos bump (#4201: chronos
4.2.4 → 4.2.5, Nimble pinned by revision 07caee39 instead of 0.24.1+patch, the
`requires.generated` machinery gone from the Makefile, `nix/deps.nix` chronos
re-pinned) and the REST e2e workflow (#4198). Two new commits on top:

- 4091770a "More rln membership verification to first time calling attach proof":
  the membership-state gate LEAVES `startNode` and runs in `attachRlnProof`
  before the node's first proof. A pass is cached (`Waku.rlnMembershipVerified`),
  a failure is not, so the next send retries the read. `startNode` now only logs
  "RLN module started" / "RLN module start failed" and never refuses to start —
  a node without a usable membership comes up and fails its first send with
  "The node does not have a usable RLN membership: <status>" (or "Failed to
  verify RLN membership: …" on a transport failure). The "RLN membership
  verified" log line is gone.
- 66850a13 "Fix dependency import path": byte-identical to our 31bd16ab
  (`from …/waku/rln/rln_evm/proof import toRLNSignal`).

Submodule pins unchanged (zerokit 5e64cb88, waku-rlnv2-contract d9906ef4).

**logos-delivery-module `impl-plugable-rln-api-module`** df25eda → 8210137:

- 06e7c52 "Add job queue caps and timeouts per rln function type": bounded lanes
  (`kFastQueueCap` 64, `kSlowQueueCap` 8) shed new work at enqueue with a
  transient `rln_bridge_overloaded` (start/stop never shed); a dequeued job whose
  wait already exceeded the library budget — `budgetMsFor`: 200 s register,
  80 s reads, 10 s the rest, mirroring `rln_api.nim` — is answered
  `rln_bridge_expired` (transient) without serving. Touches `enqueue`/`laneLoop`
  only; the serve path is untouched.
- 471e70f: the `logos-delivery` pin 78777eef → 01ef60e1.
- 8210137: `rln-relay-lez` → `rln-lez` in comments/docs and the integration
  test's config keys (`rln-registry-id`, `rln-identifier`) — the wording fix our
  171b824 had already made on the fork.

**The DM pin dangles.** 01ef60e1 is the PRE-rebase LD tip (same 21 commits +
4091770a + the import fix, on the old base). After the upstream rebase it is not
reachable from the branch ref any more — fetchable by SHA only, so nix's
`git+https://…?ref=impl-plugable-rln-api-module&rev=01ef60e1&submodules=1`
keeps working only while GitHub retains the dangling object. Upstream flag (K.5).

### K.2 What we did

- **LD fork retired.** `rln/integration-fixes-v6` (31bd16ab) is subsumed by
  66850a13; the bench now runs the plain upstream tip through worktree branch
  `rln/tip-0907` = 66850a13 (no commits of ours). The e2e overrides the DM's
  `logos-delivery` input with that tree, so the dangling pin never matters here.
- **DM `rln/toolchain-0.9` rebased** df25eda → 8210137, same three commits:
  09cc7b7 (builder ed9ebdac; `flake.lock` merged cleanly — our builder re-lock
  and their LD re-lock touch different nodes), 3eb9a22 (typed slow lane; two
  conflicts: the header-comment wording both sides had rewritten, and the
  constants block where their queue-cap constants now sit above our
  `ReplyBox<T>`), d8423d4 (refusal classification, clean). Their queue discipline
  and our lanes compose without further edits: `enqueue`/`laneLoop`/`budgetMsFor`
  are theirs, `serveSlow`/`serveFast`/`callFail` ours, and our per-call client
  deadlines (190/70/10 s) sit under their per-op library budgets (200/80/10 s).
- **e2e scenario `delivery-rln` reworked for the moved gate** (logos-rln-e2e,
  on top of 9c5ff74): bring-up asserts "RLN module started" on both nodes and
  that n1 fires NO `rlnGetMembershipStateRequest` at start (a read there means
  the library under test predates 4091770a or moved it back); the send leg
  asserts n1's first send fires exactly one read whose registry and
  rln_identifier match the conf, BEFORE its first `rlnGenerateProofRequest`
  (event-line order), and that the read count stays 1 across every later send
  (the attempt loop and the tamper probe). `messageError` diagnostics quote the
  library's gate error text. Header comments, the witness comment and the PASS
  banner follow. Only `delivery-rln` asserted the gate; `delivery`,
  `chat-basecamp-*` and the consumer scenarios were unaffected.

### K.3 Results

| gate | result |
|------|--------|
| DM unit tests @ d8423d4 (`.#unit-tests`, LD overridden to the staged tip) | 55 passed |
| DM module lib @ d8423d4 | builds; 12 `logos_module_*` exports (0.9 set incl. `about_to_unload`, `set_call_caller`), 0 undefined `lp_*` |
| `delivery --target none` | PASS run 20260907-094717 (3 nodes, relay both ways; first attempt failed on the bench, K.4) |
| `delivery-rln --target local` | PASS run 20260907-095100: leaves 0/1; "RLN module started" on both; no read at start; n1's first send: one scoped membership read, then generate; delivered attempt 1/3; witness verdicts duplicate,invalid; hijack control. Whole-run event counts — n1: 1 start, 1 membership read, 2 generate, 2 validate; n2: 1 start, 2 validate (a receiver never reads membership) |
| `delivery-rln --target local`, rerun with the post-tamper cache assertion | PASS run 20260907-100306 — "still one read after 2 sends" (attempt 1 + tamper probe); everything else as above |

### K.4 Bench notes

- The scratchpad had been wiped again; rebuilt per the memory recipe
  (worktrees `rlnm-lp`/`dm-09`/`ld-tip`, LD submodules rsync'd from the main
  checkout — same pins —, `lez_core.lgx` repacked from run 20260905-155020,
  sequencer binary copied, `gates-dm.sh` / `ladder-dm.sh` recreated with nix on
  PATH for background shells).
- **New trap: the Xcode shims are broken after the macOS upgrade** (Darwin
  25.6). `/usr/bin/python3`, `nm`, `strings`, `otool` abort with "dlopen
  @rpath/libxcodebuildLoader.dylib … Symbol not found: _XPCTypeBool" and
  "xcode-select: Failed to locate 'python3'" because `xcode-select -p` points at
  a broken Xcode.app. The harness's `install_lgx` needs python3, so the first
  rung died with "cannot read name from …/lez_core.lgx". Fixed without touching
  system state: a shim dir first on PATH (`$S/bin/{python3,strings,nm}` →
  `/Library/Developer/CommandLineTools/usr/bin/*`, python 3.9.6 — the same
  interpreter `/usr/bin/python3` used to resolve to). The durable fix is the
  user's: `sudo xcode-select -s /Library/Developer/CommandLineTools`, or repair
  Xcode.
- Nothing pushed: DM `rln/toolchain-0.9` (local, rebased — the old SHAs
  dd9516d/171b824/1d8f1a1 are gone), LD `rln/tip-0907` (pointer only;
  `rln/integration-fixes-v6` kept but superseded), the e2e scenario commit
  efb43fa (local).

### K.5 Upstream flags (new, delivery side)

- DM's `logos-delivery` pin 01ef60e1 is off the rebased branch; re-pin to
  66850a13 (or later).
- The library no longer refuses to start without a membership. A fundless or
  unregistered node starts, and its first send surfaces "The node does not have a
  usable RLN membership" as a `messageError`. Any docs describing the start-time
  gate (DM `docs/rln.md` "bring-up", the LD conf docs) should say so; the app now
  has to treat that error as "register first, then retry".
- 06e7c52's comment calls the queue check a "stopgap until the ABI carries
  deadlines". With 0.9 the typed client carries per-call deadlines (our
  3eb9a22), so the two tables — their `budgetMsFor` (200/80/10 s) and our client
  deadlines (190/70/10 s) — could collapse into one; the queue-wait check itself
  stays useful.
- DM's integration test (`tests/test_delivery_integration.cpp`,
  `integration_rln_start_chain_round_trip`) covers the start request only, and
  only opt-in (`LOGOS_DELIVERY_RLN_LIVE`; it takes the skip path otherwise).
  Nothing on their side exercises the send-path gate — the e2e scenario is its
  only coverage.

## L. The 0.9 stack inside Basecamp (2026-09-07, afternoon)

Question (from the "how seamless is install → run → register in Basecamp"
assessment): does a protocol-0.9 delivery plugin, plus the 0.9 Rust RLN
modules, load inside Basecamp's embedded core at all? Until now every 0.9
run had been under the logoscore-cli host; the only Basecamp runs (chat, late
August) used the 0.2-builder modules.

### L.1 What was run

New e2e scenario `delivery-basecamp-rln` (logos-rln-e2e 8aa7f52), derived
from `chat-basecamp-rln` with chat removed: Basecamp (headless, dev `#app`
build with the QML inspector, throwaway `--user-dir`) gets the harness
modules dir copied in and loads `lez_core`, `liblogos_lez_rln_module`,
`liblogos_rln_module`, `delivery_module` through `backend.loadCoreModule`;
every module call goes through the inspector's `evaluate` →
`backend.callCoreModuleMethod`. No consumer app: the scenario calls
`delivery_module` directly. An ordinary logoscore daemon (n1) runs the same
four modules as receiver/validator with NO membership of its own (a receiver
never needs one since logos-delivery 4091770a).

Steps: n1 wallet + faucet claim into a fresh holding, `lez_core save`, copy of
the wallet home for Basecamp (its storage then carries the holding's
derivation; n1 never spends); n1 delivery up on the rln-* conf (bridge
auto-enabled, subscribed); Basecamp launch + load; wallet open/sync;
`liblogos_rln_module.start`; `register_membership(registry, ZERO_ID,
[rate_limit, funding_holding_account_id])` where ZERO_ID is the membership
wizard's `DEFAULT_RLN_ID` (32 zero bytes, `membership.js`) — the identifier a
Basecamp user's delivery conf has to carry; poll to `active`; `createNode` on
the same conf (registry + zero id, static peer n1) + `start`; one `send`
whose bytes payload rides the 0.9 tagged form `{"_bytes": <base64url>}`
(`logos_codec.h` `jsonToBytes`; padding tolerated); n1 `messageReceived` on
the topic with ≥1 `rlnValidateProofRequest` before it.

Bench: the Basecamp build. `nix build .#app` of the checkout (master 24dfadf,
2026-08-07) resolves to a derivation whose output is NOT in the store and the
nix daemon dropped ("Nix daemon disconnected unexpectedly") twice a few
minutes into the rebuild (during nodejs fetch / lgx-lib build). The stored dev
build `/nix/store/l3cglk9r…-logos-basecamp-0.0.0-dev` (InspectorServer
present; liblogos `pc38xxnx…`, cpp-sdk `ib5a5ygv…` per its README — the
build the August chat runs used) was gc-rooted at `$S/basecamp-app` and passed
as `BASECAMP_APP`. So the host under test is that August build, not a fresh
build of today's checkout.

### L.2 Result

**PASS**, first attempt: run `20260907-120626-delivery-basecamp-rln-local`
(delivery-module `rln/toolchain-0.9` d8423d4, logos-delivery 66850a13,
rln-modules `chore/drop-raw-lp` e61df09, local sequencer).

| leg | evidence |
|-----|----------|
| load | Basecamp log "Module loaded: delivery_module"; all four modules answer `getCoreModuleMethods` (delivery_module lists `createNode` + `rlnBridgeEnable`, liblogos_rln_module lists `register_membership`) |
| register | `register_membership` → pending → active at leaf 0 under the zero identifier, paid from the faucet-funded holding |
| run | `createNode` logged "rln served in-process" (bridge auto-enabled by `rln-lez`); library logged "RLN module started"; node reports a peer id |
| send | n1 received the message on the topic on attempt 1/3, with one `rlnValidateProofRequest` before the receipt |
| noise | 24 `QMetaObject::invokeMethod: No such method LogosAPI::currentCallerJson()` lines — the known 0.9-plugin-under-an-older-host warning (no `current_caller` on this host), harmless |

Timing: the Basecamp leg took under a minute on the local target — n1
started 18:15:51Z, Basecamp's four modules were loaded by 18:16:20Z, n1
received the message at 18:16:45Z; the wallet synced to head in seconds
(fresh sequencer).

### L.3 What this settles, and what it does not

- Settled: the 0.9 C++ delivery plugin and the 0.9 Rust RLN modules load,
  introspect and serve calls inside a Basecamp whose embedded core predates
  protocol 0.9 (the August dev build); the bridge auto-enable, the app-side
  registration under the wizard's identifier, the first-send gate and the
  proof path all work in that host. This closes the "unverified" item in the
  seamlessness assessment.
- Not settled: a Basecamp built from today's checkout (the rebuild never
  completed — daemon drops), the catalog install path (side-loaded here), and
  testnet (wallet sync; the scenario declares `TARGETS="local testnet"` and
  should run there unchanged).
- Basecamp's `getCoreModuleMethods` is the introspection seam an installer
  can use to confirm a module answers; nothing in the app surfaces the
  0.9-vs-host mismatch except the log noise above.

### L.4 Bench notes

- The stored Basecamp build must be gc-rooted (`$S/basecamp-app`) — a GC
  would remove the only host we can run without the rebuild.
- `pkill -f LogosBasecamp` before a rung; the inspector port 3768 must be
  free.
- The nix daemon drops under the Basecamp rebuild specifically (two for two);
  every other build today completed. Worth a look at the daemon's launchd log
  before relying on a fresh `#app` build.

## M. The consolidated branch on the local ladder (2026-09-07, evening)

`feat/lip-alignment` is now the single branch: four commits on origin/main
aa026dc — 93779f8 (LIP wire, rln module + membership-ui), 34d81de (lez
concurrency "multi" 2.1.0), e4dde78 (toolchain ed9ebdac, origin fix, lez
clippy + CI), 6044e3c (drop the raw `lp_*` ABI). Its tree is the old
`chore/drop-raw-lp` tree minus the 86 comment lines squashed in #10. Crate
gates: rln 165, lez 16 (`cargo +1.94.0`); the user's uncommitted polish still
passes 165 on top of it.

Local ladder against the delivery fork `rln/toolchain-0.9` d8423d4 and the
logos-delivery tip 66850a13, bench worktree at 6044e3c:

| rung | result |
|------|--------|
| `delivery --target none` | PASS 17:57 local (modules rebuilt from the consolidated tree) |
| `delivery-rln --target local` | PASS 18:07 — leaves 0/1, first-send gate once then cached, delivered attempt 1/3, witness duplicate,invalid, hijack control |
| `delivery-basecamp-rln --target local` | PASS 18:17 — 0.9 stack loaded inside Basecamp, register under the wizard's zero id, createNode + start, send received on n1 attempt 1/3 |

Superseded and never pushed: `chore/toolchain-0.9`, `chore/drop-raw-lp`.
Backups: `backup/lip-alignment-pre-rebase`, `backup/drop-raw-lp-pre-rebase`,
`backup/keystore-auto-password-pre-squash`. `origin/feat/lip-alignment` is
still at the old SHAs (force-with-lease to land). Testnet rungs not run.

## N. Upstream moved a third time — re-based and re-verified (2026-09-08)

**What moved.** logos-delivery-module `impl-plugable-rln-api-module`:
8210137 → fb88f63, one commit re-pinning `logos-delivery` to a8f7ecaf — a rev
that is, again, not on the branch (fetchable by SHA only). logos-delivery
`impl-plugable-rln-api-module`: rebased onto the 0.39 main (nim-segmentation,
nim-leopard via cmake, mix + QUIC on every library build) and five new RLN
commits: b0d61800 moves the C seam from `library/logos_delivery_api/rln_api.nim`
to `logos_delivery/waku/rln/rln_lez/transport.nim` (exports and callback
typedefs byte-identical apart from `*` exports; `library/liblogosdelivery_rln.h`
unchanged), abc53a6f **starts the module before the switch listens and makes a
start failure fatal**, then **verifies the membership at start non-fatally**
(usable → cached on the handle, else a notice; `attachRlnProof` re-verifies per
send until one passes), 25a85268 splits `RlnLezConf` from the EVM conf (wire
keys unchanged: rln-lez / rln-registry-id / rln-identifier / rln-registry-options
/ rln-relay-epoch-sec / rln-relay-user-message-limit), plus two test/import
fixes. Tip 24fc9c99.

**What we did.** DM `rln/toolchain-0.9` rebased onto fb88f63 with no conflicts
(c89a8bb, 37e2a84, 26a29d2). LD bench worktree moved to `rln/tip-0908` =
24fc9c99 (submodule pins unchanged). Scenarios reworked for the new lifecycle
(logos-rln-e2e dc94247): delivery-rln asserts the start-time read of the
configured scope, "RLN module started" + "RLN membership verified" on both
nodes, exactly one membership read for n1 across the run and before its first
generate; delivery-basecamp-rln asserts the same pass for the registered
Basecamp node and tolerates the receiver's "no usable RLN membership; sends
will fail until it is active" notice.

**Results.** DM unit tests 55 passed; DM module lib builds against the 0.39
library. Local ladder: `delivery --target none` PASS 13:57, `delivery-rln
--target local` PASS 14:07 (n1: 1 start, 1 membership read, 2 generate, 2
validate), `delivery-basecamp-rln --target local` PASS 14:17 (Basecamp: "RLN
module started" + "RLN membership verified"; n1 without a membership: started,
notice `status=Unknown`, received the message). Nothing pushed.

**Design notes from the day.** (1) `start`/`stop` are wire methods no host
calls; delivery drives `start` (right: it carries the application epoch), nobody
calls `stop` (library defines `rlnStop`, no caller; `about_to_unload` is the
scaffold no-op — B13). (2) A second consumer's `start` REPLACES the module's
CONFIG (default epoch, gap, whole overrides map) while tracked registries
accumulate — a different default epoch silently rebinds the first consumer's
registry; fix = bind epoch params per registry at track time. (3) Config
ownership: the association of a delivery preset with the registry details
belongs in logos-delivery's `NetworkPresetConf` (add `rlnLezRegistryId`; reuse
`rlnEpochSizeSec`/`rlnRelayUserMessageLimit`; `checkSetPresetValueToField`
already gives explicit-wins semantics); the identifier stays per node and comes
from the module's memberships, injected by the plugin at `createNode`; the
durable source for registry details is the lez-rln deployment pin (a
`default_registry(namespace)` on the module would serve both the wizard and
the plugin).

## O. Rebased onto igor-sirotin:bump/module-builder-crates-cdn (2026-09-08, afternoon)

**The branch.** Three commits on origin/main aa026dc: 2f01f33 relocks both module
flake.locks onto logos-module-builder 9f420c29 (2026-09-08; a descendant of our
ed9ebdac — rust-sdk 102f8677, protocol 46386344 = still 0.9.0, logos-nix
30285b10 whose `lib.nativeOverlays` carry the three crates.io-403 fixes),
ecc3882 drops the static-CDN crate prefetch from rln-module.yml, d7d3b4a sets
the rln Cargo.lock's logos-rust-sdk to 0.3.0. The rust-sdk delta since our pin is
nix wiring, a lidl-gen fix for optional_depends and tests — no `src/` API change.
The protocol delta is three fixes (token exchange waits on the caller's budget,
3-arg informModuleToken marshalled to the owner thread).

**What we did.** feat/lip-alignment rebased onto it: the only conflicts were the
two module flake.locks in our toolchain commit, resolved to Igor's. Our toolchain
commit no longer relocks anything; it now carries stage-sources.sh SDK_REV →
102f8677 (folded in), the lez scaffold (regenerated at 102f8677: byte-identical
to the 6462fd15 output), root lock, Cargo.lock (lez), flake.nix protocol-version
passing, the origin fix, lez clippy, the lez CI workflow (which never had a
prefetch step). New history: e1132f5 (LIP wire), a211174 (lez multi), 0f014fe
(toolchain, reworded), 056fa26 (drop raw lp), on d7d3b4a. Our fork of the
delivery module is untouched (its own builder pin stays ed9ebdac). Remote `igor`
added; backup `backup/lip-alignment-pre-cdn` (6044e3c) kept.

**Validation.**
| gate | result |
|------|--------|
| crate fetch wiring | `nix derivation show -r` of the rln module's `lgx` closure: 198 crate fetches from static.crates.io, 0 from crates.io (the one `crates.io` string is a template inside a builder script) |
| cargo +1.94.0 test, rust-sdk 102f8677 | rln 165 passed, lez 16 passed |
| `delivery --target none` | PASS 15:17 — both bundles rebuilt under builder 9f420c29 |
| `delivery-rln --target local` | PASS 15:27 (run 20260908-151706) |
| `delivery-basecamp-rln --target local` | PASS 15:37 (run 20260908-152729) |

Caveat: the crate FODs were already in the store from the earlier prefetch (1817
`crate-*` paths), so the ladder could not exercise a cold CDN download; the
derivation URLs are the evidence that a cold machine would fetch from the CDN.
The user's checkout inputs (lez `logos-rust-sdk-src`, rln SDK copy + scaffold)
were refreshed to 102f8677; the polish (12 files) rode the move with no
conflict. Nothing pushed; origin/feat/lip-alignment still at the old SHAs.

## P. Onto origin/main f8ab37c (2026-09-08, late afternoon)

Both of Igor's PRs merged: #12 (crates-cdn relock, plus 4e92677 relocking the
root path inputs) and #11 (Attic cache: `nixConfig` with the Logos substituter
in all four flakes, CI publish steps). feat/lip-alignment rebased onto main:
one conflict, the root flake.lock (ours vs 4e92677) → main's; our toolchain
commit no longer touches any lockfile and its message drops the root-lock
sentence. History on f8ab37c: 0e0b628 (LIP wire), 9aecf9e (lez multi), 6a0ac46
(toolchain), 370a429 (drop raw lp). Rust and every pin identical to the tree
validated in §O, so the cargo gates carry over; the flakes changed (nixConfig),
so both bundles rebuilt: `delivery --target none` PASS 15:48, `delivery-rln
--target local` PASS 15:58 (run 20260908-154846). The nixConfig substituter is
ignored locally ("untrusted user"), as before. Polish (12 files) carried across
with no conflict; backups: `backup/lip-alignment-pre-main0908` (056fa26),
`backup/lip-alignment-pre-cdn` (6044e3c). Still not pushed; origin's copy is at
the old SHAs (force-with-lease).
