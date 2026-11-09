# Code-slop review — logos-rln-modules + logos-rln-e2e

Run 2026-09-09 against logos-rln-modules `feat/lip-alignment` (1c1d396) and
logos-rln-e2e `feat/delivery-rln-acceptance` (dc94247, pre-consolidation tree).

Method: 33 finder agents over 11 units x 3 category lenses -> 378 raw findings;
each then put to an adversarial refuter (default verdict: NOT valid, must find and
check the documented rationale first) and a separate value assessor; survivors ranked
per repo. **221 confirmed, 157 refuted** (~42% kill rate). Untracked working note.

## Shape of what survived

| | count |
|---|---|
| Duplicated logic or state | 57 |
| Unhelpful comments or names | 57 |
| Unnecessary machinery or repeated work | 23 |
| Excessive defensiveness | 20 |
| Low-value tests | 18 |
| Code in the wrong place | 11 |
| Unnecessary helpers | 9 |
| Dead or unrelated code | 9 |
| Too many branches | 7 |
| Unneeded backwards compatibility | 6 |
| Premature extensibility | 4 |

Worth: high 108, medium 65, low 47. 
Effort: trivial 138, small 74, medium 9.
By unit: lez-module 42, rln-proof-keystore 35, rln-runtime 30, rln-lib 21, ui-qml 21, e2e-delivery 20, ui-tests-tooling 19, e2e-app-scenarios 12, e2e-consumer 11, e2e-harness 10


## logos-rln-modules — the two Rust modules and the QML UI

### 1. `logos-rln-modules/logos-rln-module/rust-lib/src/provider.rs:328` — excessive-defensiveness (trivial)

`v.get("registered").and_then(as_bool).unwrap_or(false)` turns a malformed-but-parseable get_membership reply into the authoritative 'not registered' signal, which the poller acts on destructively (Failed / Erased 'removed_from_registry'). The sibling always emits the key and its own comment forbids collapsing a non-answer into registered:false.

**Why:** The only finding that closes a live fail-destructive path on real data: a reply object missing `registered` erases a live membership (poller.rs:216-229) or fails a pending one (poller.rs:176-196). The same function already refuses to default leaf_index/rate_limit two lines below (provider.rs:337-348) with exactly the right reasoning, so this restores an existing rule to the one field that escaped it. provider_failure leaves the record untouched (poller.rs:88-94), the intended non-answer behaviour.

**Apply:** Replace the `unwrap_or(false)` with the same shape as the `required` closure below it: `let registered = v.get("registered").and_then(|x| x.as_bool()).ok_or_else(|| ApiError::new(ErrorKind::ProviderFailure, "get_membership: missing registered"))?;`. Leave the `if !registered` early return as-is. Check: `cargo test` in logos-rln-module/rust-lib (stubbed_transport_degrades_to_provider_failure, provider.rs:541, asserts kind only); then the logos-rln-e2e `register` rung, which exercises a real lez reply carrying the key.

### 2. `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:265` — excessive-defensiveness (small)

`record.cache.leaf_index.unwrap_or(0)` defaults a usable membership's leaf to 0 in the poller's path refresh, and identically at lib.rs:1241 in generate_proof — the exact substitution provider.rs:335-338 says must never happen ('leaf 0 is a VALID leaf; defaulting would prove against the wrong membership').

**Why:** Unreachable through the store's own writers, but reachable through the unauthenticated plaintext cache (store.rs:1005-1016): today that path fetches leaf 0's Merkle path, reserves and durably burns a message_id slot, and emits a proof no verifier accepts. path_cache.rs:7-10 spells out why a stale-leaf path must not be used. Both sites are a `let ... else` away from failing loudly instead.

**Apply:** poller.rs:265: `let Some(leaf_index) = record.cache.leaf_index else { eprintln!("membership poller: {hash} usable without leaf_index — skipped"); continue };`. lib.rs:1241: replace with an `ok_or_else(|| ApiError::new(ErrorKind::UnknownMembership, "usable membership has no leaf_index"))?` before the reservation. Leave views.rs:82 and lib.rs:909 alone (the lidl view requires an int). Add one cargo test seeding an Active cache row with leaf_index None. Check: `cargo test` in logos-rln-module/rust-lib.

### 3. `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:344` — excessive-defensiveness (trivial)

merkle_proofs_exec's `.find(..).map(..).unwrap_or(&[])` silently substitutes an absent subtree for a plan/exec mismatch, producing a proof over cached default nodes instead of an error. Merged: findings [104] and [117] are the same edit.

**Why:** Both callers (lib.rs:597-612, testnet_tests.rs:356-364) push one entry per plan subtree derived from the same leaf_indices, so the miss is unreachable — but if it ever fires the module ships a wrong proof rather than the wire's "" error, contradicting lib.rs:594-596's own stated policy of never substituting 'empty' for an existing subtree. The legitimate empty-subtree case (Absent → Vec::new()) is a present entry and is unaffected.

**Apply:** Change to `.ok_or(RlnError::InvalidLeafIndex)?` (reuse the existing variant; do not add MissingSubtree unless finding [121]'s variant pass also lands). Keep the empty-slice path intact — only a MISSING map entry errors. Check: `cargo test` in logos-lez-rln-module/rust-lib, plus the gated `LEZ_RLN_TESTNET_TESTS=1 cargo test testnet_merkle_proof_recomputes_the_live_root` (the only live proof round-trip) before merge.

### 4. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:364` — excessive-defensiveness (small)

flat_bool_option's JSON-bool arm and flat_str_option's non-string arm reject values parse_registry_options (lib.rs:431-440) already made impossible — it errors on any non-string `value` and inserts only Value::String — so both arms are dead and force Result plumbing through five `?` at lib.rs:634-649. Merged: findings [4] and [17].

**Why:** Verified: register_impl is the sole consumer and the tests that pin the type-error text (lib.rs:2996, 3035) assert parse_registry_options' message at :436, not the helpers' 'options_json.{key} …' text. Making both infallible deletes two unreachable error messages, five `?`, and two doc comments that restate a rule enforced upstream; gifter_peer_id/gifter_multiaddr at :636-645 already use the plain `get().and_then(as_str)` shape, so the file stops contradicting itself.

**Apply:** `fn flat_bool_option(opts,key)->bool { opts.get(key).and_then(|v| v.as_str()) == Some("true") }` and `fn flat_str_option(opts,key)->Option<String> { opts.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from) }`; drop the five `?` at lib.rs:634-649 and shrink the docs at :359-361/:375-376 to 'values are strings by construction — see parse_registry_options'. Preserve both semantics: only "true" is truthy, "" means unset. Check: `cargo test` in logos-rln-module/rust-lib (delegated-options tests cover every surviving branch).

### 5. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:849` — too-many-branches (trivial)

get_membership_state_impl resolves the `store` Result twice: once degrading Err to empty records (:831-834), then again with a comment asserting the second `?` cannot fail ('Records exist, so the store does too.', :848-849). With Err the function always returned `unknown` at :840, so the second `?` is a dead error path.

**Why:** Confirmed by reading: an Err store yields empty records → empty candidates → early `unknown` return, so `let store = store?;` is unreachable in that case. Resolving once removes the inference the comment asks the reader to verify, with byte-identical replies on both paths and no new failure mode.

**Apply:** At the top of the fn: `let store = match store { Ok(s) => s, Err(_) => return ok_json(views::MembershipStateView::unknown(&registry.canonical)) };` (keep it AFTER provider_of at :828 so the no-store test still sees `unknown` and takes no register claim), then `let records = records_for_registry(&store, &registry);` and delete :848-849. Check: `cargo test` in logos-rln-module/rust-lib — membership_state_reads_take_no_register_claim (lib.rs:2483) drives the no_store path.

### 6. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1171` — code-in-the-wrong-place (trivial)

json_str_array/json_u8_array decode a provider get_merkle_proof reply but live in lib.rs; every call site is path_cache.rs:46,:47,:50. The doc 'Shared with path_cache.rs so cache hits and misses build identically-shaped witnesses' names a lib.rs caller that no longer exists.

**Why:** Verified by grep and by reading generate_proof's miss path (lib.rs:1251-1258), which goes through path_cache::fill_path_cache/hit. Moving both fns next to their only caller shrinks lib.rs by ~18 lines, drops two pub(crate) names, and removes a rationale that is now false — the identical-shape guarantee comes from there being one decoder inside path_cache.rs.

**Apply:** Cut lib.rs:1168-1187 into path_cache.rs above fill_path_cache as private `fn`s; drop `json_str_array, json_u8_array` from the `use crate::{...}` at path_cache.rs:17; rewrite the doc to 'Decode one field of a provider get_merkle_proof reply.' Check: `cargo test` in logos-rln-module/rust-lib (a compile pass proves no other caller).

### 7. `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:130` — unhelpful-comments (trivial)

root()'s doc says the decoded root 'serves tests' and it carries `#[cfg_attr(not(test), allow(dead_code))]`, but validate_proof_impl reads it on the production hot path (lib.rs:1389, inside the fn at :1351; `mod tests` starts at :1751) for the valid-root window check that triggers roots::nudge. Merged: findings [51], [65] and [69] are one edit.

**Why:** Read and confirmed: the attribute is inert (the symbol is live in release builds) and the doc tells the next reader the window pre-check is test-only — exactly backwards for the security-relevant fresh-root-race path. Three separate reviewers flagged it, which is itself a signal about how misleading it reads.

**Apply:** Delete the `#[cfg_attr(not(test), allow(dead_code))]` at proof.rs:134 and rewrite :130-133 to keep both true halves: 'The root the proof was generated against — validate_proof checks it against the warm valid-root window before verifying (a miss answers `invalid` and nudges the refresher); the circuit verification itself reads the root out of the canonical bytes inside zerokit.' Check: `cargo test` in logos-rln-module/rust-lib (no warning appears — the fn is live).

### 8. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/hex.rs:1` — duplicated-logic (small)

sealed_store/hex.rs is a byte-identical copy of registry_id.rs:111-139 (I diffed both: same HEX table, same trim/0x/even-length decoder), and its header rationale ('kept module-private so the sealed store's public surface stays the crypto + file layer') died when the keystore-core subcrate was folded back in. Merged: findings [55], [72] and [84].

**Why:** registry_id.rs:110 calls itself 'the crate's single hex encoder' while store.rs imports both homes side by side (store.rs:22 vs :183/:1186/:1193). One decoder guards MAC, nonce and uuid parsing; two copies is one drift point in the security-relevant file set for zero benefit. Deleting is a 3-import swap with byte-identical output.

**Apply:** `rm logos-rln-module/rust-lib/src/sealed_store/hex.rs`; drop `pub(crate) mod hex;` from sealed_store/mod.rs; repoint store.rs:22, crypto.rs:12 and format.rs:214 (test module) to `crate::registry_id::{bytes_to_hex, hex_to_vec}`. Check: `cargo test` in logos-rln-module/rust-lib — the sealed-store golden vectors (format.rs:255-268) and the unlock/MAC tests prove the encoding is unchanged.

### 9. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:31` — unnecessary-machinery (trivial)

OpenError::NoPersistencePath is constructed once (lib.rs:1575-1581) only to be `.to_string()`d through a Display that is `f.write_str(m)` — an identity round trip. Its own doc admits 'constructed by the caller — open itself always receives a dir'; nothing ever matches the variant.

**Why:** I read both sites: Store::open never returns it, tests match only DirLockHeld/OldFormatPresent/Unreadable, and the reply text is byte-identical either way. Deleting it shrinks OpenError to what `open` actually produces and removes a fake error path from the store's refusal vocabulary.

**Apply:** In lib.rs:1574-1581 assign the literal straight into `StoreCell::Unready("no instance persistence path from the host — keystore ops are disabled (no silent cwd fallback; see README)".to_string())`; delete the `NoPersistencePath` variant (store.rs:31-33) and its arm in the Display match (:42). Check: `cargo test` in logos-rln-module/rust-lib (compile-checked; no_persistence_path_reports_internal pins the message text).

### 10. `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:236` — duplicated-logic (trivial)

CacheFile::new() (lifecycle.rs:236-242) defines the cache-file header and has no caller but its own Default; write_cache (store.rs:1114-1119) rebuilds the same {format, version} pair by hand. Merged: findings [43] and [78].

**Why:** Verified both bodies: identical FORMAT_CACHE + FORMAT_VERSION stamp in two places, so a version bump has two homes and one of them is dead. The fix is a two-line struct-update expression that also lets the FORMAT_CACHE import leave store.rs:13, with identical bytes on disk.

**Apply:** store.rs:1115-1119 → `let file = CacheFile { entries: inner.cache.clone(), ..CacheFile::new() };` and drop FORMAT_CACHE from the store.rs import list; keep `impl Default` (fs.rs:95's `T: Default` bound uses it on the read side — verify with the compiler rather than deleting blind). Check: `cargo test` in logos-rln-module/rust-lib (locked_cache_updates_do_not_invalidate and the restart tests re-read the file).

### 11. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:31` — unhelpful-comments (trivial)

The crate header documents the error envelope as `{"error":{"kind":…,"message":…}}`, omitting `class` — the field consumers are told to switch on. README.md:188 repeats the stale shape while ApiError::body (lib.rs:192-201), the pinned test error_envelope_shape, the .lidl and the UI mock all carry class.

**Why:** I read lib.rs:29-32: the entry-point doc is the first thing a consumer or a new maintainer reads about the wire, and it is missing the one field docs/wire-binding.md:70-71 says to branch on. Two one-line edits with no code change.

**Apply:** Rewrite lib.rs:31 to `{"error":{"class":…,"kind":…,"message":…}}` (alphabetical key order, matching the serialized bytes) and point at `ErrorKind::class` (lib.rs:156); make the same edit at README.md:188. Check: `cargo test` in logos-rln-module/rust-lib for form; error_envelope_shape already pins the real bytes.

### 12. `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:24` — unhelpful-comments (trivial)

The poller's module doc says provider calls take `provider_call`'s async+channel path 'automatically (owner-thread contract)'. `provider_call` was deleted with the raw lp_* ABI; the name exists nowhere else in the crate, and the real contract (concurrency:"multi" worker threads + `await_reply` channel wait) is documented at provider.rs:12-21.

**Why:** Read at poller.rs:22-27 — a maintainer chasing the threading rule is sent to a symbol that does not exist and to an owner-thread model the 0.9 toolchain bump removed. Keeping one home for the threading contract is the point; this is the last dangling pointer to the old one.

**Apply:** Replace the sentence with: 'All provider calls from this worker go through provider.rs's `await_reply` (async twin + channel wait), the same path every handler takes — the worker blocks only on the channel.' Leave the surrounding catch_unwind sentence intact. Check: `cargo test` in logos-rln-module/rust-lib (doc-only).

### 13. `logos-rln-modules/logos-rln-module/rust-lib/src/views.rs:158` — unhelpful-comments (trivial)

StartReply's doc says 'all fields are always present' two lines above `#[serde(skip_serializing_if = "Option::is_none")] overrides`, and lib.rs:1113-1114 builds overrides as `(!overrides.is_empty()).then(...)` — so the common start() omits the key, exactly as docs/wire-binding.md:77 and the .lidl describe.

**Why:** Read and confirmed: the struct doc contradicts the struct itself and the two shipped contract documents. A consumer author reading the Rust source would code against a field that is usually absent.

**Apply:** Rewrite views.rs:158 to '`start`'s reply. Not a `.lidl` record; `epoch_size_sec`/`max_epoch_gap`/`registries`/`started` are always present, `overrides` only when a registries entry set per-registry values.' Check: `cargo test` in logos-rln-module/rust-lib (serialization untouched; the start-reply shape tests still pin the bytes).

### 14. `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingView.qml:20` — unhelpful-comments (trivial)

`flowController` is documented as a handle 'for the mock-bridge test harness; prod-inert', but Main.qml uses it in three production paths: the startup probe's callRetry (Main.qml:48, run from Component.onCompleted) and the two `flow:` bindings feeding MembershipView/MembershipCard's required property (Main.qml:140, :165).

**Why:** I grepped Main.qml and read all three sites. A reader who trusts 'prod-inert' could guard or delete the alias and break startup routing plus both the list and detail views. This repo uses comments as its design record, so a comment that inverts the truth about a seam is the expensive kind.

**Apply:** Reword to: 'The flow controller. Read by Main.qml (probe()'s callRetry, and the `flow` binding MembershipView/MembershipCard require) and by tests/flow-tests.mjs.' Check: no runtime surface changes; a `nix build .#integration-test` (ui-tests + flow-tests) run as part of the merge-prep sweep is enough.

### 15. `logos-rln-modules/logos-rln-membership-ui/qml/StepProgress.qml:17` — dead-code (trivial)

`readonly property string syncStatus` reproduces MembershipRow.syncState()'s wallet+sync fold clause for clause and has no reader — I grepped qml/, tests/, README.md and CLAUDE.md and the only hit is its own declaration. Merged: findings [128] and [146] (and the deletion half of [138]).

**Why:** The bar that actually paints uses MembershipRow.qml:49-55; this is a second copy of a phase rule inside the wizard that nothing consumes and that can silently drift from the one that renders. Not one of README's documented wizard/Advanced mirrors — those pair a wizard phase with an Advanced view's wire flow.

**Apply:** Delete StepProgress.qml:16-20 (the comment and the property). Leave `currentError` (:22-26) — it is read at :84/:103/:109. Check: `nix build 'path:.#integration-test'` in logos-rln-membership-ui (ui-tests + flow-tests); QML would fail loudly at load if a reader existed.

### 16. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/crypto.rs:23` — dead-code (trivial)

CryptoError::Unsupported is never constructed — its own comment says so ('Reserved for format evolution — nothing constructs it yet') — and survives behind #[allow(dead_code)] plus a Display arm. Format/version refusal already lives in store.rs:858-869/934-945 as OpenError::Unreadable. Merged: findings [63] and [83].

**Why:** The only match on CryptoError outside crypto.rs (store.rs:501-506) has an `other =>` arm, so removal breaks nothing and the error enum then lists only outcomes that can occur. A reserved-for-later variant in the crypto layer invites a future reader to route a real refusal through it instead of the OpenError path that consumers actually see.

**Apply:** Delete the variant (crypto.rs:20-23) with its `#[allow(dead_code)]`, and its arm in the Display impl (:37). Check: `cargo test` in logos-rln-module/rust-lib (compile-checked; no test references it).

### 17. `logos-rln-modules/logos-rln-module/rust-lib/src/worker.rs:276` — duplicated-logic (trivial)

`generation()` (worker.rs:275-278) and `generation_for_test()` (:129-132) are byte-identical `#[cfg(test)] pub(crate)` readers of `SUP.generation`, implying a distinction that does not exist. Merged: findings [26] and [38].

**Why:** I read both: identical bodies, both test-only, callers all inside worker.rs's own test module (:329 vs :384/:390). Keeping the `_for_test` spelling matches `nudges_for_test`/`live_worker_count` and leaves one accessor to maintain. Zero production surface, so it costs nothing to land in merge prep.

**Apply:** Delete `generation()` (worker.rs:275-278) and repoint worker.rs:384 and :390 to `generation_for_test()`. Check: `cargo test` in logos-rln-module/rust-lib — start_after_stop_respawns_with_new_generation is the consumer.

### 18. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:402` — unhelpful-comments (trivial)

`#[allow(dead_code)] // consumer surface: views read the record's flag; the tests read this` sits on a `pub fn is_quarantined` whose every caller is inside store.rs's own test module; production reads `r.quarantined` off snapshot records (lib.rs:321,720,837,960,1457; select.rs:66). Merged: findings [52] and [64].

**Why:** Read at store.rs:400-405: the comment half-claims a consumer that does not exist, and the blanket allow on a `pub` method of the keystore means the compiler will never notice if production quietly grows a dependency on it. `#[cfg(test)]` enforces the real contract and keeps all ~30 test asserts untouched.

**Apply:** Replace `#[allow(dead_code)]` + the comment with `#[cfg(test)]` on store.rs:403 (keep the method and its body). Check: `cargo test` in logos-rln-module/rust-lib plus a plain `cargo build` — a non-test build failing would prove a production caller exists.

### 19. `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:464` — unhelpful-comments (small)

Eight stderr tags say 'FFI failed'/'FFI error' (lib.rs:464,509,523,563,589,625,644,762) for plain Result errors from the in-crate `mod rln_core`, whose own header says 'plain Rust (no C ABI)'. The `use rln_core as native;` alias (lib.rs:36, testnet_tests.rs:36) carries the same fiction. Merged: [106] and [120]; ride-along [107] (`fetchAccountData` tags at :322/:328/:333/:346, `K_MAX_SNAPSHOT_ATTEMPTS` at :572).

**Why:** I grepped the eight sites and confirmed each wraps `Result<_, RlnError>` from an in-crate module; the identical strings live in the retired C++ predecessor. An operator debugging a failed register/proof is sent hunting a boundary that does not exist, and `fetchAccountData` does not grep to `fetch_account_data`. Nothing in logos-rln-e2e or any consumer matches these strings, so the rename is free.

**Apply:** Drop 'FFI' from the eight eprintln! tags ('register_plan failed', 'merkle_proofs_plan error', 'proof build failed', 'instruction encode failed'); rename the four `fetchAccountData` tags to `fetch_account_data` and `K_MAX_SNAPSHOT_ATTEMPTS` → `MAX_SNAPSHOT_ATTEMPTS`. Do the `native` → `rln_core` alias rename only as a separate mechanical commit (~75 lines) if diff noise is acceptable. Check: `cargo test` in logos-lez-rln-module/rust-lib.

### 20. `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:717` — excessive-defensiveness (trivial)

register_member's idempotency pre-check nests `if existing.len() >= 64` around decode_membership, which already returns Err(DataTooShort) for `< MEMBERSHIP_STATE_SIZE` (rln_core.rs:113,:433-436) — a magic literal restating a layout constant plus a nesting level that cannot change the outcome. Merged: [92] and [97]; ride-along [88]/[110] (fetch_account_data_quiet's one caller and its stale 'membership polls' doc).

**Why:** I read lib.rs:713-726: short data falls through to submit either way, so the branch is pure noise, and the literal 64 duplicates a constant owned by the layouts pin. Inlining the tri-state match at the same time deletes fetch_account_data_quiet, whose doc claims a caller (`membership polls`) that deliberately avoids it because the Error→Absent collapse would be destructive there.

**Apply:** Rewrite lib.rs:716-718 as `if let FetchOutcome::Present(existing) = fetch_account_data_tri_state(&membership_pda_hex) { if let Ok(membership) = native::decode_membership(&existing) { ... } }`, delete `fetch_account_data_quiet` (:302-310), and keep a one-line note that the pre-check is best-effort (Claim::Pda on chain is the real guard). Check: `cargo test` in logos-lez-rln-module/rust-lib, then the logos-rln-e2e idempotent re-register rung.

### 21. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1217` — duplicated-logic (trivial)

The timestamp freshness gate — epoch_of_timestamp → current_epoch → epoch_in_window → the same InvalidArgument text 'timestamp is outside the acceptable epoch window (now ± max_epoch_gap)' — is copy-pasted between generate_proof_impl (:1213-1222) and get_epoch_quota_impl (:1444-1451), and a test exists solely to assert the two agree.

**Why:** A rule that a test must pin as identical is a rule that wants one home. Pure extraction: same kind, same message, no wire change; validate_proof keeps its verdict-not-error path through epoch_binding_holds and is untouched.

**Apply:** Add `fn fresh_epoch(timestamp: i64, size: u64, gap: u64) -> Result<(u64, u64), ApiError>` beside the other epoch helpers; call it from both handlers AFTER epoch_params_for so the 'readiness gate FIRST' ordering (comments at :1208, :1441) survives; generate_proof keeps `now_epoch` for retain_floor. Check: `cargo test` in logos-rln-module/rust-lib — epoch_quota_rejects_bad_or_out_of_window_timestamp is the pin.

### 22. `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:758` — excessive-defensiveness (small)

register_impl round-trips the freshly generated commitment through hex — `hex_to_bytes32(&commitment_hex).ok_or_else(|| ApiError::internal("generated commitment is not 32 bytes"))?` — although proof::generate_identity returns `bytes_to_hex(&fr_to_u32(..))`, i.e. always exactly 64 hex chars from a `[u8; 32]`.

**Why:** Deletes a dead internal-error arm on the register path plus the identical re-parse in two tests (lib.rs:2561-2562, 2635). proof.rs:370's fr_to_u32 already has the bytes; returning them alongside the hex is two lines. identity_commitment is still persisted as the same LE hex, so membership_hash input stays byte-identical and the frozen registry_id vector is untouched.

**Apply:** Change `generate_identity` (proof.rs:401-410) to return the `[u8; 32]` alongside the hex; pass it straight to registry_id::membership_hash in register_impl and delete lib.rs:757-758's re-parse; update the two test call sites. Check: `cargo test` in logos-rln-module/rust-lib (registry_id's frozen vector test proves the hash input is unchanged).

### 23. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:337` — duplicated-logic (trivial)

`hex_to_vec(..).and_then(|v| <[u8; 32]>::try_from(v).ok())` is spelled out four times (store.rs:337, 955, 998, 1093-1095) although registry_id::hex_to_bytes32 is exactly that body and is already called at store.rs:183; store.rs:164 is the same shape for 16 bytes.

**Why:** I diffed hex_to_bytes32 (registry_id.rs:142-145) against the inline form: identical semantics. These four sites decode section MACs, the root MAC and mac_bytes — the parsing that guards splice detection — so one decoder rather than five is worth having, and the substitution is compile-checked.

**Apply:** Replace the four 32-byte sites with `registry_id::hex_to_bytes32(..)`; add a `hex_to_bytes16` sibling (or a const-generic `hex_to_array::<N>`) in registry_id.rs for store.rs:164. Land it together with rank 8 (the hex.rs deletion) so the imports settle once. Check: `cargo test` in logos-rln-module/rust-lib — the MAC/splice tests (store.rs:1431 etc.) exercise every site.

### 24. `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:1143` — duplicated-logic (trivial)

Snapshot.has_credentials stores `!records.is_empty()` as its own field (built at store.rs:1143, read back by has_credentials() at :390-392) although build_snapshot inserts one record per sealed credential regardless of quarantine — so the field is exactly derivable.

**Why:** One less field to keep in step inside the published snapshot, and the doc about quarantine-independence (which gates keychain auto-unlock, keychain.rs:298) moves onto the method where a reader looks for it. Snapshot is Arc-published and read-only, so deriving costs nothing.

**Apply:** Drop the field from `Snapshot` (store.rs:106-109) and its assignment (:1143-1144); make `pub fn has_credentials(&self) -> bool { !self.snapshot_arc().records.is_empty() }` carrying the existing doc. Check: `cargo test` in logos-rln-module/rust-lib (store.rs:1534 and :1983 observe the value; keychain auto-unlock tests exercise the gate).

### 25. `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:385` — unneeded-backwards-compatibility (trivial)

isTransientError's `if (typeof err === "string") return TRANSIENT_ERROR_KINDS[err] === true;` serves a `isTransientError(err.kind)` call shape that no longer exists here and that CLAUDE.md:21-23 explicitly forbids ('pass the whole error object, not err.kind').

**Why:** I read the fn and all four call sites (MembershipCard.qml:61, MembershipView.qml:58, OnboardingFlow.qml:157, :584) — every one passes the object. The only bare-kind callers are the installed plugin snapshots under registry-trial/ and gifter-local/, each shipping its own older membership.js. Removing the branch makes the code stop advertising the banned shape.

**Apply:** Delete membership.js:385-386 and its comment; keep the `!err` guard, the `class === 'transient'` check and the TRANSIENT_ERROR_KINDS fallback (that table is still the class fallback for the lez module's classless "" → empty_reply). Check: `nix build 'path:.#integration-test'` in logos-rln-membership-ui — the transient-recovery flow-test scenarios drive callRetry.

### 26. `logos-rln-modules/logos-rln-membership-ui/qml/RegisterView.qml:4` — unhelpful-comments (trivial)

RegisterView's header and the `fundingAccount` property comment (:4-5, :18) both say Main.qml wires WalletView.funded into fundingAccount; Main.qml contains no occurrence of funded/WalletView/fundingAccount. The sole writer is AdvancedView.qml:85-90's `WalletView { onFunded: ... }`.

**Why:** Confirmed by grep. In a module whose design record IS its comments, a pointer to the wrong file costs the next reader a hunt through the largest QML file — and RegisterView/WalletView are the deliberately-verbatim Advanced views where people go looking for exactly this wiring.

**Apply:** In both comments replace 'Main.qml' with "AdvancedView.qml's WalletView.onFunded" so the note names the signal, not just the file. Check: comment-only; covered by the normal `nix build 'path:.#integration-test'` sweep.

### 27. `logos-rln-modules/logos-rln-membership-ui/qml/WalletView.qml:154` — unhelpful-comments (trivial)

runSyncAttempt's comment promises 'progressTimer surfaces movement meanwhile', while the same function 20 lines later says '(the module serves no reads meanwhile)' and OnboardingFlow.qml:302-306 states the wallet serves NO reads during sync_to_block (concurrent probes starve; disconnecting mid-call can crash the module host).

**Why:** The comment sells a live progress feed that cannot exist — precisely the trap the chunked wizard path was built around. Fixing the wording is free; touching progressTimer itself is not (see demoted).

**Apply:** Reword WalletView.qml:154-157 to: 'No client timeout: a fresh wallet takes minutes. The 4s progressTimer only observes movement BETWEEN attempts — the module serves no reads while a sync_to_block is in flight.' Do NOT remove progressTimer (behaviour change in a live-proven Advanced view). Check: comment-only.

### 28. `logos-rln-modules/logos-rln-module/rust-lib/src/rate_limit.rs:225` — unhelpful-comments (trivial)

Test comments cite external audit labels — 'Audit cause B' (rate_limit.rs:225), 'Audit cause D' (:294), and in the sealed store 'L1' (store.rs:1522), '(I2b)' (:1956) and 'the suppressed-escalation reissue path' (:1431) — that resolve in no tracked file. Merged: findings [25] and [56].

**Why:** The labels point at a report that will not ship with the PR stack (only the untracked audit-*.md notes mention them, and not by definition), so an outside reviewer cannot follow them; the behavioural sentence after each label is self-contained. Matches the no-audit-refs convention already used elsewhere in this workspace.

**Apply:** Drop the label prefixes, keep the scenario sentences; for store.rs:1431 replace the bug name with the behaviour: 'a stripped or edited MAC on B must not cause A's spliced older section to be accepted.' Check: `cargo test` in logos-rln-module/rust-lib (comment-only, inside #[cfg(test)]).


**Themes**

Five patterns account for most of the confirmed slop.

1. Comments and attributes frozen at an earlier design. The code moved; the prose did not. proof.rs:130-134 still calls the production root-window input a tests-only view (and carries an inert cfg_attr) though lib.rs:1389 reads it per message; poller.rs:24 names `provider_call`, deleted with the raw lp_* ABI; views.rs:158 says "all fields are always present" directly above a skip_serializing_if; lib.rs:31 and README.md:188 omit `class` from the error envelope; keychain.rs:28 describes the pre-feea675 custody design; proof.rs:94/274 narrate a validate_proof "scan" that the timestamp wire replaced; OnboardingView.qml:20 calls a production seam "prod-inert"; RegisterView.qml:4 names the wrong wiring file; logos-lez-rln-module/rust-lib/src/lib.rs:464 and seven siblings blame an FFI boundary v2.0.0 removed, alongside "fetchAccountData" (:322) and K_MAX_SNAPSHOT_ATTEMPTS (:572). Cheap to fix and expensive to leave: this codebase uses comments as its design record.

2. Defensive fallbacks that substitute a plausible-but-wrong value where the invariant guarantees a right one. provider.rs:328 turns a reply missing `registered` into the destructive "absent" signal; poller.rs:265 and lib.rs:1241 default a usable membership's leaf to 0, the exact substitution provider.rs:335-338 forbids; rln_core.rs:344-348 substitutes an empty subtree and proves against default nodes; logos-lez-rln-module/rust-lib/src/lib.rs:487 falls back to an empty JSON map that would ship a proof containing only valid_roots. Each fires only off a broken invariant, and each then produces a wrong answer rather than the error the surrounding code already knows how to carry.

3. Dead validation left behind after the check moved upstream. flat_bool_option/flat_str_option (lib.rs:364, :382) re-enforce a type parse_registry_options already guaranteed at :431-440; lib.rs:849's `store?` cannot fail because the Err path returned at :840; select_membership_impl re-searches the same slice for the hash select_hash just returned (lib.rs:945) and generate_proof re-reads the store for it (:1240); CryptoError::Unsupported (crypto.rs:23) and OpenError::NoPersistencePath (store.rs:31) are variants nothing constructs or matches; lez lib.rs:717's `len() >= 64` restates decode_membership's own guard.

4. One fact with two homes, mostly residue of the subcrate fold-in and the module split. sealed_store/hex.rs is byte-identical to registry_id.rs:111-139 (whose doc calls itself "the crate's single hex encoder"); CacheFile::new (lifecycle.rs:236) vs the hand-built header in store.rs:1115; worker.rs:130 vs :276; the epoch freshness gate at lib.rs:1213 vs :1444; store.rs:337/955/998/1093 vs registry_id::hex_to_bytes32; the transition write and emit shared by lib.rs:869-899 and poller.rs:110-149; the PDA seed recipes at rln_core.rs:272 and :388; in the UI, StepProgress.qml:17 vs MembershipRow.qml:49 and WalletView.qml:214 vs membership.js:314.

5. Helpers and parameters whose second caller is gone. lez funding_prologue (lib.rs:419) is a "funding-method entry" with one caller since mint_tokens was dropped at v2.0.0; fetch_account_data_quiet (:305) documents a "membership polls" user that deliberately avoids it; init_wallet_client (:109) and get_valid_roots_impl (:500) are one-line forwarders; poller::ensure_running (poller.rs:46) and roots::ensure_refresher (roots.rs:104) forward to worker; records_for_registry (lib.rs:285) forwards to store.records_for; lib.rs:1171's decoders sit in the wrong file with a "shared with" rationale whose sharer disappeared.


**Demoted / not worth it**

No finding failed a spot-check; all ten I re-read held up on the cited lines.

Demoted under the frozen-wire / keystore-format / poller-worker / UI-mirror rule, where benefit did not clearly outweigh it:

- [31] persist_observation and [9] shared transition rules (poller.rs:176, lib.rs:864). The duplication and the Unknown-absent drift are real, but the fix touches consumer-visible failed_reason strings and the membership_state_changed emit, and lib.rs's CAS gate has no poller equivalent — a design decision plus e2e, not merge prep. [32] (one home for emit_transition) is the safe half to take first if this area opens.
- [40] STOPPED AtomicBool, [16] fill_path_cache's return value, [13] close_store extraction: supervisor/poller invariants or the store write lock; [16] additionally deletes an accidental stale-leaf guard on the proof path.
- [39] roots install()/adopt_hex: adopt's empty-skip vs refresh_one's install-empty is load-bearing — unifying them flips validate_proof from NOT_READY to `invalid`.
- [66][67][68][79][85] sealed-store restructures (Provisioned bundle, insert re-checks, reservation_guards, remaining_budget clone): ~10-15 touch points each in the security-critical keystore for readability, several with ordering contracts (quarantine before section lookup; Locked before any write).
- [73] fs write_via_tmp and [74] unified quarantine: the fsync ordering is that file's stated critical invariant, and the three quarantine copies differ in log text.
- [77] Section/AllocationState flatten (only its dead-derive half is safe), [42] identity_nullifier/trapdoor removal, [41]/[50] CacheFile move into format.rs. Keystore-format adjacency; [42] is byte-neutral and is the one to take if a format-touching commit happens anyway.
- [76] keeping the parsed RLNProof: the biggest hot-path win in the set (five Groth16 decompressions per validate_proof), but it edits from_json/verify — the wire-critical path — so it deserves its own change with the e2e validate rungs.
- [3]/[44] the pre-scope legacy rln_identifier branch: confirmed unreachable, but the edit spans .lidl comments, docs/wire-binding.md and the UI mock's undefined branch.
- [23] provider_failure reason text: real (timeouts report "empty reply"), but it changes wire message text and only the out-of-tree e2e harness can prove nothing asserts on it.
- [18] handler store routing, [93]/[103] lez fetch parser/owner shape, [90]/[125] PDA seed helpers, [91] config id source, [94]/[115] Vec-shaped plan, [95] token_core → rln_layouts, [102]/[116] snapshot-loop restructure, [121] RlnError variants: all defensible, all medium effort with chain-derivation, vendoring or e2e-only validation. The PDA helper pass and [95] are the two worth scheduling deliberately.
- [130] phase chaining into OnboardingFlow, [141] the unused `mnemonic` (deleting it breaks flow-tests.mjs:211's reset mirror), [131] MembershipCard raw leaf/rate (flow-tests.mjs:260 asserts the stringified form), [133] componentising the design-system workarounds, [136]/[143] the dead `timeout` kind (mirrored in the mock's CLASS_OF), [147] detailReturnMode: UI mirrors or wizard sequencing, none visible to the suite.
- [49] the `epoch_size_sec.max(1)` guard: explicitly not worth doing — churn on a security-critical file, and the guard is documented as the single division site.
- Skip as pure churn: [1][2] stale test comments, [12] records_for_registry, [20] public_membership_json, [7]/[119] LazyLock conversions (idiom drift unless all ~10 statics follow), [29][30][62][71][82][112][113][114][118]. Exception worth one commit: [58][59][60][61] (drop kdf_runs_counts_each_derive, fold the order-independence assert, drop close_then_reopen_preserves_state, fold the epoch asserts into json_roundtrip_preserves_verification) remove real suite time — Argon2 derives under the serial mutex and one Groth16 generate — not just lines.


## logos-rln-modules — tests, flakes, CI and release tooling

### 1. `logos-rln-modules/.github/workflows/rln-module.yml:56` — unhelpful-comment / lost-coverage (trivial)

`cargo test --locked -- --skip keychain` plus the comment 'drive the live macOS keychain' drops every keychain::tests case from CI; the tests inject FakeKeychain (keychain.rs:44, :382-383) and never touch the live keychain.

**Why:** Spot-checked: keychain.rs has no cfg(target_os) below line 185, so no test is macOS-only; the trait seam is the injection point. Restoring the filter gives the sealed-store/keystore-format tests their only CI platform. lez-module.yml:56 already runs unfiltered, so this is the honest sibling.

**Apply:** Delete the comment at rln-module.yml:53 and the `-- --skip keychain` suffix at :56 (leave `cargo test --locked`). Prove: `cargo test --locked` in logos-rln-module/rust-lib passes locally (tests inject the fake on macOS too), then one green rln-module.yml run on the PR.

### 2. `logos-rln-modules/tools/catalog-gen.py:19` — unhelpful-name / stale-constant (trivial)

REPO_HOMEPAGE = logos-co/logos-lez-rln (the C++ registry repo) is written into the published logos-repo.json `homepage` (:86); every other release surface names logos-rln-modules.

**Why:** Spot-checked the constant and its single use. Display metadata Basecamp shows for the catalog; release.yml regenerates logos-repo.json on every run so the fix lands on the next main release with no hash/signer involvement.

**Apply:** Change :19 to https://github.com/logos-co/logos-rln-modules (hard-coded; --base-url may be a non-GitHub host). Prove: `python3 tools/catalog-gen.py --help` still runs / a dry-run generation shows the new homepage; lands via the next release workflow run.

### 3. `logos-rln-modules/logos-rln-module/flake.nix:71` — duplicated-state (merged [1]+[8]) (trivial)

Generate app hardcodes `--concurrency multi` while the builder derives it from metadata.json ("multi"); the same flake's comment at :24-26 still says 'single default'. Same hardcode at lez flake.nix:77. [1] and [8] are one edit.

**Why:** Spot-checked all three sites: metadata.json:9 = multi, :71 = multi, :24-26 = single. Reading metadata makes the scaffold cargo tests compile against provably the one nix builds, and kills a comment that actively misleads. Output string for the multi case is unchanged, so no relock and no wire impact.

**Apply:** In both flakes read `concurrency = (builtins.fromJSON (builtins.readFile ./metadata.json)).concurrency or "single"` next to protocolVersion and emit `--concurrency multi` via lib.optionalString; replace rln flake :24-26 with the lez wording (:24-25 there). Prove: `nix run path:./logos-rln-module#generate` then diff rust-lib/generated/provider_gen.rs against the pre-change copy (identical), `cargo clippy --locked --all-targets -- -D warnings` + `cargo test --locked` in both rust-lib dirs.

### 4. `logos-rln-modules/logos-rln-membership-ui/tests/ui-tests.mjs:5` — unhelpful-comment (trivial)

Header lists the status card, post-password progression and the wizard->card handoff as 'hermetically untestable', but flow-tests.mjs in the same dir covers all three under the same `nix build .#integration-test` (:237-271, :275-289).

**Why:** Spot-checked the header text. It tells the next author to reach for the live Basecamp smoke for coverage that already exists hermetically; README.md:121-137 documents the real split. Comment-only, zero risk.

**Apply:** Rewrite :5-8: ui-tests = no-bridge static-chrome smoke (click-driven, no text-input API); state-machine coverage incl. status card, password step and handoff lives in flow-tests.mjs (mock bridge). Keep the port-pinning notes at :12-16. Prove: `nix build .#integration-test` in logos-rln-membership-ui still passes (comment only).

### 5. `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:90` — unhelpful-comment (trivial)

Comment cites 'docs/wire-binding.md "Error envelope"' as if local to the UI; the UI has no docs/ and the section is logos-rln-module/docs/wire-binding.md:50.

**Why:** Spot-checked: `ls logos-rln-membership-ui/docs` fails, section exists in the module docs. House phrasing is 'the module's docs/wire-binding.md' (README.md:83,:87; qml/membership.js:186). The file is already modified on this branch, so it rides free.

**Apply:** Change :90 to '(the module's docs/wire-binding.md "Error envelope")'. Prove: flow-tests still run under `nix build .#integration-test` (comment only).

### 6. `logos-rln-modules/tools/publish.sh:59` — duplicated-pipeline (merged [5]+[13], absorbs [0]'s publish.sh half) (small)

publish.sh is a drifted second release pipeline: 3 modules vs release.yml's 8, no lez_core shadow, unreferenced RELEASE_REPO (:25), header (:7-8) contradicting release.yml, catalog missing the UI's gifter deps; README.md:56 advertises it.

**Why:** Spot-checked :7-8, :25, :50-59 and README.md:56. Anyone following the README produces an uninstallable catalog. Deleting it also removes the stale 'fresh clone' generate rationale ([0]'s second half) and the header lie ([13]) in one stroke.

**Apply:** `git rm tools/publish.sh`; point README.md:56 at the `release` workflow (workflow_dispatch from main). Record the lost `lgx sign` recipe (:67-80) in the commit message or a one-line README note since release.yml publishes unsigned. Prove: `grep -rn publish.sh` across the repo is empty; release.yml never calls it, so the next workflow_dispatch is unaffected. Keep tools/catalog-gen.py.

### 7. `logos-rln-modules/.github/workflows/release.yml:217` — unnecessary-machinery (trivial)

release.yml runs `nix run path:./$dir#generate` before `nix build …#lgx-portable`, but the builder stages the SDK and regenerates the scaffold in-derivation; rln-module.yml:73 builds #lgx from a clean checkout with no generate step.

**Why:** Spot-checked :211-228 and rln-module.yml:58-73 (clean-checkout nix build, no staging). The pre-step costs one nix run per module per variant leg and implies the .lgx depends on staged inputs, which the flake comments explicitly deny. Ranked below the locally-provable items because validation is only the next workflow_dispatch; the plan/publish guard keeps a failed build non-publishing.

**Apply:** Replace the generate arm at :215-217 with `: ;;` (or collapse the case to the unknown-module guard). Prove: locally `nix build path:./logos-rln-module#lgx-portable` from a tree with no rust-lib/generated or logos-rust-sdk-src succeeds; then the next release run's build job. Retire memory build-release-pipeline.md:13 which asserts the opposite.

### 8. `logos-rln-modules/flake.nix:66` — unhelpful-comment (trivial)

Root-flake comment says 'The sim builds with --override-input logos-lez-rln-module', but no consumer overrides that input; the harnesses override their own `rln-modules` input with a filtered path: copy.

**Why:** Low benefit but zero risk and trivial; prevents cargo-culting a wrong override flag. Keep the WHY (path: sub-inputs resolve inside the overridden copy so the gitignored staged SDK is visible).

**Apply:** Replace :66-68 with generic phrasing: 'Harnesses build this repo through their own input, overridden with `--override-input <input> path:<copy>`; path: sub-inputs then resolve inside that copy.' Prove: `nix flake show path:.` still evaluates (comment only).

### 9. `logos-rln-modules/.github/workflows/rln-module.yml:36` — unnecessary-machinery (trivial)

Job is named 'cargo (fmt, clippy, test)' and installs rustfmt, but no step runs cargo fmt; lez-module.yml:22/36 is the honest variant.

**Why:** Two-token edit, zero behaviour change. Do NOT take the add-fmt-check arm: cargo fmt --check currently reports hundreds of hunks across files this branch modifies and would collide with the 2-PR stack.

**Apply:** Rename :22 to 'cargo (clippy, test)' and drop `rustfmt` from :36. Prove: next rln-module.yml run green (only the job title and an installed component change).

### 10. `logos-rln-modules/.github/workflows/release.yml:78` — duplicated-logic (small)

The gifter checkout + EZ checkout + jq shadow-version block is pasted byte-identically into plan (:78-95), build (:160-177) and publish (:266-283); the TEMPORARY-shadow removal note has to enumerate the three copies.

**Why:** Puts the temporary shadow in one file next to its removal condition and stops new external modules being wired into three jobs. CI-only, cannot be exercised locally; a checkout typo fails plan before publish so catalog idempotency is safe.

**Apply:** Add .github/actions/checkout-catalog-sources/action.yml (composite; inputs gifter_repo/gifter_rev/ez_repo/ez_rev/ez_version passed as `with: ${{ env.* }}` from the callers, since env context is unusable inside a composite) and `uses:` it in the three jobs; update the env comment at :50-52 to name the action. Prove: `actionlint` if available, then the next workflow_dispatch plan job.

### 11. `logos-rln-modules/.github/workflows/release.yml:198` — excessive-defensiveness (small)

Metal-toolchain install (:189-191) and `--option sandbox false` (:198-200, used at :228) run for every darwin module build, but only the shadowed lez_core wallet builds risc0 kernels; both are absent from the shadow removal list (:50-52).

**Why:** Restores sandboxed darwin builds for 7 of 8 modules and makes the TEMPORARY shadow removable in one pass. Real risk: sandboxed darwin builds of our modules are unproven (release only validated sandbox-off) and gifter modules are external — if one links risc0 its darwin leg fails. Needs a force release run, so ranked below the safe edits.

**Apply:** Minimum safe step: add both steps to the removal list at :50-52. Fuller step: move the sandbox opt into the `external/logos-execution-zone-module` case arm and gate the Metal step on `contains(needs.plan.outputs.to_build, 'external/logos-execution-zone-module')`. Prove: a forced workflow_dispatch with fail-fast:false; inspect per-variant markers.

### 12. `logos-rln-modules/.github/workflows/lez-module.yml:21` — duplicated-logic (small)

rln-module.yml and lez-module.yml are the same six-step cargo job with the module dir swapped; only rln has a nix .lgx job, so a lez nix-build regression first surfaces at release time.

**Why:** Gives lez a CI nix build (listed as an open defect in the guidelines evaluation). Costs reusable-workflow plumbing (module_dir + test_args inputs, secrets: inherit) and adds an up-to-60-min lez nix job per PR; validation only on a PR run. Do after ranks 1 and 9 so the inputs are simpler (no --skip, no rustfmt).

**Apply:** Add .github/workflows/_module-ci.yml (workflow_call; inputs module_dir; jobs cargo + nix as in rln-module.yml) and reduce the two files to path-filtered callers with `secrets: inherit`. Prove: PR run shows both callers green including the new lez nix job.

### 13. `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:173` — unhelpful-comment (trivial)

The register_membership mock repeats verbatim the COMMIT/COMMIT2 selection comment already at :79-81.

**Why:** Cosmetic; one fewer place for the rationale to drift. Test-only comment, zero risk.

**Apply:** Drop only the repeated sentence at :173-175; keep the first sentence at :172-173 ('minted in-module, only the commitment released'), which is unique and accurate. Prove: `nix build .#integration-test`.

### 14. `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:34` — unhelpful-name (trivial)

Helper `phase(app, prop)` is a generic flowController property read; 6 of 9 call sites read password/fundError/regError/unlockError through it.

**Why:** File-local helper, mechanical ~10-line rename, no exports or contract. Small readability gain.

**Apply:** Rename to `flow` (keep `waitPhase` at :43-48 as the phase wrapper) and update the call sites (:240, :438, :449, :463, :482-483 and the phase reads). Prove: `nix build .#integration-test`.

### 15. `logos-rln-modules/logos-lez-rln-module/stage-sources.sh:3` — unhelpful-comment (trivial)

Header narrates history ('no separate SDK_REV to keep in step any more') instead of the contract (who calls it, what it forwards to).

**Why:** Redundant rather than wrong (CLAUDE.md:5-9 holds the history; README.md:49 says wrapper kept for callers). Comment-only; script body untouched so e2e live-registry callers are unaffected.

**Apply:** Replace :3-6 with: 'Entry point the harness live-registry scenarios call; forwards to `nix run .#generate`, choosing the path: fetcher when the tree carries no .git.' Prove: `bash -n stage-sources.sh`; logos-rln-e2e live-registry rung unchanged.

### 16. `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:384` — low-value-test (small)

Scenario 5c (relaunch with one membership never celebrates) repeats 5b's preamble (:361-368) plus texts scenario 1 already asserts (:256).

**Why:** Marginal: saves a few lines, no measurable time (relaunch fires no timers), and loses a named regression. Only worth taking if touching the file anyway; must also update README.md:125's '15 scenarios'.

**Apply:** Fold '+ New Membership' and '<rate> msg/epoch' into 5b's expectTexts at :366, delete :384-392, change README.md:125 to 14 scenarios. Prove: `nix build .#integration-test`.


**Themes**

1. Stale narration left behind by refactors — comments describing a pre-extraction or pre-flip world: logos-rln-module/flake.nix:24-26 ('single default' after 88dbfe3 flipped to multi), ui-tests.mjs:5-7 ('hermetically untestable' after flow-tests.mjs landed in the same commit), root flake.nix:66-68 (an override flag nobody uses), stage-sources.sh:3-6 (SDK_REV history), publish.sh:7-8, catalog-gen.py:19 (logos-lez-rln homepage). The extraction commit d998344 is the common origin.
2. Second copies of a fact that the build already derives from one place — flake generate apps hardcode `--concurrency multi` and the --dep list that the builder reads from metadata.json (rln flake :71, lez flake :77); publish.sh:59 re-lists modules that release.yml:58-66 owns; rln-module.yml and lez-module.yml are the same six steps; release.yml pastes the checkout+shadow block three times (:78, :160, :266). Each copy has already drifted.
3. Cargo-cult CI steps whose rationale was never true or has expired — `--skip keychain` with a false 'live keychain' comment (rln-module.yml:53-56), rustfmt installed for a fmt that never runs (:36), `nix run #generate` before a nix build that regenerates in-derivation (release.yml:215-217, publish.sh:50-56), Metal toolchain + sandbox-off for all darwin modules when only the shadowed wallet needs them (release.yml:189-200).
4. TEMPORARY blocks with incomplete removal recipes — the lez_core shadow note (release.yml:44-52) enumerates three pasted copies and omits the Metal/sandbox steps that landed 8h after it, so the temporary block will outlive its condition.
5. Test-file cosmetics that accrete without pruning — verbatim duplicated comment (flow-tests.mjs:173-175 vs :79-81), a generic helper named `phase` (:34), and scenarios that restate earlier scenarios' assertions (5c :384, 9 :487).


**Demoted / not worth it**

[17] flow-tests.mjs:487 (scenario 9, petname) — dropped: the only novel assertion is the empty-commitment guard (:495, membership.js:435) and there is no pure-JS home for it (membership.js is a `.pragma library`, not node-loadable); folding it into scenario 1 muddies the golden path for ~10 saved lines. The refuter's own worth line says 'skip'. [13] publish.sh:7 and [8] rln flake :25 are not demoted but merged: [13] into rank 6 (deleting publish.sh removes the header) and [8] into rank 3 (same file, same edit as [1]); [0]'s publish.sh:50-56 half is likewise absorbed by rank 6. Spot-check of the top 8 (keychain.rs cfg gates, catalog-gen.py:19/:86, both flakes + metadata.json:9, ui-tests.mjs:5-8, flow-tests.mjs:90 + missing UI docs/, publish.sh header/loop + README.md:56, release.yml:211-228 vs rln-module.yml:58-73, root flake.nix:66) held up; none dropped. Caveat carried from the refuter: [0]'s builder claim rests on the pinned mkLogosModule.nix store path and rln-module.yml's clean-checkout nix build, not on a local nix run (nix absent here), hence its rank below the locally provable edits. Ranks 11-12 ([6], [4]) sit low not because the claims are weak but because each needs a CI/release run to validate and can expand CI time or break a darwin leg; rank 11's minimum safe step (extend the removal list) is worth taking even if the sandbox scoping is deferred.


## logos-rln-e2e

### 1. `logos-rln-e2e/scenarios/delivery-rln/run.sh:132` — duplicated-logic (trivial)

MERGES [10],[32],[44]: polls() (budget/interval, floor 1) is byte-identical in 8 scenarios and inlined as tries= in wallet.sh:127-128 and chain.sh:41-42.

**Why:** Verified: identical 4-line function in all 8 scenario run.sh files, same floor-1 arithmetic inline in two harness helpers. Pure arithmetic, bash-3.2 clean, zero contract surface; removes ~40 lines and one rule gets one home.

**Apply:** Add polls() to harness/lib/compat.sh (sourced by every scenario and run.sh); replace wallet.sh:127-128 with tries=$(polls "${E2E_CONFIRM_TIMEOUT_S:-180}" "$iv") and chain.sh:41-42 likewise with :-600; delete the 8 scenario copies. Prove: bash -n on all files, ./run.sh register --target local.

### 2. `logos-rln-e2e/scenarios/delivery-rln/run.sh:186` — code-in-wrong-place (small)

MERGES [11],[31],[43]: the base58 decode of E2E_CONFIG_ACCOUNT plus REGISTRY_ID="logos:${E2E_TARGET}:$CONFIG_HEX" is a 10-line python heredoc copied into 8 scenarios.

**Why:** Verified identical heredoc + REGISTRY_ID line in all 8 scenarios; harness/lib has no base58 helper (json.sh:15 is a comment). Largest dedup on the list; chain.sh already owns E2E_CONFIG_ACCOUNT reads. Output string must stay byte-identical, but any slip dies at the first start/register.

**Apply:** Add registry_id() to harness/lib/chain.sh (python3 base58 -> 32-byte hex, print logos:${E2E_TARGET}:<hex>); in each of the 8 scenarios replace the block with REGISTRY_ID=$(registry_id) || die. Keep it a chain.sh helper, not a target export (selftest/consumer-selftest use synthetic ids). Prove: ./run.sh register --target local (register + proof path).

### 3. `logos-rln-e2e/scenarios/delivery-rln/run.sh:123` — duplicated-logic (trivial)

[17] The checkout preflight is enforced by top-level run.sh:61-67 via PREFLIGHT_ANY and re-implemented in delivery-rln/run.sh:123-130 and delivery-basecamp-rln/run.sh:82-85 with drifted text.

**Why:** Verified: scenario.env:12 PREFLIGHT_ANY encodes exactly the predicate re-tested in the scenario body; run.sh:88 is the only invoker, so the in-scenario check can never fire first. Deleting removes drifted branch/version strings (rln/integration-fixes, 0.6.1) that also feed [19].

**Apply:** Delete delivery-rln/run.sh:118-130 and delivery-basecamp-rln/run.sh:82-85; move the 'DM flake pins the pre-fixes lib' rationale next to PREFLIGHT_ANY in scenario.env. Prove: ./run.sh delivery-rln --target none fails at run.sh:66 when checkouts are unset; bash -n.

### 4. `logos-rln-e2e/scenarios/delivery-rln/run.sh:677` — repeated-work (trivial)

[15] evt_arg (delivery-rln:181-184) exists but :677-678 and :737-738 re-inline the identical python one-liner; delivery/run.sh:114 is a third copy with no helper.

**Why:** Verified: evt_arg used at :580,:597,:598 while :677 and :737 inline evt_arg "$PROP" 1 verbatim; delivery/run.sh:114 same. Pure substitution on a line node_wait_event already produced; no name collision.

**Apply:** Move evt_arg beside node_wait_event in harness/lib/daemon.sh; replace delivery-rln:677-678 and :737-738 with MSGHASH=$(evt_arg "$PROP" 1) etc., and delivery/run.sh:114 with msghash=$(evt_arg "$prop" 1); delete the scenario-local definition. Prove: ./run.sh delivery --target none.

### 5. `logos-rln-e2e/scenarios/delivery-rln/run.sh:525` — dead-code (trivial)

MERGES [16],[26]: responder-n1.log is truncated (:525), tailed (:149-152) and grepped (:758-759) but only responder_loop n2 (:527) ever writes; the file is always empty.

**Why:** Verified: responder_loop appears only at :346 (def) and :527 (n2); answer_event writes to responder-$node.log only from that loop. Header :17-18 puts the witness on n2. Removing the n1 half also lets :758 drop its 2>/dev/null, which today would mask a path typo and silently disable the UNHANDLED canary.

**Apply:** Keep the :523 loop for node_watch_start on both nodes but move ': >responder-n2.log' outside it; change :758 to grep only responder-n2.log without 2>/dev/null and :759 to the single file; optionally drop the per-node responder tail loop in die() (its -s guard already skips n1). Prove: bash -n + one local delivery-rln run.

### 6. `logos-rln-e2e/scenarios/register/run.sh:51` — duplicated-logic (small)

[38] The contract-env preflight loop (for _v ...; eval "[ -n ..." || die "contract env missing") is copied into 11 scenarios with two message spellings.

**Why:** Verified: identical eval/die line in 11 scenario run.sh files (register:51 vs chat-basecamp-rln:76 differ only in message). Preflight runs before any daemon, so die() overrides are irrelevant; none-target fail-fast preserved. run.sh:61-67 is a different any-of shape and stays.

**Apply:** Add need_env() to harness/lib/compat.sh (loop + eval + die 'contract env missing: $v (see docs/contract.md)'); each scenario's preflight becomes need_env VAR...; leave top-level run.sh:61-67 alone. Prove: ./run.sh consumer-selftest --target none, and unset one var to see the die.

### 7. `logos-rln-e2e/scenarios/delivery-rln/run.sh:646` — code-in-wrong-place (small)

MERGES [21],[37]: the get_valid_roots warm-up poll (E2E_ROOTS_WARM_BUDGET_S, default 300, 5s sleep, die_node) is copied into 4 scenarios and its knob is undocumented.

**Why:** Verified: delivery-basecamp-rln:334-343 and chat-basecamp-rln:335-344 are byte-identical; delivery-rln:646-660 differs only in node, a leading say and the '(wallet still syncing?)' hint. E2E_ROOTS_WARM_BUDGET_S appears in no doc/header, which contract.md requires. chain.sh already hosts confirm_and_ready, the analogous poll.

**Apply:** Add wait_roots_warm <node> <registry_id> [budget_s] to harness/lib/chain.sh (hardcode liblogos_rln_module, keep the syncing hint in the die_node message, document the knob in chain.sh's header); call it from the 4 sites. Prove: bash -n + one local delivery-rln run (the chat/basecamp sites are testnet-only; the loop body is unchanged).

### 8. `logos-rln-e2e/scenarios/register/run.sh:67` — duplicated-logic (trivial)

MERGES [36] and the consumer-register half of [45]: register:64-83, consumer-register:61-79 and keystore:65-75 re-implement daemon.sh's die (28-37) and daemon_stop_all's E2E_KEEP branch (230-241).

**Why:** Verified: daemon.sh:10-12 documents that sourcing replaces die; its die tails 40 lines of E2E_DIE_NODE (= n1 via daemon_start:53) whenever the log exists, which is strictly more informative than the scenario's NODE_UP-gated copy (a die_node inside daemon_start prints no tail today). DYING is dead (node_logs never calls die).

**Apply:** Delete register's and consumer-register's die() + NODE_UP/DYING bookkeeping and cleanup(); trap daemon_stop_all EXIT. keystore's cleanup keeps only the HOLDER_PID kill then calls daemon_stop_all. Prove: ./run.sh register --target local PASS, then force a failure (bad E2E_SEQUENCER) and confirm the tail prints; E2E_KEEP=1 run leaves the node up.

### 9. `logos-rln-e2e/scenarios/delivery-rln/scenario.env:3` — stale-docs (trivial)

[18] scenario.env:3-5 and README.md:21 describe a per-node responder and 'tampered message NOT delivered', the inverse of what run.sh:12-21 and :739-746 assert.

**Why:** Docs-only but actively misleading for delivery devs, and delivery-integration.md:22 already names run.sh's header as the single owner. Zero runtime risk.

**Apply:** Replace scenario.env's blurb and README's row with one-line pointers to scenarios/delivery-rln/run.sh's header (or restate the witness/hijack-control wording matching its six 'What it proves' points). Prove: ./run.sh --list still prints id+status; read-through.

### 10. `logos-rln-e2e/scenarios/delivery-rln/run.sh:81` — stale-docs (trivial)

MERGES [19],[28],[29]: the required rln-modules/delivery pin is stated five ways (toolchain-0.9 / 0.6.1 / integration-fixes / chore/drop-raw-lp / 0.7.x) across two headers, scenario.env and the doc; PREFLIGHT_MSG points in a circle.

**Why:** Every statement disagrees and one names a superseded branch (chore/drop-raw-lp is not an ancestor of feat/lip-alignment). Comment/string only, but the header is what operators read before spending on testnet. Rank 3's deletion of the die copies removes two of the five.

**Apply:** In delivery-rln/run.sh's Required-checkouts block and delivery-basecamp-rln:39-41 state the pin once in wire-version terms (0.7.x wire: proof_canonical + RegistryOptions register, 0.9 builder; main after merge / flake pin); make scenario.env:2,11 and docs/delivery-integration.md:7 say 'see header'; delete delivery-rln's PREFLIGHT_MSG so run.sh:66's fallback points at the header (as basecamp's already does). Prove: read-through; bash tools/check-naming.sh.

### 11. `logos-rln-e2e/scenarios/delivery-rln/run.sh:117` — stale-docs (trivial)

[27] The funding preflight die says n1's registration is paid from a faucet claim, but both nodes claim (:435-458) and register (:510-511).

**Why:** False operator-facing error text left from the single-payer topology; header :47-48 already states the truth. Nothing greps this string.

**Apply:** Reword :117 to "both nodes' registrations are paid from faucet claims into their own holdings". Prove: bash -n.

### 12. `logos-rln-e2e/scenarios/delivery/run.sh:16` — stale-docs (trivial)

MERGES [24],[25]: delivery/run.sh:16-22 narrates the header's own revision history, and delivery-rln/run.sh:577 cites a 'finding-8' that exists nowhere in the repo.

**Why:** Comment-only in the delivery track's entry-point scenario; the live fact (one opaque proof_canonical field) already lives in docs/delivery-integration.md section 3. Keep lines 5-9 (zerokit v2 co-residency) which remain true.

**Apply:** Replace delivery/run.sh:16-22 with 'No RLN<->delivery coupling here - see scenarios/delivery-rln; the message wire carries the module's proof_canonical blob opaquely (docs/delivery-integration.md section 3)'; delete the parenthetical at delivery-rln:577. Prove: bash -n.

### 13. `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:288` — dead-code (small)

MERGES [51],[52]: getMembershipState splices consumer_poller (zero readers, breaks the README's forward-VERBATIM policy); the same 5-line 'state of a tstr reply' parse is written twice (241-245, 271-275).

**Why:** Verified: lastPolled written only at :240, read only at :290-291; no scenario/harness/doc reads consumer_poller. Dropping it removes shared poller state and a parse/merge; stateOf() is a free rider on the same two procs. Config JSON, not the frozen wire.

**Apply:** Delete lastPolled (29, 240, 288-294) and return the tstr reply as-is; add private proc stateOf(reply: string): string {.raises: [].} and use it in confirmationPoller and rlnconsumerRegisterMembership; update the doc comments at rlnconsumer.nim:281 and rln_consumer_plugin.h:72-73. Prove: nix build of the consumer lgx + ./run.sh consumer-selftest --target none, then consumer-register --target local.

### 14. `logos-rln-e2e/run.sh:53` — excessive-defensiveness (trivial)

[0] run.sh defaults TARGETS to 'local testnet' (twice) and RUNNER to bash although the contract makes both mandatory and all 12 scenario.env files set them.

**Why:** Verified at run.sh:53,55,87. A scenario that forgets TARGETS silently inherits testnet and can spend against a real tree; fail-loud is strictly safer. Trivial and cheap to validate.

**Apply:** After sourcing scenario.env (run.sh:50) add [ -n "${TARGETS:-}" ] || die "scenario '$SCENARIO': scenario.env must declare TARGETS" and the same for RUNNER (use die, not :?, to keep the 'e2e: FAIL:' prefix); reference plain $TARGETS/$RUNNER afterwards. Prove: ./run.sh --list and one --target none run.

### 15. `logos-rln-e2e/tools/check-naming.sh:3` — stale-docs (trivial)

MERGES [3],[4]: check-naming.sh's header names a deleted docs/journeys/mix.md and claims the testnet URL 'belongs to the testnet target' while excluding testnet.sh, which has never contained the URL.

**Why:** Comment fix plus a guard tightening: dropping the dead ':!harness/targets/testnet.sh' exclusion makes a hardcoded sequencer URL in the target fail the check, matching its own descriptor-required design. Seconds to verify.

**Apply:** Rewrite lines 3-4 to describe only the excl array (scenarios/mix, docs/naming.md, itself; point at scenarios/mix/STATUS.md instead of 'P4'); reword 17-19 to 'the URL lives only in committed descriptors under deployments/' and remove the testnet.sh exclusion. Prove: bash tools/check-naming.sh passes.

### 16. `logos-rln-e2e/scenarios/chat-basecamp-gifter/run.sh:341` — unnecessary-machinery (trivial)

[41] A save/mutate/restore of the global E2E_CONFIRM_TIMEOUT_S (with a dead second restore inside the die branch) exists only to give confirm_and_ready a 300s budget.

**Why:** Correct and trivial (call-scoped prefix assignment is the repo idiom, chat-basecamp-rln:155), and it removes a latent trap where an early return leaves the global at 300 for the :374-375 read. Ranked below the harness items only because the scenario is testnet-only and the testnet rung is currently blocked.

**Apply:** Replace :341-352 with E2E_CONFIRM_TIMEOUT_S=300 confirm_and_ready n1 ... for both calls and delete _CONFIRM_SAVED and both restores (or add an optional 5th budget arg to confirm_and_ready). Prove: bash -n now; chat-basecamp-gifter --target testnet when the rung reopens.

### 17. `logos-rln-e2e/nim-rln-consumer/flake.nix:11` — unnecessary-machinery (trivial)

[48] The consumer flake's nix-bundle-lgx input is never consumed (metadata.json dependencies is [], the builder bundles with its own pin), so the lock carries two independent pins.

**Why:** Verified: outputs bind only logos-module-builder; flakeInputs is filtered by the empty dependencies list. Removing drops a duplicate pin subtree. Needs lock regeneration in consumer and root, which is why it sits mid-list rather than top.

**Apply:** Delete flake.nix:11; run nix flake lock in nim-rln-consumer and the root (plain removal, not follows, so the builder's bundler stays at b49074a). Prove: nix build of the consumer attr + ./run.sh consumer-selftest --target none.

### 18. `logos-rln-e2e/scenarios/delivery-rln/run.sh:170` — duplicated-logic (small)

MERGES [13],[33]: must_call (delivery_module call + StdLogosResult success gate) is byte-identical in 4 scenarios; delivery/run.sh:74-82 differs only by die_node.

**Why:** ~36 lines and one place for the StdLogosResult unwrap; die resolves at call time so scenario die() overrides still apply. Keep the existing signature (all 17 callers are delivery_module). Put it beside node_call in daemon.sh to avoid a new lib file in 5 for _lib lists.

**Apply:** Add must_call <node> <method> <label> [args...] to harness/lib/daemon.sh using die_node "$node"; delete the 5 scenario copies. Prove: ./run.sh delivery --target none (only chainless caller) + delivery-rln local.

### 19. `logos-rln-e2e/scenarios/register/run.sh:115` — duplicated-logic (small)

MERGES [12],[34]: the faucet prologue (fresh holding -> bounds -> price -> claim rate*price*2 -> wait_balance) is repeated 9 times in 8 scenarios; 3 copies have a dead error check (| jres >/dev/null || die).

**Why:** Real dedup and it fixes the missing-BOUNDS guard and dead error check in keystore/consumer-gifter/chat-gifter. Mid-list because the helper must export PRICE/CLAIM globals (reused at chat-gifter:361, delivery-rln:455), touches every chain scenario's bring-up, and 4 sites are testnet-only.

**Apply:** Add fund_fresh_holding <node> <rate_limit> [multiplier] to harness/lib/wallet.sh that sets E2E_PRICE_PER_UNIT/E2E_CLAIM and prints the holding; replace the 9 blocks, keeping delivery-rln's HOLDING2 != HOLDING assert. Prove: ./run.sh register + keystore --target local; testnet sites when the rung reopens.

### 20. `logos-rln-e2e/scenarios/chat-basecamp-rln/run.sh:95` — code-in-wrong-place (small)

MERGES [20],[39] + gifter half of [45]: 7 scenarios override daemon.sh's die() with a NODES_UP/DYING guard + all-node tail (making die_node's node arg inert); the 3 basecamp scenarios repeat the same die/cleanup pair.

**Why:** Restores die_node (delivery-rln:656, basecamp:340) and folds 7 copies, but it is the failure/exit path of every scenario and touches daemon.sh plus basecamp.sh hooks; needs forced-failure runs per shape. Apply after rank 8 (the narrow single-node deletions) has landed.

**Apply:** Make daemon.sh's die tail every node in $E2E_NODES with a re-entrancy guard and an optional E2E_DIE_HOOK for extra tails (responder log, basecamp_die_tails); add basecamp_cleanup to basecamp.sh (basecamp_stop + daemon_stop_all under E2E_KEEP); drop the scenario overrides and delivery-rln's duplicate KEEP branch (:160-163). Prove: forced-failure delivery-rln local run (all tails print), E2E_KEEP=1 run, bash -n on all.

### 21. `logos-rln-e2e/harness/artifacts.sh:144` — dead-code (small)

[2] E2E_LEZ_RLN is set, exported and documented as 'the target's call' but has zero readers; testnet.sh:41-62 re-derives the same answer with dead nix-build/../logos-lez-rln fallbacks.

**Why:** Consuming it in testnet.sh deletes ~20 lines and one phantom contract. Do NOT retarget local.sh:170 (local needs a dev checkout, not a store path). Needs a testnet run to prove, so mid-list.

**Apply:** Replace _testnet_lez_src in testnet.sh with $E2E_LEZ_RLN; make artifacts.sh:144 die when LEZ_RLN_CHECKOUT is set but missing (as testnet.sh:43 does); leave local.sh alone; update the header comment. Prove: one testnet register run when the rung reopens; until then bash -n + --target none.

### 22. `logos-rln-e2e/harness/targets/local.sh:44` — naming (trivial)

[5] _LOCAL_HERE and _TESTNET_HERE hold the repo root, which lgx.sh:13 already exposes as E2E_ROOT before either target is sourced; 'HERE' means three different dirs across run.sh/selftest.sh/targets.

**Why:** Identical value by construction (run.sh:78 sources artifacts.sh->lgx.sh before the target at :82). Small clarity gain; needs a doc line update since E2E_ROOT becomes the override for profiles/ and deployments/ too, and --target none never exercises it.

**Apply:** Use $E2E_ROOT at local.sh:139,170 and testnet.sh:51,60-61,66,84; delete the two _*_HERE lines; extend lgx.sh:11's E2E_ROOT comment to mention profiles/ and deployments/. Prove: ./run.sh register --target local.

### 23. `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:150` — duplicated-logic (trivial)

[50] Hand-rolled hexToBytes/bytesToHex duplicate stew/byteutils hexToSeqByte/toHex, already pinned and what delivery's RLN code uses.

**Why:** 17 fewer lines and the same codec as delivery; byte-identical encoding so proof parity holds. Touches the signal bytes proven over, so it needs a full consumer-register run and a Nim rebuild; batch with rank 13's rebuild.

**Apply:** import stew/byteutils; replace lines 150-165 with hexToSeqByte/toHex, keep .strip() at line 309. Prove: consumer lgx rebuild + ./run.sh consumer-register --target local (proof + validate).

### 24. `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:193` — duplicated-logic (small)

[42] The createConsumer default table (600/10/95/5/300) lives in both rln_consumer_plugin.cpp:100-104 and rlnconsumer.nim:193-197; the Nim copy is unreachable and both drift from delivery's 10/80/200.

**Why:** One owner for five defaults and a chance to fix the README/plugin-header prose. Medium because the surviving owner must keep 95 for registryOpTimeoutSec (scenarios do not pass it) or the read budget shifts silently; needs a rebuild.

**Apply:** Have C++ pass raw strings (empty when absent) and let Nim's intOr own the defaults; keep 95 (or deliberately move to delivery's 80/200 and say so); point README:37-40,141-143 and plugin.h:44-49 at the Nim table. Prove: consumer rebuild + consumer-selftest --target none + consumer-register local.

### 25. `logos-rln-e2e/nim-rln-consumer/nim-lib/nix/default.nix:56` — unnecessary-machinery (trivial)

[49] --header emits a Nim header into $NIMCACHE that installPhase never copies, and pkgs.git is a build input nothing invokes; both are residue of delivery's recipe.

**Why:** Two residue lines and git leave the closure; output is unchanged. Any default.nix edit forces a full Nim rebuild on host and in Dockerfile.node, so batch with the rlnconsumer.nim edits (ranks 13/23/24).

**Apply:** Drop --header from line 56 and pkgs.git from line 35. Prove: nix build of the consumer + consumer-selftest --target none.

### 26. `logos-rln-e2e/harness/selftest.sh:2` — low-value-test (small)

[9] harness/selftest.sh is an unreferenced standalone entry point re-implementing run.sh's bootstrap; it is also the only cheap chainless call INTO both RLN modules.

**Why:** Converting (not deleting) gives a cheap RLN_MODULES_CHECKOUT load gate that shows up in --list and drops the duplicated bootstrap. Needs one run to prove the probes still pass on the post-LIP wire.

**Apply:** Create scenarios/rln-selftest/{scenario.env (TARGETS=none, NEEDS_MODULES=the three RLN bundles), run.sh} carrying the two probes; delete harness/selftest.sh. Prove: ./run.sh rln-selftest --target none.

### 27. `logos-rln-e2e/harness/artifacts.sh:168` — too-many-branches (small)

[1] resolve_artifacts re-splits NEEDS_MODULES five times with sequential one-arm case statements (168-216), and again for NEEDS_APPS (225-238).

**Why:** Cosmetic: one for/case loop is shorter and the next module is one arm. Order becomes declaration order, and _chat_lgx reuses _delivery_lgx's staged copies only if delivery_module ran first (both chat scenario.envs list it first; reversed only re-rsyncs).

**Apply:** Replace with for m in ${NEEDS_MODULES:-}; do case "$m" in delivery_module) ...;; nim_rln_consumer) ...;; chat_module) ...;; libp2p_module) ...;; rln_gifter_module) ...;; esac; done, keeping the [ -n ] || guards and arm comments; same for NEEDS_APPS. Prove: ./run.sh delivery --target none + consumer-selftest --target none.

### 28. `logos-rln-e2e/harness/lib/daemon.sh:5` — stale-docs (trivial)

MERGES [6],[7],[8]: header hygiene: undefined 'P3' + three 'container later' clauses (daemon.sh:5, chain.sh:3, wallet.sh:3), rename archaeology at wallet.sh:6-7, a dated note at artifacts.sh:14-17 duplicated in flake.nix:76-78.

**Why:** Comment-only, no behaviour; worth a single header-hygiene commit alongside ranks 14-15, not on its own.

**Apply:** Drop 'P3' and two of the three 'container later' clauses (keep one forward pointer to RUNNER=compose per mix/STATUS.md:22); trim wallet.sh:6-7 to 'wallet module id (default lez_core)'; reduce artifacts.sh:13-17 to the attr list plus the still-true 'staging scripts are only for bare-cargo dev loops' clause, leaving flake.nix:76-78 as the one home. Prove: bash -n.


**Themes**

1. Scenario-local copies of harness primitives. The same 4-15 line helper is pasted into every scenario instead of living in harness/lib: polls() in 8 files (scenarios/delivery-rln/run.sh:132, register/run.sh:58), the base58 registry-id heredoc in 8 (delivery-rln/run.sh:186), the contract-env preflight loop in 11 (register/run.sh:51), must_call in 5 (delivery-rln/run.sh:170), the roots warm-up poll in 4 (delivery-rln/run.sh:646), the faucet prologue in 9 (register/run.sh:115). The harness even inlines the same rule itself (wallet.sh:127-128, chain.sh:41-42) rather than naming it.

2. Re-implementing what the sourced lib already provides. daemon.sh documents that sourcing it replaces die() and that daemon_stop_all honours E2E_KEEP (daemon.sh:10-12, 230-241), yet register/run.sh:64-83, consumer-register/run.sh:61-79, keystore/run.sh:65-75 and 7 multi-node overrides rewrite both, which also silently disables die_node. Same shape: evt_arg defined at delivery-rln/run.sh:181 then re-inlined at :677 and :737; the PREFLIGHT_ANY rule enforced by run.sh:61-67 re-tested at delivery-rln/run.sh:123-130; chain_head probed right before wallet_sync probes it again (register/run.sh:110).

3. Leftovers of retired topologies and superseded pins. Code and comments outlive the design they describe: responder-n1.log for a responder that only runs on n2 (delivery-rln/run.sh:525, :758), scenario.env:3-5 and README.md:21 describing the per-node responder and an inverted negative control, the 'n1 pays' die text at delivery-rln/run.sh:117, five disagreeing pin statements (delivery-rln/run.sh:5/:81/:125, delivery-basecamp-rln/run.sh:41, docs/delivery-integration.md:7), E2E_LEZ_RLN exported with no reader (artifacts.sh:144-150).

4. Narrative comments instead of facts: dated verification stamps (artifacts.sh:14), a header's own revision history (delivery/run.sh:16-22), dangling review references ('finding-8', delivery-rln/run.sh:577), rename archaeology with commit hashes (wallet.sh:6-7), roadmap phases nobody defined ('P3', daemon.sh:5), phantom files (tools/check-naming.sh:3).

5. Copied build recipes carrying dead knobs. The consumer's nix/flake files inherit delivery's shape without its needs: an unconsumed nix-bundle-lgx input (nim-rln-consumer/flake.nix:11), --header and pkgs.git in nim-lib/nix/default.nix:35,56, a defaults table duplicated across C++ and Nim (rlnconsumer.nim:193 vs rln_consumer_plugin.cpp:100), hand-rolled hex codecs beside a pinned stew (rlnconsumer.nim:150).


**Demoted / not worth it**

Spot-check: all top 8 hold as cited (polls x8 + inline tries=, base58 heredoc x8, run.sh:61-67 vs delivery-rln:123-130, evt_arg vs :677/:737, responder_loop only at :527, preflight loop x11, roots loop x4, daemon.sh die/daemon_stop_all vs register:64-83). Nothing dropped for not holding up.

Demoted/excluded:
- [30] chat.sh extraction (~150 lines, gifter vs rln): medium effort, both scenarios testnet-only (~25min basecamp sync each), testnet rung blocked, copies not verbatim (rln has extra probes/degrade check). Unverifiable now; revisit when testnet reopens.
- [46] consumer.sh extraction: consumer-register is the linear reference README:74/172 cites; helpers need 4 globals; scenarios diverge on assertions; medium effort for ~45 lines.
- [14] delivery_conf helper: a THIRD key dialect exists (chat fork's old rln-relay-* spellings its parser requires); one template invites unifying them and needs ~8 positional args to save ~2 lines/site. Frozen-spelling risk outweighs benefit.
- [35] rln_register_wait/registry_options: the OPTIONS_JSON literal IS the frozen 0.6.0 wire; only two poll callers, diverging on purpose (register's R2 diagnostics + commitment extraction; keystore:233 rate-only array).
- [40]/[47] chain_head before wallet_sync: valid only at register:110, keystore:133, consumer-register:106; in the 4 basecamp/delivery-rln sites it is a fail-fast before wallet_open's ~90s probe loop. The 'wallet_sync says the head' variant pollutes its stdout value channel. Not worth a separate change.
- [22] evt_count helper: readability-only in one file; fold in only if delivery-rln/run.sh is open for ranks 4/5.
- [23] dropping lgx from 10 for _lib lists: dead but zero behavioural gain; all 10 at once or none.
- [45] split: consumer-register half into rank 8, gifter half into rank 20. [3]/[4], [6]/[7]/[8], [24]/[25], [19]/[28]/[29] merged into single header-hygiene entries (ranks 15, 28, 12, 10).


## Index of every confirmed finding

Sorted by unit, then file. `worth` is the value assessor's rating.

| unit | file:line | category | worth | effort | summary |
|---|---|---|---|---|---|
| e2e-app-scenarios | `logos-rln-e2e/scenarios/chat-basecamp-gifter/run.sh:127` | Duplicated logic or state | medium | medium | chat-basecamp-gifter copies ~150 lines of chat-basecamp-rln verbatim: conf builder, must_call, n1 chat bring-up, basecamp rln/bridge/chat init, membership poll, roots-warm + messag |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/chat-basecamp-gifter/run.sh:341` | Unnecessary machinery or repeated work | high | trivial | A save/mutate/restore of the global E2E_CONFIRM_TIMEOUT_S (with a second restore inside the failure branch) exists only to hand confirm_and_ready a 300s budget. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/chat-basecamp-rln/run.sh:95` | Code in the wrong place | medium | small | The basecamp-scenario die()/cleanup() pair (basecamp_die_tails + node tails, basecamp_stop + daemon_stop_all under E2E_KEEP) is rewritten in every basecamp scenario instead of livi |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/chat-basecamp-rln/run.sh:118` | Duplicated logic or state | low | small | must_call (delivery_module call + StdLogosResult success gate) is copied into five scenarios; in both chat scenarios it has exactly one caller. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/chat-basecamp-rln/run.sh:335` | Duplicated logic or state | high | trivial | The get_valid_roots warm-up wait (E2E_ROOTS_WARM_BUDGET_S loop) is copied into four scenarios. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/keystore/run.sh:150` | Duplicated logic or state | low | small | keystore's unlock -> RegistryOptions register_membership -> poll-to-active block re-implements register's, including the hand-built OPTIONS_JSON literal. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:48` | Duplicated logic or state | high | small | The contract-env preflight (`for _v in ...; eval "[ -n ..." \|\| die`) is boilerplate copied into eleven scenarios and run.sh; only the var list differs. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:58` | Duplicated logic or state | high | trivial | polls() (budget / interval, floor 1) is redefined identically in eight scenarios and re-derived inline by two harness helpers. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:67` | Duplicated logic or state | high | trivial | register redefines die() to tail the node log and cleanup() to honour E2E_KEEP — both behaviours are already provided by the daemon.sh it sources. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:85` | Code in the wrong place | high | small | Every chain scenario derives REGISTRY_ID by hand-decoding E2E_CONFIG_ACCOUNT (base58 -> 32-byte hex) with an inline python heredoc; the contract owns that fact and says not to grow |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:110` | Unnecessary machinery or repeated work | low | trivial | Scenarios probe chain_head immediately before wallet_sync, which probes it again itself; the first result is only echoed or discarded. |
| e2e-app-scenarios | `logos-rln-e2e/scenarios/register/run.sh:115` | Duplicated logic or state | medium | small | The faucet-funding prologue (fresh holding -> get_registry_bounds -> price -> claim rate*price*2 -> wait_balance) is repeated in eight scenarios; wallet.sh already owns its first a |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/flake.nix:11` | Unnecessary machinery or repeated work | high | trivial | The root `nix-bundle-lgx` flake input is never consumed (mkLogosModule bundles with its own and reads flakeInputs only by metadata dependency names), so the lock carries two indepe |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/nim-lib/nix/default.nix:56` | Unnecessary machinery or repeated work | medium | trivial | `--header` generates a Nim header into $NIMCACHE that installPhase never copies, and `pkgs.git` is a build input nothing invokes; both are residue of copying logos-delivery's recip |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:150` | Unnecessary machinery or repeated work | medium | trivial | Hand-rolled hexToBytes/bytesToHex duplicate stew/byteutils, which is already a pinned dependency and is what delivery's own RLN code uses for the same job. |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:193` | Duplicated logic or state | medium | small | The createConsumer default table (600/10/95/5/300) lives in both the C++ plugin and Nim; the Nim copy is unreachable in practice and both already drift from the delivery values the |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:241` | Duplicated logic or state | high | trivial | The "state field of a tstr reply" parse (try parseJson{"state"}.getStr("") / except "") is written out twice. |
| e2e-consumer | `logos-rln-e2e/nim-rln-consumer/nim-lib/src/rlnconsumer.nim:288` | Unnecessary machinery or repeated work | high | small | getMembershipState re-parses the module reply to splice in the poller's `lastPolled` as `consumer_poller`, but nothing reads that key and it breaks the documented forward-verbatim  |
| e2e-consumer | `logos-rln-e2e/scenarios/consumer-gifter/run.sh:188` | Duplicated logic or state | low | medium | consumer-register and consumer-gifter carry the same ~60 lines of consumer driving (config printf, create/subscribe/start, poll-to-active, proof extraction, validate loop). |
| e2e-consumer | `logos-rln-e2e/scenarios/consumer-register/run.sh:55` | Duplicated logic or state | high | trivial | `polls()` (budget/interval, floor 1) is copied verbatim into 9 scenarios, and the same rule is written inline in the harness's own wait_balance. |
| e2e-consumer | `logos-rln-e2e/scenarios/consumer-register/run.sh:63` | Duplicated logic or state | medium | small | The scenario's `die()` override re-implements harness/lib/daemon.sh's die, which already prints the same 40-line daemon-log tail for the node daemon_start registered. |
| e2e-consumer | `logos-rln-e2e/scenarios/consumer-register/run.sh:81` | Code in the wrong place | medium | small | The base58 decode of E2E_CONFIG_ACCOUNT into the CAIP-10 REGISTRY_ID is a target-level fact re-derived inline in 8 scenarios; the harness has no helper and the contract says to gro |
| e2e-consumer | `logos-rln-e2e/scenarios/consumer-register/run.sh:106` | Unnecessary machinery or repeated work | low | trivial | chain_head is called only to print a log line, then wallet_sync immediately probes the chain head again and already dies on failure. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-basecamp-rln/run.sh:41` | Unhelpful comments or names | high | trivial | RLN_MODULES_CHECKOUT is described as '@ chore/drop-raw-lp', a branch off the live lineage; delivery-rln calls the same knob 'the 0.6.1 stack' and the doc says '0.7.x'. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-basecamp-rln/run.sh:334` | Code in the wrong place | high | small | The valid-roots warm-up poll (get_valid_roots with E2E_ROOTS_WARM_BUDGET_S) is copied into 4 scenarios; it is a chain primitive like confirm_and_ready, and its knob is undocumented |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:81` | Duplicated logic or state | high | trivial | The required rln-modules stack/branch is stated five times in delivery-rln and the statements disagree (toolchain-0.9 vs 0.6.1 vs integration-fixes; the doc says 0.7.x). |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:117` | Unhelpful comments or names | high | trivial | The funding preflight message says n1's registration is paid from a faucet claim, but both nodes claim from the faucet and register. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:123` | Duplicated logic or state | high | trivial | The checkout preflight is enforced twice: scenario.env PREFLIGHT_ANY (checked by top-level run.sh before the scenario starts) and again in the scenario body, with messages that hav |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:132` | Code in the wrong place | high | small | polls() (timeout/interval, floor 1) is copy-pasted into 8 scenario scripts while the harness computes the same thing inline twice; it belongs in harness/lib. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:141` | Code in the wrong place | medium | small | Seven scenarios override daemon.sh's die() with the same NODES_UP/DYING guard + all-node log tail; the override also makes die_node's node argument inert. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:170` | Duplicated logic or state | medium | small | must_call (delivery_module StdLogosResult unwrap-or-die) is defined identically in 5 scenarios; it is harness plumbing next to jres/jval. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:186` | Code in the wrong place | high | small | The base58-decode of E2E_CONFIG_ACCOUNT and the `logos:<target>:<hex>` registry-id rule are re-implemented in 8 scenarios; chain.sh owns the config account and should own the deriv |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:435` | Duplicated logic or state | medium | small | The faucet-funding block (fresh holding → get_registry_bounds → price → CLAIM=rate*price*2 → claim_tokens → wait_balance) is duplicated 9 times across 8 scenarios, twice in deliver |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:523` | Unnecessary machinery or repeated work | high | trivial | A responder log is created, tailed on failure and grepped for n1, but only n2 runs a responder — responder-n1.log is always empty (leftover of the retired per-node responder topolo |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:539` | Duplicated logic or state | low | small | The flat WakuNodeConf template and the rln-* key spellings (85c2d6f8) are maintained in two identical printf literals plus a third RLN-less one; a key rename has to be found in all |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:577` | Unhelpful comments or names | high | trivial | '(the old finding-8 gap, now closed)' cites a review finding that exists nowhere in the repo or docs. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:677` | Unnecessary machinery or repeated work | high | trivial | evt_arg() exists for exactly this extraction but two later sites re-inline the same python one-liner; delivery/run.sh inlines it a third time. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:686` | Duplicated logic or state | low | trivial | The 'exactly one rlnGetMembershipStateRequest' assertion is written out three times (plus a fourth grep -c for generate requests) over the same event file. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/run.sh:758` | Low-value tests | medium | trivial | The UNHANDLED-op check greps responder-n1.log, which nothing ever writes (only n2 runs a responder), so half the check and die()'s n1 responder tail inspect an always-empty file. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/scenario.env:3` | Duplicated logic or state | high | trivial | scenario.env and README describe a topology and negative control that run.sh no longer implements (per-node responder; tampered message NOT delivered). |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery-rln/scenario.env:13` | Unhelpful comments or names | medium | trivial | PREFLIGHT_MSG points to the doc's quickstart 'for the exact checkouts/branches', but the quickstart names none and points back to run.sh's header — a circular pointer ending at the |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery/run.sh:16` | Unhelpful comments or names | high | trivial | Lines 16-22 narrate the header's own revision history ('settled the other way than this header once predicted') instead of stating the current fact in one sentence. |
| e2e-delivery | `logos-rln-e2e/scenarios/delivery/run.sh:42` | Unnecessary machinery or repeated work | low | trivial | All three delivery scenarios source harness/lib/lgx.sh (bundle build/unpack) but call none of its functions; it is boilerplate copied across 10 scenarios. |
| e2e-harness | `logos-rln-e2e/harness/artifacts.sh:14` | Unhelpful comments or names | low | trivial | A dated verification note ("Verified 2026-08-10 ...") narrates history and is repeated verbatim in flake.nix. |
| e2e-harness | `logos-rln-e2e/harness/artifacts.sh:28` | Unhelpful comments or names | medium | small | E2E_LEZ_RLN is documented as the lez-rln source the targets choose between, but no target or scenario reads it — each target re-derives its own answer. |
| e2e-harness | `logos-rln-e2e/harness/artifacts.sh:168` | Too many branches | medium | small | resolve_artifacts re-splits NEEDS_MODULES five times with sequential single-arm case statements over the same padded string. |
| e2e-harness | `logos-rln-e2e/harness/lib/daemon.sh:5` | Unhelpful comments or names | low | trivial | Headers promise a container node_call "(compose topology, P3)" / "(host daemon now, container later)"; "P3" is defined nowhere and the container path is quarantined. |
| e2e-harness | `logos-rln-e2e/harness/lib/wallet.sh:6` | Unhelpful comments or names | low | trivial | E2E_WALLET_MOD's doc narrates the wallet module's old id and rename commit; the old name appears nowhere in the active tree. |
| e2e-harness | `logos-rln-e2e/harness/selftest.sh:2` | Low-value tests | medium | small | selftest.sh is an unreferenced standalone smoke test; every layer it proves (artifacts, lgx, daemon, JSON, chainless) is already exercised by the active `delivery --target none` sc |
| e2e-harness | `logos-rln-e2e/harness/targets/local.sh:44` | Unhelpful comments or names | medium | trivial | `_LOCAL_HERE` (and `_TESTNET_HERE` in testnet.sh:25) are named "here" but hold the repo root, which the already-sourced lgx.sh exposes as E2E_ROOT. |
| e2e-harness | `logos-rln-e2e/run.sh:53` | Excessive defensiveness | high | trivial | run.sh substitutes defaults for TARGETS (twice) and RUNNER although the contract makes both mandatory in scenario.env and every scenario declares them. |
| e2e-harness | `logos-rln-e2e/tools/check-naming.sh:3` | Unhelpful comments or names | high | trivial | Comment names `docs/journeys/mix.md` as an excluded frozen artifact; the file does not exist and the exclusion list does not mention it. |
| e2e-harness | `logos-rln-e2e/tools/check-naming.sh:17` | Unhelpful comments or names | high | trivial | Comment says the hosted-testnet URL "belongs to the testnet target", and the check excludes harness/targets/testnet.sh — but the target never contains the URL. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:25` | Unhelpful comments or names | high | trivial | Header claims "The only `unsafe` in this crate is the generated module-impl scaffold", but author code carries two more `#[allow(unsafe_code)]` sites. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:36` | Unhelpful comments or names | high | small | `use rln_core as native;` plus eight "… FFI error/failed" log strings describe an FFI boundary that no longer exists; the crate is plain in-crate Rust. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:88` | Unneeded backwards compatibility | low | trivial | REG_IN_FLIGHT wraps its HashMap in Mutex<Option<…>> + get_or_insert_with only because HashMap::new is not const — a pre-1.80 idiom the crate's own rust-version rules out |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:88` | Unnecessary machinery or repeated work | low | trivial | REG_IN_FLIGHT is a Mutex<Option<HashMap>> whose Option exists only because HashMap::new() is not const; every access pays a get_or_insert_with that LazyLock (used in the sibling cr |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:109` | Unnecessary helpers | low | trivial | init_wallet_client() is a one-line forwarder to wallet_client() with a single caller. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:216` | Excessive defensiveness | low | trivial | strip_hex_prefix's `trimmed.len() >= 2 &&` guard is implied by starts_with("0x") |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:302` | Unhelpful comments or names | low | trivial | `fetch_account_data_quiet`'s doc lists "membership polls" as a user, but get_membership calls the tri-state fetch directly; the helper's only caller is register_member's pre-check. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:305` | Unnecessary helpers | high | trivial | fetch_account_data_quiet collapses FetchOutcome to Option for one caller; its doc names a second caller that does not use it. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:315` | Duplicated logic or state | medium | medium | fetch_account_data and fetch_account_data_tri_state each parse the get_account_public reply independently; the owner out-param then forces a second length validation in resolve_con |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:322` | Unhelpful comments or names | high | trivial | C++-era identifiers leak into logs and locals: `fetchAccountData` tags a function named `fetch_account_data`; `K_MAX_SNAPSHOT_ATTEMPTS` carries the C++ `k` prefix. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:336` | Too many branches | medium | small | fetch_account_data 'tolerates' an empty program_owner into a Vec out-param, but its only owner-requesting caller rejects anything not 32 bytes — the tolerance only relocates the fa |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:389` | Unnecessary helpers | high | trivial | words_to_json only exists because send_generic_tx takes pre-converted Vec<Value> and a pre-hexed program id; both callers repeat the same two conversions. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:419` | Unnecessary machinery or repeated work | high | small | funding_prologue is a 'shared funding-method entry' whose second user (mint_tokens) was removed at v2.0.0; it now serves claim_tokens alone. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:419` | Premature extensibility | low | small | funding_prologue is a generic 'funding-method entry' parameterised by `who`, but since v2.0.0 dropped mint_tokens it has exactly one caller and `who` is always "claim_tokens". |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:419` | Unnecessary helpers | low | trivial | funding_prologue ('Funding-method entry') has had exactly one caller (claim_tokens) since the repo's first commit; the 3-tuple it returns is an extra layer over three inline lines. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:464` | Unhelpful comments or names | high | trivial | Eight error logs say "FFI error"/"FFI failed" for calls into the in-crate plain-Rust rln_core; there is no FFI, and the strings were copied verbatim from the retired C++ module. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:487` | Excessive defensiveness | low | trivial | proofs_with_roots_json falls back to an empty JSON map when serializing ProofJson 'fails', a state the derive makes impossible — and the fallback would silently emit a proof with o |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:500` | Unnecessary helpers | low | trivial | get_valid_roots_impl exists only so the trait method can forward to it; nothing else calls it. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:547` | Excessive defensiveness | low | trivial | get_merkle_proofs coerces negative and fractional leaf indices through a three-way u64/i64/f64 chain with an unreachable `unwrap_or(0)`; its only caller sends a single non-negative |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:576` | Too many branches | medium | small | The stable-snapshot loop threads its result through three outer mutables (`proofs`, `stable_roots`, `consistent`) plus a post-loop `if !consistent` instead of returning on success  |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:598` | Too many branches | medium | small | The stable-snapshot loop threads success through three pre-declared mutables plus a subtree_fetch_errored flag with break-then-continue and a post-loop `if !consistent` |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:717` | Duplicated logic or state | high | trivial | The literal `>= 64` in register_member restates MEMBERSHIP_STATE_SIZE and the length check decode_membership already performs. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:717` | Excessive defensiveness | high | trivial | register_member's idempotency pre-check re-implements decode_membership's own length guard (`existing.len() >= 64`) as an extra nesting level. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:754` | Too many branches | high | small | register_member claims the REG_IN_FLIGHT slot before building the instruction, so it needs a rollback branch for an instruction-build failure that depends on nothing the slot prote |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:773` | Duplicated logic or state | medium | small | register_member submits the config account re-derived by register_plan while claim_tokens submits the resolved ctx.config_hex — two sources for the same fact. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:880` | Unhelpful comments or names | high | trivial | Section comment narrates a "v1.1 additive surface" and "the frozen methods" that the 2.0.0 contract no longer has; it points readers at a lidl that says nothing about v1.1. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:1001` | Unhelpful comments or names | low | trivial | Test name `hex_roundtrip_mirrors_cpp_hex_to_bytes` names a C++ function that no longer exists in this module; the test is a plain hex_to_bytes edge-case check. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:1050` | Low-value tests | high | small | The "legacy" half of augmented_proofs_match_legacy_string_roundtrip re-implements proofs_with_roots_json, so the equality asserts serde_json against itself; only the final byte pin |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/lib.rs:1076` | Low-value tests | medium | trivial | `merkle_proofs_input_validation_shortcircuits` claims early return before any wallet call, but the test transport also yields "" on failure, so 3 of 4 asserts cannot tell the two a |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:30` | Unnecessary machinery or repeated work | medium | medium | MerkleProofsPlan/RlnMerkleProof keep C-ABI-era fixed arrays plus counts (MAX_SUBTREES_PER_CALL=64, [..; TREE_DEPTH]) in a plain-Rust crate, forcing parallel-index juggling and an u |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:30` | Unneeded backwards compatibility | medium | medium | MerkleProofsPlan/RlnMerkleProof keep the lez-rln-ffi C-ABI shape (fixed 64-slot arrays + subtree_count, [..;TREE_DEPTH] + depth, MAX_SUBTREES_PER_CALL cap) in a module that has no  |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:210` | Excessive defensiveness | high | trivial | build_merkle_proof guards `&main_data[OFFSET_TOP_TREE_DATA..]` with an if/else although the length check four lines above already guarantees the slice is in bounds. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:272` | Duplicated logic or state | medium | small | The PDA seed recipes for the 'main' and 'subtree' accounts are spelled out twice inside rln_core (merkle_proofs_plan and register_plan) and a third time in its test; a label change |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:344` | Excessive defensiveness | high | trivial | merkle_proofs_exec's `.unwrap_or(&[])` fallback for a missing subtree silently proves against default nodes instead of failing, for a state the caller cannot produce |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:348` | Excessive defensiveness | high | trivial | merkle_proofs_exec substitutes an empty subtree when a leaf's subtree id is missing from `subtrees` — a state both callers make impossible, and one that yields a silently wrong pro |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:388` | Duplicated logic or state | medium | small | The tree-main and subtree PDA seed recipes are written twice in rln_core, and lib.rs/testnet_tests call merkle_proofs_plan with an empty leaf list six times just to obtain the main |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:480` | Unnecessary machinery or repeated work | medium | small | The token_core git dependency is carried solely to decode a 49-byte token holding that rln_layouts (already a dependency) describes as TokenHoldingLayout. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/rln_core.rs:490` | Unhelpful comments or names | medium | small | RlnError variants are reused for unrelated failures, so the logged text misleads: an NFT token holding logs "invalid config account data", an out-of-range tree depth logs "account  |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/testnet_tests.rs:300` | Duplicated logic or state | high | trivial | The live test asserts next_leaf_index < 1u64 << 20 with a literal 20 while its own message says 'inside TREE_DEPTH'; the value is owned by rln_layouts::TREE_DEPTH. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/testnet_tests.rs:327` | Low-value tests | low | small | `testnet_valid_roots_come_from_the_live_tree`: two of its three assertions hold by construction of get_valid_roots, and the third is subsumed by the proof-recompute test. |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/testnet_tests.rs:401` | Low-value tests | low | small | `testnet_membership_read_absent_or_decodes_with_live_state` asserts nothing on its documented normal path; a wrong membership-PDA seed also reads as absent, so it cannot catch the  |
| lez-module | `logos-rln-modules/logos-lez-rln-module/rust-lib/src/testnet_tests.rs:446` | Unhelpful comments or names | high | trivial | Comment claims the base58 vector is "pinned against the deployment record's config account", but no deployment record carries that account — it belongs to a retired deployment. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:31` | Unhelpful comments or names | high | trivial | Crate header documents the error envelope as {"error":{"kind","message"}} — it omits the `class` field, the one consumers are told to switch on. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:263` | Unnecessary helpers | low | trivial | public_membership_json forwards five args verbatim to views::MembershipView::new, adding only a serialization policy (unwrap_or(Null)) that differs from ok_json, used by every othe |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:285` | Unnecessary helpers | low | trivial | records_for_registry(store, registry) is a pure pass-through to store.records_for(&registry.canonical) with no added contract. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:308` | Unneeded backwards compatibility | medium | small | scope_matches keeps a 'pre-scope legacy record' branch (empty rln_identifier backs every scope) for records the sealed store can never contain. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:362` | Unnecessary machinery or repeated work | high | small | flat_bool_option/flat_str_option re-check that option values are JSON strings, a property parse_registry_options already established for every entry in the map they read. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:364` | Excessive defensiveness | high | small | flat_bool_option's JSON-bool arm and flat_str_option's non-string arm reject values parse_registry_options already made impossible, forcing Result plumbing through register_impl. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:500` | Duplicated logic or state | medium | small | funded_submit_callback and delegated_submit_callback duplicate the whole fire-and-record shell (Weak upgrade, update_cache, submit-error policy, store-closed error, logging); only  |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:605` | Excessive defensiveness | low | trivial | REGISTER_IN_FLIGHT is a Mutex<Option<HashSet>> only because HashSet::new isn't const, so RegisterClaim::take lazily inserts and Drop guards a None that cannot exist while a claim i |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:758` | Excessive defensiveness | high | small | register_impl round-trips the freshly generated commitment through hex and guards a 'generated commitment is not 32 bytes' failure the generator cannot produce. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:849` | Too many branches | high | trivial | get_membership_state_impl branches on the same `store` Result twice: once to degrade a missing store to no records, then again with a comment asserting the second `?` can't fail. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:864` | Duplicated logic or state | medium | small | The membership-state transition write (pending→active field set, confirmation_window_elapsed, removed_from_registry) and the event emit are maintained in both get_membership_state_ |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:945` | Excessive defensiveness | medium | small | select_membership_impl re-searches `records` for the hash select_hash just picked out of the same `records` and handles a 'selected record vanished' case that cannot occur. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:945` | Unnecessary machinery or repeated work | high | small | select::select_hash returns only a hash String, so both callers re-search for the record they just selected and carry a 'selected record vanished' error branch. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1171` | Code in the wrong place | high | trivial | json_str_array/json_u8_array decode a provider get_merkle_proof reply but live in lib.rs, whose only remaining callers are in path_cache.rs; the 'Shared with path_cache.rs' rationa |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1217` | Duplicated logic or state | high | trivial | The timestamp freshness gate (epoch_of_timestamp + current_epoch + epoch_in_window + the same InvalidArgument text) is copy-pasted between generate_proof_impl and get_epoch_quota_i |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1254` | Unnecessary machinery or repeated work | low | small | On a path-cache miss generate_proof_impl calls fill_path_cache (fetch+decode+insert) then hit() again to re-lock and clone back the path it just decoded, plus a 'vanished' error br |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1521` | Duplicated logic or state | medium | medium | 'Which store is open' lives in two places (the impl's RwLock<StoreCell> and the global published slot) and handlers are split between them, so the cell's Unready(cause) reaches onl |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1569` | Duplicated logic or state | medium | small | on_context_ready's empty-path branch re-implements open_store's close→unpublish→replace-cell prefix instead of sharing it. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1575` | Unnecessary machinery or repeated work | high | trivial | OpenError::NoPersistencePath is constructed once, only to be Display'd straight back into the same string it was built from. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:1771` | Unhelpful comments or names | low | trivial | `seed_membership` doc narrates history against a type (`MembershipMeta`) that no longer exists anywhere in the crate or sibling repos. |
| rln-lib | `logos-rln-modules/logos-rln-module/rust-lib/src/lib.rs:2625` | Unhelpful comments or names | low | trivial | Test comment misattributes why the warm-up is harmless: `tracked` is empty because the config names no registries, not because no membership exists; the path warm-up runs regardles |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/keychain.rs:28` | Unhelpful comments or names | high | trivial | Module doc's caveat about "deleting an auto-created account's item" describes the pre-feea675 design; self-provisioning no longer writes a keychain item, it writes rln_autounlock.s |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/keychain.rs:125` | Unhelpful comments or names | high | trivial | The Unavailable backend doc says "every call maps to keychain_unavailable", but a read failure is folded into a noted miss and a fresh store still self-provisions successfully. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:94` | Unhelpful comments or names | high | trivial | The `epoch` field doc (and epoch() at 274-276) says an epoch-less proof is 'resolved by scanning'; validate_proof never scans — the epoch derives from the timestamp. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:130` | Unhelpful comments or names | high | trivial | root() doc says the decoded root 'serves tests' and is cfg-allowed dead in prod, but production validate_proof reads it for the root-window check. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:134` | Unhelpful comments or names | high | trivial | root() is documented and cfg-attributed as a tests-only decoded view, but production validate_proof_impl calls it for the root-window check. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:134` | Dead or unrelated code | high | trivial | RateLimitProof::root() carries a stale #[cfg_attr(not(test), allow(dead_code))] and a doc claiming it "serves tests", but production validate_proof calls it. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:243` | Unnecessary machinery or repeated work | medium | medium | A wire proof is Groth16-deserialized/serialized up to five times per validate_proof call because RateLimitProof keeps only bytes and re-parses them for verify |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:370` | Unhelpful comments or names | high | trivial | `fr_to_u32` and `secret_to_u32` return `[u8; 32]`; "u32" reads as the Rust integer type, and the crate's own name for this shape is `bytes32`. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:379` | Duplicated logic or state | high | trivial | fr_to_u32 and secret_to_u32 are the same 32-byte LE serializer written twice for two CanonicalSerialize types |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:531` | Duplicated logic or state | low | small | generate_for_test rebuilds the seeded witness material and zero path that tests::material_from_seed/zero_path already build; lib.rs tests rebuild the zero path and epoch[32] encodi |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/proof.rs:794` | Low-value tests | high | trivial | epoch_survives_generate_and_json_roundtrip rebuilds json_roundtrip_preserves_verification's exact fixture to add two epoch() assertions. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/crypto.rs:20` | Premature extensibility | high | trivial | `CryptoError::Unsupported` is a variant reserved for 'format evolution' that nothing constructs, kept alive only by `#[allow(dead_code)]` and a Display arm. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/crypto.rs:23` | Dead or unrelated code | high | trivial | CryptoError::Unsupported is never constructed; it exists only behind #[allow(dead_code)] with a comment admitting nothing builds it. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/crypto.rs:226` | Low-value tests | high | trivial | kdf_runs_counts_each_derive asserts only that the cfg(test) KDF_RUNS counter increments — it tests the test instrumentation, and defers the real claim to store.rs. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/format.rs:72` | Duplicated logic or state | medium | medium | format::Section/AllocRow and rate_limit::AllocationState/EpochAllocation are one shape kept as two struct families with hand-written mapping both ways; the runtime pair carries unu |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/format.rs:296` | Low-value tests | high | trivial | section_payload_is_input_order_independent re-proves what the golden vector already freezes (sorting) and asserts a `&[AllocRow]` argument was not mutated, which the type forbids. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/format.rs:366` | Low-value tests | low | trivial | file_cap_... and detect_covers_all_four_presence_states unit-test 3-line fs probes whose every branch is already driven through Store::open by the store.rs matrix. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/format.rs:390` | Low-value tests | low | trivial | The two *_roundtrips_through_json tests assert serde-derive roundtrips of the schemas; the real on-disk roundtrip is exercised by every store.rs open→close→reopen test. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/fs.rs:51` | Duplicated logic or state | high | small | write_durable and write_atomic_loose duplicate the whole tmp-open-0600-write-rename body; only the two sync calls differ |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/hex.rs:1` | Unhelpful comments or names | high | small | The header justifies a private hex copy with a "sealed store's public surface" boundary that no longer exists; registry_id.rs has byte-identical helpers and both homes are used sid |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/hex.rs:1` | Premature extensibility | high | small | `sealed_store/hex.rs` is a byte-identical copy of `registry_id::{bytes_to_hex, hex_to_vec}` kept for a subcrate extraction that was abandoned; store.rs already imports `registry_id |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/hex.rs:4` | Duplicated logic or state | high | trivial | sealed_store/hex.rs is a byte-for-byte copy of registry_id.rs's bytes_to_hex/hex_to_vec, and its stated reason for existing no longer holds |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:85` | Duplicated logic or state | medium | small | Inner.store_uuid is a second home for SealedFile.store_uuid, kept in sync by hand and re-guarded at four sites that already hold `sealed` |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:284` | Excessive defensiveness | medium | small | Five `let Some(..) else` refusals guard a sealed/store_uuid desync that the store's own invariant makes impossible (the pair is only ever assigned together). |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:337` | Duplicated logic or state | high | trivial | store.rs re-inlines `hex_to_vec(..).and_then(\|v\| <[u8; 32]>::try_from(v).ok())` four times although registry_id::hex_to_bytes32 is exactly that and is already used in the same fi |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:402` | Unhelpful comments or names | high | trivial | `#[allow(dead_code)] // consumer surface: views read the record's flag; the tests read this` on is_quarantined claims a consumer that does not exist; the method is test-only. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:402` | Dead or unrelated code | high | trivial | Store::is_quarantined is a test-only accessor compiled into production under #[allow(dead_code)]. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:451` | Excessive defensiveness | medium | small | Store::insert checks the session three times (and store_uuid/sealed twice) in one critical section where nothing between the checks can change them. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:679` | Excessive defensiveness | medium | small | `remaining_budget` clones the whole allocation section with an `unwrap_or_default()` fallback for a credential-without-section state that load and insert already turn into quaranti |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:764` | Too many branches | medium | small | reservation_guards takes Option<&AllocationState> and answers UnknownMembership for None, but reserve_message_id re-handles None immediately after and remaining_budget never passes |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:800` | Duplicated logic or state | medium | small | The '.bad.<unix-ts>' quarantine rename is implemented three times (fs.rs load_json, store.rs quarantine_file, keychain.rs quarantine_secret_file), one with its own copy of now_unix |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:1114` | Duplicated logic or state | high | trivial | write_cache rebuilds the cache-file header by hand while CacheFile::new() already defines it and has no other caller |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:1143` | Duplicated logic or state | high | trivial | Snapshot.has_credentials stores `!records.is_empty()` as a separate field instead of deriving it |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:1489` | Low-value tests | high | trivial | close_then_reopen_preserves_state is a strict subset of two neighbouring tests that already close, reopen, unlock == 1 and read the membership back. |
| rln-proof-keystore | `logos-rln-modules/logos-rln-module/rust-lib/src/sealed_store/store.rs:1522` | Unhelpful comments or names | low | trivial | Test comments cite audit-finding labels ("L1", "(I2b)") and a past bug name ("the suppressed-escalation reissue path") that resolve nowhere in the repo. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:70` | Dead or unrelated code | high | small | StoredCredential.identity_nullifier / identity_trapdoor (lines 69-73) are always None and never read: dead optional fields on the sealed credential. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:224` | Code in the wrong place | medium | small | Self-described storage-agnostic lifecycle.rs hosts on-disk shapes (CacheFile, FORMAT_CACHE, StoredCredential); store.rs rebuilds the cache header by hand and lifecycle's constructo |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:229` | Code in the wrong place | high | small | The cache sidecar's on-disk schema (CacheFile, FORMAT_CACHE) lives in the 'storage-agnostic' lifecycle module while its file name and version live in sealed_store/format.rs |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:236` | Dead or unrelated code | high | trivial | CacheFile::new() and impl Default for CacheFile (lines 235-249) have no caller; the store builds the struct literal by hand. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/lifecycle.rs:320` | Low-value tests | low | trivial | `first_active_at_semantics` re-asserts two cases that `merge_state_matrix` already asserts verbatim. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/panic_hook.rs:26` | Unhelpful comments or names | high | trivial | Panic log lines are prefixed "rln_membership:", a module name that exists nowhere else in the tree; every other log line in the crate uses a "membership ..."/"roots ..." prefix. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/path_cache.rs:50` | Unneeded backwards compatibility | high | trivial | `if let Ok(roots_hex) = json_str_array(&merkle, "valid_roots")` tolerates 'older providers' that omit valid_roots, but the only provider has always emitted it. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/path_cache.rs:80` | Low-value tests | low | trivial | `cold_hash_misses` asserts that a never-inserted key is absent from a HashMap. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/path_cache.rs:96` | Low-value tests | medium | trivial | `refresh_overwrites_the_prior_entry` exercises only the cfg(test) helper `set_path_for_test` (a HashMap insert); the production writer `fill_path_cache` never runs. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:24` | Unhelpful comments or names | high | trivial | Module doc references a `provider_call` function and an "owner-thread contract" that no longer exist anywhere in the crate. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:46` | Unnecessary helpers | low | trivial | `poller::ensure_running` only forwards to `worker::ensure_poller`, whose doc already states the same idempotent/no-op-while-stopped contract. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:70` | Duplicated logic or state | high | trivial | `observe` and `refresh_paths` each parse the record's registry_id, log the identical "bad stored registry_id" message, and route to the provider. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:98` | Duplicated logic or state | high | small | `RecordUpdate` is a second encoding of `ProviderMembership`'s registered/absent split; every consumer re-derives it from the `registered: bool` + `Unknown` placeholder. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:131` | Duplicated logic or state | high | trivial | `emit_transition` (transition_event → destructure 5-tuple → emit_membership_state_changed) is duplicated verbatim in lib.rs get_membership_state. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:176` | Duplicated logic or state | medium | medium | The poller re-implements lifecycle::merge_state's pending→failed / absent→erased rules and lib.rs's persistence closure inline, and the two copies already disagree for Unknown reco |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/poller.rs:265` | Excessive defensiveness | high | trivial | `record.cache.leaf_index.unwrap_or(0)` defaults a usable membership's leaf to 0 — a state the store makes impossible, and the one fallback provider.rs says must never happen. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/provider.rs:111` | Unnecessary machinery or repeated work | high | small | `read_reply` and `fold_reply` implement the same ""→provider_failure fold twice, and `await_reply` is generic over T yet every use is String wrapped in `read_reply`. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/provider.rs:304` | Unhelpful comments or names | medium | small | `provider_failure`'s message "failed (empty reply)" is attached to every failure class, transport errors and channel timeouts included, so the wire message misleads. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/provider.rs:328` | Excessive defensiveness | high | trivial | `v.get("registered").and_then(as_bool).unwrap_or(false)` turns a reply missing the key into the destructive 'not registered' signal the sibling is careful never to emit spuriously. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/provider.rs:375` | Excessive defensiveness | medium | trivial | register_async's `if options_json.trim().is_empty() { json!({}) }` branch (375-381) handles an empty string the only caller can never pass. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/rate_limit.rs:69` | Excessive defensiveness | none | trivial | `now_unix / epoch_size_sec.max(1)` guards a zero epoch size that start() and the override parser already reject. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/rate_limit.rs:225` | Unhelpful comments or names | high | trivial | Test comments cite "Audit cause B" / "Audit cause D", labels from an external audit report that is not in the repository, so a reader cannot resolve them. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/roots.rs:104` | Unnecessary helpers | low | trivial | `roots::ensure_refresher` is a pure forward to `worker::ensure_refresher` with a single caller (`roots::track`). |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/roots.rs:163` | Duplicated logic or state | medium | small | The window insert is written three times in roots.rs, and the roots hex-decode (silently dropping bad entries) is written in both roots.rs and path_cache.rs. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/roots.rs:191` | Low-value tests | low | trivial | `cold_registry_has_no_window` asserts a HashMap miss for a never-inserted key; the meaningful cold case (stale window) is already tested elsewhere. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/views.rs:88` | Unneeded backwards compatibility | medium | small | The empty-"legacy" rln_identifier branches (views.rs:88-89, lifecycle.rs:194-195 doc, lib.rs:305-309 scope_matches `\|\| is_empty()`) shim pre-scope records no loadable keystore ca |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/views.rs:158` | Unhelpful comments or names | high | trivial | `StartReply` doc says "all fields are always present" but `overrides` is skipped when None, which is the common case. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/worker.rs:35` | Duplicated logic or state | medium | small | `STOPPED` AtomicBool is a second copy of `Supervisor.state == Stopped`, hand-synchronised at three sites; the stated lock-free rationale does not hold for its callers. |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/worker.rs:276` | Unhelpful comments or names | high | trivial | Two differently named cfg(test) accessors return the same field: `generation()` (line 276) and `generation_for_test()` (line 130) are identical, implying a distinction that does no |
| rln-runtime | `logos-rln-modules/logos-rln-module/rust-lib/src/worker.rs:276` | Duplicated logic or state | high | trivial | `generation()` and `generation_for_test()` are two identical `#[cfg(test)]` accessors for the same field. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/Main.qml:88` | Premature extensibility | medium | trivial | `detailReturnMode` records "where detail was opened from", but detail has exactly one origin (the status list), so it is always "status" — its declared default. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/MembershipCard.qml:209` | Unnecessary machinery or repeated work | high | trivial | leaf/rate are stored as pre-formatted display strings and then decoded back to undefined at render so a second formatter can re-encode the same 'missing' case. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/MembershipRow.qml:62` | Unhelpful comments or names | medium | small | `regState()` returns a progress-segment status while `flow.regState` in the same scope is the wire MembershipStatus; StepProgress adds a third name, `syncStatus`, for the same comp |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingFlow.qml:1` | Unhelpful comments or names | medium | trivial | Header states the phase order as wallet -> sync -> password -> claim -> register, but the password is checked before the wallet phase (create_new consumes it); header and A-E lette |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingFlow.qml:29` | Unhelpful comments or names | medium | small | `mnemonic` is justified by a comment about a future surface that does not exist; the property is write-only, and the README claims the wizard shows the mnemonic once, contradicting |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingFlow.qml:142` | Dead or unrelated code | low | trivial | `signal completed(string commitment)` carries an argument its only listener discards; `finish()` exists just to forward it. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingFlow.qml:158` | Duplicated logic or state | high | trivial | The one-shot delayed-call idiom (createObject Timer, connect triggered -> destroy + callback, start) is hand-written three times in the flow. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/OnboardingView.qml:20` | Unhelpful comments or names | high | trivial | `flowController` is documented as a test-only, prod-inert handle, but it is the production seam Main.qml uses for callRetry and for the list/detail views' required `flow`. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/RegisterView.qml:5` | Unhelpful comments or names | high | trivial | Header and property comments say Main.qml wires WalletView.funded into fundingAccount; the wiring lives in AdvancedView.qml and Main.qml never references WalletView or funded. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/StepProgress.qml:17` | Duplicated logic or state | high | trivial | StepProgress.syncStatus re-states MembershipRow.syncState()'s wallet+sync folding rule and is referenced nowhere. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/StepProgress.qml:17` | Dead or unrelated code | high | trivial | `syncStatus` is a readonly property nothing reads; the same wallet+sync fold that the bar actually uses lives in MembershipRow.syncState(). |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/StepProgress.qml:48` | Code in the wrong place | medium | small | Phase chaining is split: wallet->sync lives in the controller, but sync->funding and funding->registration live in a view's Connections/entered(). |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/StepProgress.qml:115` | Duplicated logic or state | medium | small | Two design-system workarounds are copy-pasted instead of componentised: the 'LogosButton text:"" + overlay LogosText' label hack (3 copies) and the LogosTextField font-lift block ( |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/WalletView.qml:154` | Unhelpful comments or names | high | trivial | runSyncAttempt's comment promises "progressTimer surfaces movement meanwhile", while the same function's next comment and the flow controller say the wallet serves no reads during  |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/WalletView.qml:214` | Duplicated logic or state | high | trivial | The suggested-claim formula (rate x price x 1.2, ceiled) is re-implemented inline instead of calling M.suggestedClaimAmount, contradicting the README's 'pure formulas live once in  |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:16` | Dead or unrelated code | medium | trivial | `LIBP2P_MODULE` is defined but never referenced; every libp2p call is relayed through `rln_gifter_module.libp2p_call`. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:69` | Unhelpful comments or names | medium | trivial | GIFTER defaults comment points at `tools/run-local-gifter.sh`, a script that exists nowhere in the workspace. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:112` | Unhelpful comments or names | medium | trivial | LOCAL_ERROR_CLASS is documented as "the kinds this file mints locally", but its `timeout` entry (and TRANSIENT_ERROR_KINDS.timeout) is never minted: a bridge timeout becomes `bridg |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:117` | Dead or unrelated code | medium | trivial | The `timeout` error kind in LOCAL_ERROR_CLASS (:117) and TRANSIENT_ERROR_KINDS (:371) has no producer anywhere; the bridge timeout arrives as kind `bridge_failure`. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:369` | Duplicated logic or state | medium | trivial | Which locally minted error kinds are transient is declared twice: LOCAL_ERROR_CLASS and TRANSIENT_ERROR_KINDS list the same four kinds. |
| ui-qml | `logos-rln-modules/logos-rln-membership-ui/qml/membership.js:385` | Unneeded backwards compatibility | high | trivial | isTransientError's bare-kind-string branch serves a caller shape (`isTransientError(err.kind)`) that no longer exists in this repo and that CLAUDE.md forbids. |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/lez-module.yml:21` | Duplicated logic or state | medium | small | rln-module.yml and lez-module.yml are the same six-step cargo job with the module directory swapped, and they have already diverged (rustfmt, a nix `.lgx` job) without a stated rea |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/release.yml:78` | Duplicated logic or state | medium | small | The external-checkout + lez_core shadow-version block (two checkouts and the jq re-version step) is pasted verbatim into all three jobs; the env comment's removal recipe has to enu |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/release.yml:198` | Excessive defensiveness | medium | small | The darwin Metal-toolchain install and `--option sandbox false` run for every darwin module build, though only the temporarily shadowed lez_core needs them; the shadow's removal no |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/release.yml:217` | Unnecessary machinery or repeated work | high | trivial | release.yml (and publish.sh:53-56) run `nix run …#generate` before `nix build …#lgx-portable`, but the builder stages the SDK and regenerates the scaffold in-derivation; the pre-st |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/rln-module.yml:36` | Unnecessary machinery or repeated work | low | trivial | The cargo job installs the rustfmt component and is named "cargo (fmt, clippy, test)", but no step ever runs `cargo fmt`. |
| ui-tests-tooling | `logos-rln-modules/.github/workflows/rln-module.yml:53` | Unhelpful comments or names | high | trivial | CI comment says the keychain tests 'drive the live macOS keychain', but they run against an in-memory fake; the resulting `--skip keychain` silently drops every keychain.rs test on |
| ui-tests-tooling | `logos-rln-modules/flake.nix:66` | Unhelpful comments or names | low | trivial | Root-flake comment says 'The sim builds with --override-input logos-lez-rln-module' but no caller overrides that input; harnesses override their own `rln-modules` input, and 'the s |
| ui-tests-tooling | `logos-rln-modules/logos-lez-rln-module/stage-sources.sh:3` | Unhelpful comments or names | low | trivial | The script header narrates what it no longer does ('there is no separate SDK_REV to keep in step any more') instead of saying who it exists for. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:34` | Unhelpful comments or names | low | trivial | Helper `phase(app, prop)` is a generic flowController property read, but its name suggests a phase; call sites read `password`, `fundError`, `regError`, `unlockError` through it. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:90` | Unhelpful comments or names | high | trivial | Comment cites 'docs/wire-binding.md "Error envelope"' as if local to the UI; the file lives in logos-rln-module/docs/, and the UI has no docs/ directory. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:172` | Unhelpful comments or names | low | trivial | The mock's register_membership case repeats verbatim the commitment-selection comment already written at the COMMIT/COMMIT2 declaration. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:384` | Low-value tests | low | small | Scenario 5c (relaunch with one membership never celebrates) is a subset of scenario 5b's preamble plus texts scenario 1 already asserts. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/flow-tests.mjs:487` | Low-value tests | low | small | Scenario 9 tests a pure, stateless string function (M.petname) for determinism and shape that scenarios 1 and 5b already assert; only the empty-input case is new. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-membership-ui/tests/ui-tests.mjs:5` | Unhelpful comments or names | high | trivial | Header lists the status card, post-password step progression and the wizard->card handoff as 'Hermetically untestable', but flow-tests.mjs in the same directory tests all three her |
| ui-tests-tooling | `logos-rln-modules/logos-rln-module/flake.nix:25` | Unhelpful comments or names | high | trivial | Flake comment claims 'Concurrency stays at the single default', contradicted by metadata.json ("multi") and by this same file's generate app passing `--concurrency multi`. |
| ui-tests-tooling | `logos-rln-modules/logos-rln-module/flake.nix:71` | Duplicated logic or state | high | trivial | The generate app hardcodes `--concurrency multi`, duplicating metadata.json's `concurrency` that the builder reads for the real build; the same flake's comment has already drifted  |
| ui-tests-tooling | `logos-rln-modules/tools/catalog-gen.py:19` | Unhelpful comments or names | high | trivial | REPO_HOMEPAGE in the generated catalog descriptor points at logos-co/logos-lez-rln, while every other release surface (publish.sh signer URL, release.yml BASE_URL/README) names log |
| ui-tests-tooling | `logos-rln-modules/tools/publish.sh:7` | Unhelpful comments or names | high | trivial | publish.sh's header rationale (official-catalog wallet, 'our three') contradicts release.yml, which shadows the wedging official lez_core and adds the UI's gifter deps. |
| ui-tests-tooling | `logos-rln-modules/tools/publish.sh:59` | Duplicated logic or state | high | small | publish.sh is a second copy of the release pipeline that has drifted from release.yml: 3 modules vs 8, no lez_core shadow, an unreferenced release repo, and a catalog missing the U |
