# Slot-reissuance audit — full re-review record against PR #9

**Internal working document — verbose by design. The auditor-facing companion is
`audit-response.md`.** Uncommitted; lives only in the working tree.

- Audit: "slot reissuance" (Medium, Open), one invariant, causes A–E, recommendations
  R1–R5, filed against commit `d998344d` (2026-08-10).
- Remediation under review: **PR #9** — https://github.com/logos-co/logos-rln-modules/pull/9 —
  branch `feat/keystore`, head `7f1f09ce60924a01bc216c8e579167b045294efb`, base
  `origin/main` @ `f3a53934`. Two commits: `734c92c` (the sealed-store rewrite,
  +4556/−1872 over 26 files) and `7f1f09c` (docs/comment trim, no code).
- Method of this re-review: two independent exploration passes over the tree **at
  `7f1f09c`** (one mapping each audit item to its mechanism, one auditing provenance,
  test coverage, and every prose guarantee), verbatim spot-checks of the load-bearing
  quotes against `git show 7f1f09c:<path>`, a full test-suite re-run at `7f1f09c`, and a
  scripted citation check of every line reference used in these two documents.
  All line numbers below are at `7f1f09c`; permalinks use that SHA.

Permalink base: `https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/`
(prefix `logos-rln-module/rust-lib/src/` implied for bare `.rs` paths below).

---

## 0. Provenance — what the PR diff actually is

Three facts frame everything else:

1. **The audited commit is an ancestor of the PR base, and every cause was still live
   at the base.** `d998344d` is an ancestor of `f3a53934` (verified with
   `git merge-base --is-ancestor`). At `f3a53934`: `keystore.rs:336-342` is still the
   bare `fs::write` + `fs::rename` with zero `sync_all`/`F_FULLFSYNC` hits repo-wide;
   `keystore.rs:147-158` (the audit's R5 target, `MembershipMeta` with plaintext
   `allocations`) is **byte-identical** to the audited text; there is no
   `prune_floor`/`EpochRewound`/lock anywhere; `README.md:133` still says "a crash may
   waste a slot but never double-spends one". So the fix is not partially inherited
   from main — **100 % of the A–E remediation is inside PR #9's own diff.**
2. **The intermediate remediation generation was abandoned, not merged.** The branches
   whose names sound like the fix (`fix/audit-slot-reissuance` @ 8fba133,
   `feat/keystore-hardening` @ 6273d22, `refactor/keystore-sealed-store` @ e0fec6c,
   `refactor/keystore-tier1` @ 1feb716, `fix/sealed-store-audit-followups` @ 0ec3dbf)
   are in **neither** main's nor PR #9's ancestry. PR #9 is a from-scratch rewrite of
   the audited layer that squashes what those generations learned. History for the
   record: generation 1 (MAC-sidecar: HMAC over the plaintext sidecar + persisted
   floor + dir lock, its own 15-finding adversarial review) was superseded by
   generation 2 (the sealed store), which then survived its own re-audit round — see
   §7 (the H1 story).
3. **The only audit-adjacent change PR #9 inherits from main is caller-supplied
   timestamps** (`44eef59`, merged as part of PR #8): epochs derive from a caller
   timestamp, not the module's wall clock (`epoch_of_timestamp`, `lib.rs:1094-1101` —
   present at the audited commit too). That is a *precondition of the audit's threat
   model* (cause B is about the retain floor's clock, not the epoch's), not a
   mitigation. Everything below is PR #9's own diff.

What the diff does structurally: deletes `keystore.rs` (446 lines) and `store.rs`
(665 lines) — the two files carrying causes A, C, and E — and replaces them with
`sealed_store/{crypto,format,fs,hex,store}.rs` (+ `lifecycle.rs`, + the new
`docs/keystore-format.md`). The audit's file:line targets therefore no longer exist;
each cause below maps the old claim to the new mechanism.

---

## 1. Cause A + R1 — durability of the counter write

**Audit claim.** `save_atomic` = `fs::write(tmp)` + `rename`, no fsync of file or
directory; rename gives atomicity, not durability; every `generate_proof` rewrites the
whole keystore JSON, so a power cut can resurrect a lower `used` count than the proofs
already on the wire.

**Mechanism now.** All durable writes go through one function,
[`sealed_store/fs.rs:14-38` `write_durable`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/fs.rs#L14-L38)
(verified verbatim):

```rust
let mut f = opts.open(&tmp)?;           // 0600 at creation + set_permissions
f.write_all(bytes)?;
sync_or_warn(&f, file_name)?;           // fsync(tmp) BEFORE the rename
drop(f);
fs::rename(&tmp, dir.join(file_name))?;
#[cfg(unix)]
sync_or_warn(&fs::File::open(dir)?, "parent dir")?;   // directory fsync AFTER
```

- This is the audit's exact ordering: data durable before the rename, the rename (a
  directory-entry update) itself forced out.
- macOS: the code does **not** call `fcntl(F_FULLFSYNC)` itself; it relies on Rust std
  mapping `File::sync_all` to `F_FULLFSYNC` on Apple targets. The module doc declares
  this a load-bearing assumption ([`fs.rs:1-8`]: "plain `fsync` does not survive a
  power cut on APFS … the only build targets are darwin and linux, so that mapping
  always applies"). See finding **G1** — this is the one durability claim that is
  asserted rather than demonstrated.
- Fsync failure policy ([`fs.rs:82-93` `sync_or_warn`]): only
  `io::ErrorKind::Unsupported` (network/FUSE mounts that cannot sync) degrades — with
  a loud stderr warning; every other error propagates and the write **fails closed**
  (no proof is issued, see below).
- **R1's structural suggestion is adopted in its intent, adapted in its letter.** The
  audit asked for a "small append-only file" for the hot path. The shipped design
  splits by *trust class* instead ([`sealed_store/format.rs:14-19`],
  `docs/keystore-format.md:9-22`): `rln_sealed.json` (encrypted credentials — written
  only on provisioning [`store.rs:272`] and `insert` [`store.rs:462`]),
  `rln_allocations.json` (the counters — the **only** file `generate_proof` writes,
  via `reserve_message_id` → `write_allocations` → `write_durable_json`,
  [`store.rs:637`] → [`store.rs:1094`]), and `rln_cache.json` (registry-healed cache,
  deliberately loose: [`fs.rs:51-71` `write_atomic_loose`] has **no fsyncs**, its
  comment restricts it to the cache, and its sole call site is [`store.rs:1107`]).
  The credential store is no longer rewritten per proof — the audit's "window open on
  every outbound message" is gone. The counter file is *not* append-only:
  `write_allocations` ([`store.rs:1036-1099`]) re-serializes and re-MACs all sections
  each reservation, bounded at ≤1024 sections × ≤4096 rows
  ([`format.rs:163-165`]) — an O(store) small rewrite, accepted because fsync cost
  dominates write size and an append-only log would need its own compaction +
  authentication story.
- **Failure-direction semantics** (the half R1 doesn't state): on a persist error no
  proof is issued and the in-memory counter deliberately stays advanced — in-process
  the slot can only be *wasted*; after restart the disk count equals the proof-backed
  count. Pinned by [`store.rs:1755` `persist_failure_wastes_slot_never_reissues`]
  (chmods the dir to 0o500, asserts the reservation errors `internal`, then asserts
  the next successful reservation *skips* the burned slot — remaining budget 3 → next
  slot allocated leaves 2, never a reuse).

**Tests.** `persist_failure_wastes_slot_never_reissues` [`store.rs:1755`];
`insert_crash_windows_are_inert_or_healed` [`store.rs:1976`] (pre-commit leftovers
inert, post-commit cache loss heals, zero quarantines);
`missing_is_default_write_roundtrips_and_is_private` [`fs.rs:165`] (roundtrip + 0600);
`unparseable_is_quarantined_not_overwritten` [`fs.rs:184`] (`.bad.` evidence file);
`loose_write_roundtrips_is_private_and_replaces` [`fs.rs:210`] (no `.tmp` left).
The fsync *ordering* itself is untestable in CI and says so in the module doc
([`fs.rs:1-8`], `docs/keystore-format.md:20-22`) — verified by inspection only.

**Residuals.** Real power-cut behavior untested (no crash injection); the
`Unsupported`-degrade branch untested; directory fsync is Unix-only; G1 (macOS
mapping assumption + ubuntu-only CI).

**Verdict: A closed (by inspection + adjacent tests), R1 adopted with a defensible
delta (trust-class file split instead of append-only log).**

---

## 2. Cause B + R2 — the clock-rewind floor

**Audit claim.** `retain_floor = now_epoch - epoch_gap()` recomputed from the wall
clock per call; prune at a high clock, step the clock back, and the pruned epoch
re-enters the window with no row → slot 0 reissued. Required rewind ≈ one epoch beyond
the acceptance window (~minutes).

**Mechanism now.** The allocator carries a **persisted, monotonically non-decreasing
floor**: `AllocationState.prune_floor` ([`rate_limit.rs:49-50`]), serialized into the
counter file's per-membership `Section` ([`format.rs:75`]) **inside the section MAC**
([`format.rs:126`]) — the audit's own condition "the floor is only trustworthy once R1
and R3 land" is honored: the floor is durable (§1) and authenticated (§3). Reservation
logic ([`rate_limit.rs:85-106`, `129-130`], verified verbatim):

```rust
let threshold = match highest {                       // highest allocated epoch AT OR
    Some(h) => alloc.prune_floor.max(retain_floor_candidate.min(h)),  // BELOW candidate, +1
    None => alloc.prune_floor,
};
if epoch < threshold { return Err(AllocError::EpochBelowFloor); }   // before ANY mutation
...                                                    // allocate first, then:
alloc.prune_floor = threshold;                         // floor only ever rises
alloc.allocations.retain(|a| a.epoch >= threshold);    // prune ⇔ floor-advance, inseparable
```

- `AllocError::EpochBelowFloor` ([`rate_limit.rs:60-62`]) maps to the wire's
  `permanent` error kind via `floor_refusal()` ([`store.rs:776-783`], call site
  [`store.rs:634`]) — a rewound clock now answers a permanent, explained refusal
  instead of silently minting a colliding proof. `remaining_budget` mirrors the
  refusal ([`store.rs:668-670`]) so `get_epoch_quota` never advertises what reserve
  will refuse.
- The wall-clock expression survives only as a **candidate** the allocator max-folds
  ([`lib.rs:1055`], comment [`lib.rs:1051-1054`]) — never an authority. That the
  acceptance floor and the retention floor were *the same expression read at two
  different times* was the underlying bug; they are now decoupled.
- **Why not the audit's literal R2 snippet** (`prune_floor.max(retain_floor)` raised on
  every call): the same hostile-clock class spikes *forward* — one reservation under a
  year-2100 clock would persist an astronomical floor, and monotonicity then bricks
  every honest epoch **forever** (recovery = re-staking). The shipped floor advances
  only on *actual pruning*, capped at one past the highest allocated epoch at or below
  the candidate. This loses zero safety — an epoch with no allocation row has no spent
  slots, so re-serving it cannot collide; the refused set stays exactly the at-risk
  set. Pinned by the no-brick pair [`rate_limit.rs:240` / `:256`] (a literal-R2
  implementation fails these).
- **Error paths mutate nothing** ([`rate_limit.rs:104-106`], pinned by
  [`rate_limit.rs:269` `failed_reservations_mutate_nothing`]) — required because the
  store re-MACs sections only on success; a mutating error path would desynchronize
  memory from its MAC and false-quarantine an honest credential later.
- Restart path: floor loaded at open ([`store.rs:972`]), proven end-to-end by
  [`store.rs:1215` `reservation_floor_and_epoch_size_survive_restart`] (reserve at
  epochs 10 and 12 → close → reopen → epoch 10 answers `Permanent`; epoch 12 resumes
  at slot 1, never a fresh 0).

**Tests.** [`rate_limit.rs:224` `rewound_clock_never_reissues_a_pruned_epoch`]
(labelled "Audit cause B" in-file; also asserts a rewound candidate never lowers the
floor); the forward-spike pair (`:240`, `:256`); `failed_reservations_mutate_nothing`
(`:269`); the restart test above.

**Residuals.** Sustained forward-spike ratchet: if proofs are actually *allocated* at
successively spiked epochs, `highest_allocated` follows the spike and the floor can
ratchet upward (the cap guarantees only: never-allocated epochs are never refused;
verifiers reject non-fresh spiked proofs anyway — the floor governs reissue, not
issuance freshness). Availability cost by design: after a genuine rewind, below-floor
epochs are permanently unservable for that membership; recovery is re-registration.

**Verdict: B closed. R2 adopted with a deliberate, tested improvement over its own
snippet (actual-prune floor + spike cap).**

---

## 3. Cause C + R3 — authenticating the counters

**Audit claim.** `allocations` lived in the plaintext `MembershipMeta` sidecar; the
load-time scan covered only `registry_id` + `identity_commitment`; file-write access
(or a backup/sync/Time-Machine restore) rewound `used` without the password —
inverting the encryption threat model. Two doc-comments asserted the opposite.

**Mechanism now.** The audited structures no longer exist (`keystore.rs` deleted). The
counters, the §2 floor, and the §5 epoch-size binding live in `rln_allocations.json`
as per-membership `Section`s ([`format.rs:72-78`]) that are **plaintext but doubly
authenticated**:

- **Per-section MAC**: HMAC-SHA256 over a canonical, domain-separated payload —
  `"rln-sealed/v1/section"` ‖ length-prefixed membership_hash ‖ store_uuid ‖
  epoch_size_sec ‖ prune_floor ‖ sorted rows ([`format.rs:113-135`]). Binding to
  `membership_hash` kills cross-entry transplants; binding to `store_uuid` kills
  cross-store transplants.
- **Root MAC** over the *set*: `"rln-sealed/v1/root"` ‖ store_uuid ‖ count ‖
  (membership_hash, section_mac)* ([`format.rs:137-150`]). This is what catches the
  attack a per-section MAC alone cannot: **splicing in an older, self-consistent
  (section + MAC) pair** — the pair verifies individually, but the root no longer
  matches.
- **Keys**: Argon2id (64 MiB, t=3, p=1; [`crypto.rs:56`]) over the keystore password →
  HKDF-SHA256 sub-keys `verify`/`seal`/`ledger` ([`crypto.rs:106-113`]). The MACs use
  the *ledger* sub-key; the credential AEAD (XChaCha20-Poly1305, nonce and AAD under
  the tag, AAD = identity block + membership_hash + store_uuid, [`format.rs:109`])
  uses *seal*; password verification is an O(1) `ct_eq` against *verify*
  ([`crypto.rs:151-153`], [`store.rs:292`]). So rewinding `used` now requires the
  password — the boundary the audit said was inverted (file-write < password) is
  restored.
- **Failure handling at unlock** is tiered and fail-closed
  ([`store.rs:300-358`], quarantine model in `docs/keystore-format.md:65-76`):
  attributable tamper (AEAD failure, one bad section MAC) quarantines that membership;
  a **root mismatch quarantines every membership not already attributed**
  ([`store.rs:347-357`]) — the comment at [`store.rs:328-333`] states the rule that
  survived our own re-audit: *a decoy tamper must never mask a splice* (§7). Missing
  allocations file, missing section, oversize, or foreign-uuid file → quarantine-all
  ([`store.rs:879-948`], uuid pre-check [`store.rs:935-948`]): "deleting counter files
  can never reset counters". A store where everything is quarantined refuses `unlock`
  outright, before any KDF runs ([`store.rs:239-249`]). Quarantined sections are
  re-written exactly as loaded, never re-stamped ([`store.rs:1032`]) — a fresh MAC
  over tampered state would launder it.
- **R3's two offered options vs what shipped**: not moved into the encrypted
  credential plaintext (that would put an Argon2id pass on the per-message hot path
  and make quota reads decrypt-gated); instead the "extend the load-time binding to a
  MAC … under the session key" option, upgraded: a dedicated HKDF ledger sub-key, per
  section *plus* a root over the set. The counters are **authenticated, not
  encrypted** — a deliberate, documented choice (they are rate metadata, not secrets,
  and locked-mode reads keep working). The audit's R3 text is satisfied in its intent
  (counters inside the authentication); the letter ("or extend … a MAC over the whole
  MembershipMeta") is exceeded (set-level root MAC, which the letter would not have
  provided).
- **The two false doc-comments** the audit cited died with `keystore.rs`. Their
  replacements state the covered set structurally: [`rate_limit.rs:32-51`] — "this
  struct IS the covered set — a field added here is authenticated, a field added
  elsewhere is not."

**Tests.** [`store.rs:1336` `tampered_allocations_matrix`] — six scenarios: rewound
`used` (the audit's literal attack) → that membership quarantined, sibling usable;
stripped section MAC; **splice of an older self-consistent section → quarantine-all**
([`store.rs:1389`]); deleted allocations file; removed section; **splice hidden behind
a decoy tamper → still caught** ([`store.rs:1431-1433`]). Golden vectors freeze the MAC payload encodings
([`format.rs:255`, `:271`], order-independence `:296`); AEAD flips
([`crypto.rs:183/:190/:198`]).

**Residuals.** Whole-file rollback of `rln_allocations.json` to an *older
self-consistent* snapshot is undetectable by any purely local construction — disclosed
in `docs/keystore-format.md:83-87`; see **G2** for the sharpened framing and the
freshness-anchor direction. Password compromise is out of scope (the MAC restores the
intended boundary, it does not extend it).

**Verdict: C closed for every partial-edit vector including splice-and-decoy; the
rollback residual is real, disclosed, and tracked (G2). R3 adopted-and-exceeded.**

---

## 4. Cause D + R2 — config changes across restarts

**Audit claim.** `CONFIG` was in-memory and overwritten by every `start()`; widening
`max_epoch_gap` across a restart re-admits epochs whose rows were pruned — no crash,
no clock anomaly, no attacker; "the best primary regression test".

**Mechanism now.** Two knobs, two answers:

- **`max_epoch_gap` is deliberately *not* persisted or bound** ([`lib.rs:1083-1089`]
  stays in-memory config): the §2 floor makes *any* gap value safe by construction — a
  widened gap re-admits only epochs the floor already refuses. Binding it would
  regress (bricking memberships on a harmless narrowing). The audit's requested
  primary regression exists verbatim:
  [`rate_limit.rs:293` `widened_epoch_gap_never_resurrects_pruned_epochs`] — reserve
  epoch 9 (slot 0), prune it at a later epoch, re-offer epoch 9 under a *widened*
  candidate window → `EpochBelowFloor`, and epoch 12 continues at slot 1. This is
  exactly the scenario the audit said defeats "any high-water-mark fix expressed
  relative to the *current* gap" — the shipped floor is absolute, so it survives.
- **`epoch_size_sec` — the sixth cause, which the audit did not enumerate — is bound
  per membership** inside the MAC'd section ([`rate_limit.rs:44-45`],
  [`format.rs:74`]): adopted at the first successful reservation
  ([`store.rs:636`]), and any later mismatch answers `permanent` at both
  `reserve_message_id` and `remaining_budget` ([`store.rs:751-774`
  `reservation_guards`], called at `:608` and `:667`): *"a rebased epoch numbering
  could reissue spent slots. Register a fresh membership under the new size."* This
  one is genuinely non-migratable: spent slots and external nullifiers are keyed by
  the bare numeric epoch index, and index N under 600 s and under 1200 s are different
  intervals with identical external nullifiers — no conversion is safe, so recovery is
  a fresh registration. `start()` deliberately *warns* rather than rejects on a
  mismatch ([`lib.rs:907-924`]) — rejecting would DoS `validate_proof` for every scope
  over one stale local membership; the hard refusal sits at the reservation, where the
  risk is.

**Tests.** The cause-D test above; the restart test
[`store.rs:1215`] also pins the epoch-size binding surviving a restart
(`remaining_budget` and `reserve_message_id` under a changed size both → `Permanent`).

**Verdict: D closed — structurally for `max_epoch_gap` (the allocator no longer
trusts any config-derived input), by authenticated binding for `epoch_size_sec`.**

---

## 5. Cause E + R4 — cross-process exclusivity

**Audit claim.** No flock/lockfile/single-instance guard; two processes on one path =
lost updates on a whole-file-rewritten JSON.

**Mechanism now.** [`fs.rs:125-141` `acquire_dir_lock`]: std `File::try_lock`
(MSRV 1.89, declared [`Cargo.toml:5-6`]) on the sentinel `rln_keystore.lock` —
non-blocking (a held lock fails immediately, never hangs context bring-up), sentinel
rather than a data file because the data files' inodes are replaced by every
tmp+rename. Taken **first thing** in `Store::open` ([`store.rs:145-160`]), before any
file is read → `OpenError::DirLockHeld`. Fail-closed at the module boundary: the store
cell parks in `Unready(cause)` ([`lib.rs:1335-1341`]) and every subsequent keystore op
errors with the cause. `close()` releases deterministically ([`store.rs:223-227`]);
`ensure_open` ([`store.rs:736-741`]) makes a stale handle to a closed store refuse all
writes, so a re-opened store's exclusion holds from inside the process too. The lock
file name is deliberately shared with the ≥0.5.0 formats ([`format.rs:17-18`]) so an
old binary and this one cannot run concurrently in one directory.

R4 offered lock-and-fail-closed OR document-and-enforce-at-host; the PR does **both**:
the OS lock where OS locks work, and a stated deployment obligation where they don't
(`docs/keystore-format.md:88-89`, README) — advisory-lock filesystems (NFS et al.)
must enforce single-process externally.

**Tests.** [`fs.rs:199` `second_locker_is_refused_until_release`];
[`store.rs:1464` `second_open_is_refused_while_the_first_holds_the_lock`]. Intra-process:
[`store.rs:1781` `concurrent_storm_holds_the_one_write_mutex_rule`] (20 concurrent
reservations against a concurrent cache writer — asserts no `(epoch, slot)` is ever
issued twice, then survives a restart with zero quarantines);
[`store.rs:2020`] snapshot-read consistency during persist.

**Residuals.** Advisory only (documented); a hung holder keeps a new process closed
indefinitely (integrity over availability, no steal mechanism); no structured
lock-held signal at context time beyond the error text.

**Verdict: E closed on lock-honoring filesystems, explicitly delegated elsewhere.**

---

## 6. R5 — the documentation, and the impact chain

- The two doc-comments the audit quoted (`keystore.rs:152-155`, `:158-161`) are gone
  with the file. The audited README sentence survives at `README.md:145-146` — but now
  inside a paragraph ([`README.md:140-150`]) that supplies exactly the qualifiers the
  audit found missing: *"durably records the allocation before the proof leaves the
  module (fsync'd write — power-loss-safe … mounts that cannot sync warn loudly and
  degrade to crash-safe)"*, followed by the floor/epoch-size sentence with the
  `permanent` recovery path. The re-review's second pass hunted for overstated prose
  and found none: every absolute is either adjacent to its caveat or backed by a named
  test. (Nit: `README.md:146` runs ~99 columns — an artifact of the `7f1f09c` trim
  commit; cosmetic.)
- `docs/keystore-format.md` (new in the PR) is the R5 artifact the audit did not ask
  for: per-file durability table (`:13-18`), the write ordering with its
  untestable-in-CI admission (`:20-22`), the wire-frozen unlock ordering (`:44-63`),
  the quarantine model (`:65-76`), and an explicit **"Accepted limits"** section
  (`:78-92`) declaring the four residuals: per-instance guarantee (copying forks the
  counters — "migrate by moving, never by copying"), whole-file rollback
  undetectability, the advisory lock, and the deliberately loose cache.
- The invariant statement itself widened: [`rate_limit.rs:1-17`] now pins never-reissue
  across "a restart, a backwards clock step, or a `max_epoch_gap` reconfiguration",
  names persist-before-issue, and describes the floor including its spike cap.
- **Impact chain**: deliberately untouched. `nullifier_log::record_verified`'s
  `Collision` classification and the `recover_identity_secret_hex` reply
  ([`nullifier_log.rs:65-84`], [`lib.rs:1205-1212`]) are byte-identical to base — it is
  always the violator's *own* secret, that automation is why self-collision is fatal,
  and the reply shape is frozen wire contract. What the PR adds is honesty about the
  *detection* side: the verify-side nullifier log is in-memory with a wall-clock floor,
  so a verifier restart forgets nullifiers — declared as a known, deliberately
  out-of-scope limit ([`nullifier_log.rs:14-19`], mirrored [`lib.rs:1150-1153`]); it
  weakens detection of *others'* violations, never the generation-side invariant.

**Verdict: R5 satisfied upward — the false claims died with their files, and the
replacement docs disclose limits the audit never asked to see.**

---

## 7. History the auditor may want: the fix's own adversarial round (H1)

Because the PR squashes its history, the record of the sealed store surviving its own
re-audit lives here. After the rewrite, three adversarial re-reviewers re-ran causes
A–E against it. A/B/D/E held; **C was partially reopened by a new high-severity
finding (H1)**: root-MAC splice detection was initially *conditional* (escalation
skipped when any other quarantine already existed), so an attacker could splice an old
counter section and then hide it behind a free decoy tamper (inject a junk credential)
— the rewound section then loaded as authoritative. The fix made any root-MAC failure
quarantine every not-already-attributed entry, **unconditionally** — which is the
"decoy must never mask a splice" rule now at [`store.rs:328-333`] and the sixth
scenario of `tampered_allocations_matrix`. The same round produced the forward-spike
floor cap refinement (§2), the row cap (G7's mechanism), and several smaller guards.
The lesson H1 taught — *a doc asserting a guarantee the code only partly provides*,
the audit's original sin recurring inside the fix — is why this re-review re-verified
every prose claim against code (§6) instead of trusting the PR description.

---

## 8. This re-review's own findings (G1–G8)

The point of the exercise was re-assertion, not marketing; these are the places the
re-review pushed and found something. None reopens A–E as filed; two (G1, G2) deserve
follow-up work; the rest are dispositions to record.

- **G1 — the macOS durability claim rests on an undocumented std mapping, untested in
  CI.** `write_durable` never calls `fcntl(F_FULLFSYNC)` itself; `File::sync_all` →
  `F_FULLFSYNC` on Apple targets is a std implementation detail, not an API guarantee,
  and the CI matrix is ubuntu-only (`.github/workflows/rln-module.yml:23`). Also, the
  *directory* fsync issues the same call on a directory fd; if Apple ever reported an
  error class other than `Unsupported` there, every `generate_proof` would fail closed
  (safe direction, but a total availability loss). Follow-up options: an explicit
  `#[cfg(target_vendor = "apple")]` `F_FULLFSYNC` call (removes the assumption), a
  macOS CI job, or at minimum a pinned test asserting `sync_all` succeeds on a
  directory fd on darwin. *Disposition: follow-up recommended; disclosed in the
  response.*
- **G2 — the rollback residual is a single-file attack, not just a whole-directory
  restore.** Restoring only `rln_allocations.json` from a backup/APFS snapshot yields
  a self-consistent, MAC-valid file: memberships that existed at backup time come back
  with rewound counters *and* a rewound floor, fully usable (later-registered
  memberships get quarantined for missing sections — which does not protect the older
  ones). That is a direct path to reissue → disclosure for an attacker with file-write
  (or a user with an over-eager backup tool). It is disclosed
  (`docs/keystore-format.md:83-87` — "no purely local MAC can prove freshness"), and
  the disclosure is correct: freshness cannot be manufactured from file contents. But
  the honest framing for the auditor is that this audit-class vector moved from
  *silently broken* to *documented accepted*, not to *closed*. The known exit is an
  external freshness anchor — a monotone generation counter mirrored where the
  file-writer cannot reach (macOS keychain, already a dependency of this module), or a
  generation number in `rln_sealed.json` re-written every N reservations. Roadmap
  item; needs a brick-vs-bypass policy decision. *Disposition: disclosed residual +
  named follow-up direction.*
- **G3 — copying the keystore forks the allocator.** Two devices, each honestly
  holding its own lock, reissue every slot. Documented ("migrate by moving, never by
  copying", `docs/keystore-format.md:80-82`, README `:155-163`); no local mechanism
  can distinguish a copy. Same freshness-anchor family as G2. *Disposition: documented
  limit, restated in the response.*
- **G4 — the per-epoch budget (`rate_limit`) lives in the unauthenticated cache.**
  [`lifecycle.rs:78`] → [`lib.rs:1033`]; `rln_cache.json` has no MAC and no fsync. The
  in-code self-assessment holds: inflating it yields extra *distinct* message_ids
  whose proofs fail verification anyway, because the on-chain leaf pins
  `poseidon(commitment, rate_limit)` — self-DoS, never a share collision; the
  slot-uniqueness invariant does not depend on the cache. Worth stating explicitly
  (the safety rests on the leaf binding, not on the cache being trustworthy).
  *Disposition: by-design, dependency named in the response.*
- **G5 — counters are readable pre-verification on the locked path.**
  `load_allocations` fills sections at open; MACs verify at `unlock`; `remaining_budget`
  deliberately serves locked reads ([`store.rs:651-672`]) — so `get_epoch_quota` on a
  *locked* store can report attacker-chosen numbers. No write and no issuance can
  happen without a session ([`store.rs:603`], [`store.rs:1037-1039`]), so this is an
  advisory-read integrity gap only. *Disposition: state it, accept it.*
- **G6 — `insert()` resets a quarantined membership's counters**
  ([`store.rs:427-433`]). Safe today only because the sole caller mints a fresh random
  identity per registration, so a membership_hash can never recur with real spent
  slots (the code says so at [`store.rs:423-426`]; there is no import/restore method
  on the wire). A future credential-import feature would silently turn this into a
  counter-reset oracle (tamper a section → re-import the same credential → slots
  restart at 0). *Disposition: latent footgun — record internally; any import feature
  must re-review this line first.*
- **G7 — the per-section row cap is a caller-triggerable permanent brick.**
  `WRITE_ROW_CAP` = 4096 ([`store.rs:746-749`]) with caller-supplied
  `rln_identifier`: a consumer can mint 4096 distinct `(rln_identifier, epoch)` rows
  in one live window and get `Permanent` "register a fresh membership". Fail-closed
  and availability-only (the cap exists so the module never writes a file it would
  refuse to read back); a new denial surface the audit did not cover. *Disposition:
  accepted; note for consumers.*
- **G8 — vestigial CI comments** reference a deleted "keystore-core" workspace member
  (`.github/workflows/rln-module.yml:48,53-54`; the `[workspace]` in `Cargo.toml` is
  deliberately empty). Harmless, cosmetic; fix opportunistically. *Disposition:
  internal nit.*

---

## 9. Test evidence (re-run at `7f1f09c`, this session)

Full suite re-run at the PR head for this re-review (scratch worktree at `7f1f09c`,
`cargo test --locked --workspace`): **146 passed, 0 failed** (80 s), every
audit-relevant test below confirmed `ok` by name in the run log; the same tree also
passed clippy `-D warnings` earlier today when the branch was assembled.
Audit-relevant tests by cause:

| Cause | Test (file:line at 7f1f09c) |
|---|---|
| A | `persist_failure_wastes_slot_never_reissues` store.rs:1755; `insert_crash_windows_are_inert_or_healed` store.rs:1976; fs.rs:165/:184/:210 |
| B | `rewound_clock_never_reissues_a_pruned_epoch` rate_limit.rs:224; `forward_clock_spike_cannot_brick_future_epochs` :240; `two_forward_spikes_do_not_brick_future_epochs` :256; `failed_reservations_mutate_nothing` :269 |
| C | `tampered_allocations_matrix` store.rs:1336 (6 scenarios incl. splice→quarantine-all and splice-behind-decoy); golden vectors format.rs:255/:271/:296; AEAD flips crypto.rs:183/:190/:198 |
| D | `widened_epoch_gap_never_resurrects_pruned_epochs` rate_limit.rs:293; `reservation_floor_and_epoch_size_survive_restart` store.rs:1215 |
| E | `second_locker_is_refused_until_release` fs.rs:199; `second_open_is_refused_while_the_first_holds_the_lock` store.rs:1464; `concurrent_storm_holds_the_one_write_mutex_rule` store.rs:1781 |
| hostile input | overcap/oversize/foreign-format set store.rs:1830/:1879/:1905/:1935/:1608 |

Known-untested (each documented in-tree as an accepted limit): real power-cut fsync
behavior, the `Unsupported`-degrade branch, whole-file rollback, advisory-lock
behavior on lock-ignoring filesystems, the file-copy fork.

Beyond unit tests, the same tree passed the chain-facing e2e `register` scenario
(register → active → proof → quota 99/100 → verify valid → tamper invalid) when the
sealed store landed, and the full delivery-integration e2e flow this week on the
branch stacked on top of it.

## 10. Citation verification

Every `path:line` used here and in `audit-response.md` was checked against
`git show 7f1f09c:<path>` by script before delivery (see the session log); the two
central code quotes (`write_durable`, the floor threshold) were additionally
eyeball-verified verbatim.
