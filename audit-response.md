# Response: slot-reissuance finding (Medium) — remediation in PR #9

**Proposed status: Resolved, with disclosed residuals** (listed at the end — one of
them, backup rollback, is the audit's cause-C class narrowed but not closed; we state
it plainly rather than claiming otherwise).

**Scope.** The remediation is [PR #9](https://github.com/logos-co/logos-rln-modules/pull/9)
(`feat/keystore`, head `7f1f09ce`), a from-scratch replacement of the audited
persistence layer: `keystore.rs` and `store.rs` are deleted and replaced by a sealed
store (`rust-lib/src/sealed_store/`). At the PR's base, all five causes were still
present exactly as filed (the `MembershipMeta` doc-comments you cited were
byte-identical to the audited commit), so the entire fix is inside this one diff.
All references below are permalinked at the PR head; the full test suite passes at
that commit (146/146, re-verified for this response), including the regression tests
named per cause.

The invariant is restated, wider, at
[`rate_limit.rs:1-17`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L1-L17):
a slot is never reissued — across a restart, a backwards clock step, or a
`max_epoch_gap` reconfiguration.

---

## A — durability (R1): fixed

All durable writes go through one function,
[`sealed_store/fs.rs:14-38` `write_durable`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/fs.rs#L14-L38):
tmp file created `0600` → `write_all` → `sync_all(tmp)` → `rename` → `sync_all` on the
directory fd — the ordering R1 asks for. On macOS, Rust std maps `File::sync_all` to
`fcntl(F_FULLFSYNC)`; this is declared a load-bearing assumption in the module doc
([`fs.rs:1-8`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/fs.rs#L1-L8))
and we track hardening it into an explicit call (residual 2 below). An fsync failure
fails the write closed — no proof is issued — except `ErrorKind::Unsupported`
(filesystems that cannot sync), which degrades with a loud warning
([`fs.rs:82-93`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/fs.rs#L82-L93)).

R1's structural suggestion is adopted by trust class rather than as an append-only
log: the store is now three files
([`docs/keystore-format.md`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/docs/keystore-format.md)) —
encrypted credentials (`rln_sealed.json`, written only on provisioning/registration),
the authenticated counter ledger (`rln_allocations.json`, the **only** file
`generate_proof` writes,
[`store.rs:637`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L637)),
and an unauthenticated, registry-healed cache (deliberately not fsync'd). "Every
outbound message rewrites the whole credential store" is gone. An append-only file was
considered and rejected: fsync cost dominates write size, and a second
must-agree-with-the-first file adds a consistency problem for no measured gain; the
counter write is a small bounded rewrite, MAC'd and fsync'd.

Failure direction: on a persist error the slot is *burned, never reused* — no proof is
issued and the disk count can only be ≥ the proof-backed count after restart. Pinned by
`persist_failure_wastes_slot_never_reissues`
([`store.rs:1755`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1755))
and `insert_crash_windows_are_inert_or_healed`
([`store.rs:1976`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1976)).
The fsync *ordering* itself is untestable in CI and is documented as
verified-by-inspection.

## B — clock rewind (R2): fixed

The allocator now carries a persisted, monotonically non-decreasing floor
(`prune_floor`), stored inside the MAC'd counter section
([`format.rs:75`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/format.rs#L75) /
[`:126`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/format.rs#L126))
— satisfying your own precondition that the floor is only trustworthy once R1 and R3
land. An epoch below the floor answers a **permanent** error before any mutation
([`rate_limit.rs:96-102`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L96-L102),
mapped to the wire at
[`store.rs:776-783`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L776-L783));
the wall-clock expression survives only as a candidate the allocator max-folds, never
an authority.

One deliberate delta from R2's snippet: the floor records **actual pruning only**,
capped at one past the highest allocated epoch at or below the candidate. Raising it
to the clock-derived value on every call (the literal snippet) lets the same hostile
clock spike *forward*: one reservation under a far-future clock would persist an
astronomical floor and permanently brick the membership. The cap loses no safety — an
epoch with no allocation row has no spent slots, so re-serving it cannot collide; the
refused set is exactly the at-risk set. Both behaviors are pinned:
`rewound_clock_never_reissues_a_pruned_epoch`
([`rate_limit.rs:224`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L224))
and the forward-spike pair
([`:240`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L240),
[`:256`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L256)),
plus `failed_reservations_mutate_nothing`
([`:269`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L269))
and the restart-crossing `reservation_floor_and_epoch_size_survive_restart`
([`store.rs:1215`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1215):
after reopen, the rewound epoch answers `permanent` and the live epoch resumes at
slot 1, never a fresh 0).

## C — counters outside authentication (R3): fixed

The audited structures are deleted. Counters, floor, and epoch-size binding now live
in `rln_allocations.json` as per-membership sections that are **doubly
authenticated**: a per-section HMAC-SHA256 over a canonical domain-separated payload
(bound to `membership_hash` and the store UUID — no cross-entry or cross-store
transplants,
[`format.rs:113-135`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/format.rs#L113-L135)),
plus a **root MAC over the set of section MACs**
([`format.rs:137-150`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/format.rs#L137-L150)),
which catches what a per-section MAC alone cannot: splicing in an older,
individually-valid section. Keys derive from the keystore password via Argon2id
(64 MiB, t=3) → HKDF sub-keys
([`crypto.rs:106-113`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/crypto.rs#L106-L113));
credentials themselves are XChaCha20-Poly1305-sealed with the identity block in the
AAD. Rewinding `used` now requires the password: the boundary the audit found inverted
(file-write < password) is restored.

Tamper handling fails closed with attribution
([`store.rs:300-358`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L300-L358)):
an attributable bad section quarantines that membership; a root mismatch quarantines
**everything** not already attributed — a decoy tamper can never mask a splice;
deleting the counter file (or a section) can never reset counters; a fully
quarantined store refuses to unlock at all. Quarantined sections are re-written
byte-identical, never re-MAC'd — a fresh MAC over tampered state would launder it.
The counters are authenticated, not encrypted — a deliberate choice (they are rate
metadata, not secrets, and quota reads must work while locked). Pinned by the
six-scenario `tampered_allocations_matrix`
([`store.rs:1336`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1336)) —
including your literal attack (rewind `used` on disk without the password) and the
splice-behind-a-decoy variant — with golden vectors freezing the MAC payload
encodings. The two doc-comments you cited died with `keystore.rs`; their replacement
makes the covered set structural:
[`rate_limit.rs:32-51`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L32-L51)
— "this struct IS the covered set".

## D — config widening (R2): fixed, structurally

`max_epoch_gap` is deliberately **not** persisted or bound: the persisted floor makes
any gap value safe by construction — a widened gap re-admits only epochs the floor
already refuses (an absolute floor, so the "defeats any fix expressed relative to the
current gap" trap does not apply). Your requested primary regression exists verbatim:
`widened_epoch_gap_never_resurrects_pruned_epochs`
([`rate_limit.rs:293`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/rate_limit.rs#L293))
— pruned epoch 9 re-offered under a widened window is refused; slot 0 is never
reissued.

Beyond the report: `epoch_size_sec` is a *sixth* cause of the same class the audit
did not enumerate — and a worse one, because spent slots and external nullifiers are
keyed by the bare numeric epoch index, so index N under two different sizes collides
with itself and **no conversion is safe**. It is now bound per membership inside the
MAC'd section at first successful reservation; any later mismatch answers `permanent`
at both reservation and quota
([`store.rs:751-774`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L751-L774));
recovery is a fresh registration. `start()` warns rather than rejects on a mismatch —
rejecting would deny proof *validation* for a whole scope over one stale local
membership; the hard refusal sits at the reservation, where the risk is.

## E — process exclusivity (R4): fixed (both halves)

`Store::open` takes a non-blocking OS lock on the sentinel `rln_keystore.lock` before
reading anything
([`fs.rs:125-141`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/fs.rs#L125-L141),
[`store.rs:145-160`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L145-L160))
and **fails closed**: a held lock leaves the module's store unready and every keystore
op erroring with the cause. R4 offered lock-and-fail-closed *or*
document-and-enforce-at-host; the PR does both — the lock where OS locks work, and a
stated deployment obligation for filesystems that don't honor them
([`docs/keystore-format.md:88-89`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/docs/keystore-format.md#L88-L89)).
The sentinel name is shared with the pre-rewrite format so old and new binaries also
exclude each other. Pinned by `second_open_is_refused_while_the_first_holds_the_lock`
([`store.rs:1464`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1464))
and, intra-process, a 20-thread reservation storm asserting no `(epoch, slot)` is ever
issued twice
([`store.rs:1781`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/sealed_store/store.rs#L1781)).

## R5 — documentation: corrected upward

The two false doc-comments were deleted with their file. The README guarantee
paragraph now carries the fsync and degrade qualifiers and the floor/epoch-size
refusal semantics
([`README.md:140-150`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/README.md#L140-L150)).
The new
[`docs/keystore-format.md`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/docs/keystore-format.md)
documents the format, the quarantine model, the write ordering (including its
untestable-in-CI admission), and — going the direction R5 asked but further — an
explicit **Accepted limits** section declaring the residuals below instead of leaving
them implicit.

**Impact chain**: intentionally unchanged — `Collision → recover_identity_secret` is
frozen wire contract and always discloses the violator's *own* secret. The PR adds an
honest limit declaration on the *detection* side (the verify-side nullifier log is
in-memory and clock-floored; hardening it is declared out of scope —
[`nullifier_log.rs:14-19`](https://github.com/logos-co/logos-rln-modules/blob/7f1f09ce60924a01bc216c8e579167b045294efb/logos-rln-module/rust-lib/src/nullifier_log.rs#L14-L19));
it never weakens the generation-side invariant this finding is about.

---

## Disclosed residuals and follow-ups

1. **Backup rollback of the counter file** — restoring `rln_allocations.json` (alone,
   or with the whole directory) from an older self-consistent snapshot is MAC-valid:
   no purely local construction can prove freshness. This is the one part of cause C's
   class that is *narrowed and disclosed* (`docs/keystore-format.md`, Accepted limits)
   rather than closed: every partial edit — including a splice hidden behind a decoy
   tamper — is caught; a coherent whole-file rollback is not. Planned direction: an
   external freshness anchor (a monotone generation counter mirrored in the OS
   keychain, which the module already uses for password custody).
2. **macOS durability rests on std's `sync_all` → `F_FULLFSYNC` mapping** (documented
   as load-bearing; CI is Linux-only). Follow-up: make the call explicit and/or add a
   macOS CI job.
3. **The keystore guarantee is per instance**: copying the files forks the counters —
   two honest copies reissue every slot. Documented ("migrate by moving, never by
   copying"); same freshness-anchor family as (1).
4. **The per-epoch budget (`rate_limit`) lives in the unauthenticated cache** by
   design: forging it yields extra *distinct* message ids whose proofs fail
   verification anyway, because the on-chain leaf pins
   `poseidon(commitment, rate_limit)` — self-DoS, never a share collision. The
   invariant's safety here rests on that leaf binding, stated explicitly.
5. **Quota reads on a *locked* store are pre-verification** (MACs verify at unlock;
   locked `get_epoch_quota` could report tampered numbers). Advisory-read gap only —
   no slot can be issued and nothing can be written without an unlocked session.
6. The advisory lock does not protect lock-ignoring network filesystems (deployment
   obligation, documented); a real power-cut fsync test and the fsync-unsupported
   degrade branch remain uncovered by CI (documented as inspection-verified).

Internal follow-ups we are tracking from this re-review (not user-visible today):
a guard note on `insert()`'s quarantine-reset should a credential-import feature ever
be added; the 4096-row per-section cap as a consumer-triggerable permanent refusal
(fail-closed availability trade); vestigial CI comments.
