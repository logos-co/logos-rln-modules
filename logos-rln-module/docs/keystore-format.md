# The sealed-store keystore format

Version 1 (`rln-sealed-store`), introduced with module 0.6.0. This is a
clean break from the pre-0.6.0 WAKU-RLN-KEYSTORE-derived format: there is
no migration and no nwaku-keyfile compatibility — abandoning keyfile
portability was a deliberate product decision (no consumers existed), not
a side effect. A directory holding only an old `rln_keystore.json` fails
`open()` with explicit guidance; the old file is never read, renamed, or
deleted. If a consumer ever needs nwaku portability again, it becomes an
explicit import/export converter tool, not a property of this format.

## One file per trust class

All files live in `<instance_persistence_path>/`, mode 0600.

| File | Trust class | Durability |
|---|---|---|
| `rln_sealed.json` | encrypted + AEAD-authenticated: header (KDF params, salt, verifier, store_uuid) and, per membership, a plaintext identity block + the XChaCha20-Poly1305-sealed credential | fsync ordering; rewritten only on insert and empty-store provisioning |
| `rln_allocations.json` | plaintext but authenticated: per-membership counter sections (allocations, epoch_size_sec, prune_floor) each with an HMAC, plus a root MAC over the section MACs | fsync ordering; one small rewrite per reservation, completed **before** the slot is returned |
| `rln_cache.json` | plaintext, unauthenticated, poller-owned: registry-derived state the poller re-heals (state, leaf_index, rate_limit, failure fields, first_active_at) | rename-atomic only, no fsync — loss is always recoverable from the registry |
| `rln_keystore.lock` | advisory OS lock sentinel; the name is shared with the ≥0.5.0 formats so those binaries and this one cannot run concurrently in one directory (the audited 0.4.0 had no lock, but its file set is disjoint) | — |

The durable write ordering (tmp 0600 → write → fsync(tmp) → rename →
fsync(dir)) is power-loss-critical and untestable in CI; it degrades only
on filesystems that report fsync unsupported, loudly.

## Crypto

- **KDF**: Argon2id (64 MiB, t=3, p=1 by default; parameters live in the
  header and are honored on read, so they are tunable per store without a
  format break) → 32-byte master key. Unlock runs the KDF exactly once.
- **Sub-keys**: HKDF-SHA256 with domain-separated info strings
  (`rln-sealed/v1/{verify,seal,ledger}`). The verifier stored in the header
  is the verify sub-key, compared in constant time — an O(1) password
  check independent of entry count.
- **AEAD**: XChaCha20-Poly1305, fresh random 24-byte nonce per seal. The
  AAD binds the membership hash, the full plaintext identity block
  (registry_id, rln_identifier, identity_commitment, submitted_at), and
  the store_uuid — editing any sidecar identity field IS a decryption
  failure; there is no separate cross-check to maintain.
- **Counter MACs**: HMAC-SHA256 under the ledger sub-key over hand-written
  canonical byte encodings (versioned domain tags, length-prefixed fields,
  sorted rows, store_uuid). The encodings are the frozen authenticated
  surface, pinned byte-for-byte by golden-vector tests in
  `sealed_store/format.rs` — never change one without a version bump.

## Unlock ordering (wire-frozen)

1. A non-empty store whose every credential failed the **unkeyed open-time
   census** (membership-hash recomputation, parse caps) refuses with
   `internal` + restore guidance before any key derivation — a vacuous
   password match must never adopt a password.
2. One KDF run. An empty store (re-)provisions the header with the offered
   password (trust-on-first-use, recorded durably; the store_uuid is kept
   across re-provisioning) — the first insert freezes the verifier.
3. Verifier check, constant-time → `bad_password` on mismatch.
4. Keyed pass, only after the verifier passes: every credential is
   AEAD-opened (failure → that membership quarantined), every section MAC
   verified (failure → that membership quarantined), then the root MAC over
   the stored section MACs. A content-only edit leaves the stored MAC (and
   thus the root) valid and stays attributable to its section; any root-MAC
   failure — a spliced older section, a stripped or edited MAC, a section
   added or removed — is unattributable (a decoy tamper must never mask a
   splice), so every not-already-attributed membership is quarantined,
   fail-closed.
5. The session (password + three sub-keys) commits all-or-nothing.

## Quarantine model

Attributable tamper — a failed hash recomputation, AEAD open, or section
MAC — quarantines exactly that membership; siblings stay fully usable.
Quarantined entries are never decrypted, selected, reserved from, or
re-stamped (re-stamping would launder tampered counters), and surface on
the wire as `failed`/`metadata_tamper` with `retryable` suppressed. An
absent allocations file (or section) for a known membership is tamper:
deleting counter files can never reset counters. Corrupt-but-parseable-as-
nothing files are moved aside as `.bad.<unix-ts>` evidence, never
overwritten. Oversized files fail their parse caps closed rather than
aborting the process.

## Accepted limits (unchanged in kind from the previous format)

- The no-reissue guarantee is per keystore instance. Copying the files
  forks the counters; concurrent use of both copies discloses the identity
  secret. Migrate by moving, never by copying.
- A whole-file rollback of `rln_allocations.json` (or the whole directory)
  to an older self-consistent backup is undetectable by any purely local
  MAC. The root MAC catches every partial edit — including a splice hidden
  behind a decoy tamper elsewhere — so the residual local attack is reduced
  to a rollback of the entire counter file to a byte-consistent past state;
  the root cannot close that (an old file is internally valid). The real fix
  is an OS-keychain freshness anchor (a per-store monotone counter held
  outside the filesystem, bound into the root), on the roadmap.
- The directory lock is advisory; deployments on filesystems that do not
  honor OS locks must enforce single-process externally.
- `rln_cache.json` is deliberately loose: a crash can lose cache updates
  recorded microseconds earlier (including a submit-failure reason). State
  is re-healed from the registry; only forensics for that window are lost.
