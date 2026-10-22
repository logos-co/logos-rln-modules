# rln-signal

The RLN signal binding liblogos_rln_module applies to a message before it
proves or verifies over it, as a library and a one-symbol C ABI:

```text
x = Fr::from_le_bytes_mod_order(keccak256(signal))     // zerokit hash_to_field_le
```

The wire form is the canonical 32-byte little-endian encoding of `x`. Hex
encoded, it is the `signal_hash_hex` argument of the module's
`generate_proof_prehashed` / `validate_proof_prehashed`, and it equals the
`share_x` field of every `RateLimitProof` reply. Hashing locally lets a
consumer hand the module 32 bytes instead of the whole message payload.

## Rust

```rust
let x: [u8; 32] = rln_signal::signal_hash(&signal);
```

## C / Nim

`include/rln_signal.h` declares the single export; link `librln_signal.a` (or
the `cdylib`):

```nim
proc rln_signal_hash(signal: ptr uint8, len: csize_t, out: ptr uint8): int32
  {.importc, cdecl.}

var x: array[32, byte]
doAssert rln_signal_hash(
  if signal.len > 0: unsafeAddr signal[0] else: nil,
  csize_t(signal.len), addr x[0]) == 0
let signalHashHex = x.toHex()   # → generate_proof_prehashed(…, signalHashHex, …)
```

A consumer that already links zerokit's `librln` has the same value via
`ffi_hash_to_field_le` followed by `ffi_fr_to_bytes_le`; this crate exists for
consumers that do not, and as the single definition the module itself links.

## Guarantees

- Byte-identical to zerokit `rln::hash_to_field_le` (asserted by test against
  `rln` 3.0.0) and to the module's frozen interop vector
  (`x("Hello, RLN!") = 9af96b55…1412`).
- The module deserializes the value strictly: a non-canonical encoding (at or
  above the field modulus) is `invalid_argument`, never re-reduced.

## Build

```
cargo test
cargo build --release      # target/release/librln_signal.{a,dylib|so}
nix build .#rln-signal     # from the repository root: lib/ + include/
```
