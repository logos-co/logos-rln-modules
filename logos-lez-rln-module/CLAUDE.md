# logos-lez-rln-module (measured at the 0.9-toolchain bump, 2026-09)

- `stage-sources.sh` `SDK_REV` must equal the `logos-rust-sdk` rev locked in
  flake.lock — nothing enforces this coupling, and it had silently drifted
  once (staged e288fb0 vs locked 270e4cf; found by review, fixed at 0780862).
  When flake.lock updates, bump `SDK_REV` in the same change (the script's
  header carries the jq one-liner that reads the locked rev). Since the SDK
  crate is versioned (0.3.0 from rust-sdk 80d028ab), a stale stage now fails
  `cargo --locked` instead of hiding. The builder is pinned by rev, not tag:
  `nix flake lock --override-input logos-module-builder github:logos-co/logos-module-builder/<rev>`.
  `rust-lib/generated/provider_gen.rs` is CHECKED IN and must be regenerated
  with the same `--protocol-version` the builder stamps (README). flake.lock
  carries TWO logos-rust-sdk nodes with different revs: only the root
  `logos-rust-sdk` node matters — it is what logos-module-builder's
  `lidl-gen`/`rust-sdk-src` build against. `logos-rust-sdk_2` is inert for
  our `type: core` modules (it belongs to the logos-standalone-app →
  logos-capability-module demo chain, only evaluated for `type: ui`
  modules); its drift can be ignored.
