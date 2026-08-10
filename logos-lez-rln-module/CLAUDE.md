# logos-lez-rln-module (measured at commit 0780862, 2026-08)

- `stage-sources.sh` `SDK_REV` must equal the `logos-rust-sdk` rev locked in
  flake.lock — nothing enforces this coupling, and it had silently drifted
  (staged e288fb0 vs locked 270e4cf; found by review, fixed at 0780862).
  When flake.lock updates, bump `SDK_REV` in the same change. flake.lock
  carries TWO logos-rust-sdk nodes with different revs: only the root
  `logos-rust-sdk` node matters — it is what logos-module-builder's
  `lidl-gen`/`rust-sdk-src` build against. `logos-rust-sdk_2` is inert for
  our `type: core` modules (it belongs to the logos-standalone-app →
  logos-capability-module demo chain, only evaluated for `type: ui`
  modules); its drift can be ignored.
