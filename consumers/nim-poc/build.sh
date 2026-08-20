#!/usr/bin/env bash
# Build everything the Nim PoC needs, at the repo's own pins:
#   1. the two module rust-libs as standalone cdylibs (undefined lp_*),
#   2. libwallet_ffi from the logos-execution-zone rev the repo pins,
#   3. the PoC binaries (register_poc, smoke).
# Requires: nix, cargo (the repo's rust toolchain), nim >= 2.0.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BUILD="$HERE/build"
mkdir -p "$BUILD"

case "$(uname -s)" in
  Darwin) DYLIB_EXT=dylib; CDYLIB_RUSTFLAGS="-C link-arg=-Wl,-undefined,dynamic_lookup" ;;
  *)      DYLIB_EXT=so;    CDYLIB_RUSTFLAGS="" ;;
esac

# 1. Generated module sources (gitignored; the lez-rln module commits its own).
if [ ! -f "$REPO/logos-rln-module/rust-lib/generated/provider_gen.rs" ]; then
  echo "== materializing logos-rln-module generated sources"
  nix run "$REPO/logos-rln-module#generate"
fi
if [ ! -d "$REPO/logos-lez-rln-module/logos-rust-sdk-src" ]; then
  echo "== staging logos-lez-rln-module SDK sources"
  "$REPO/logos-lez-rln-module/stage-sources.sh"
fi

# 2. Module cdylibs. cargo rustc overrides the crates' staticlib crate-type;
#    the undefined lp_* symbols resolve at dlopen time against the PoC
#    binary's exports (production links its plugins the same way).
for mod in logos-rln-module logos-lez-rln-module; do
  echo "== building $mod cdylib"
  (cd "$REPO/$mod/rust-lib" && \
    RUSTFLAGS="$CDYLIB_RUSTFLAGS" cargo rustc --release --crate-type cdylib)
done
RLN_LIB="$REPO/logos-rln-module/rust-lib/target/release/libliblogos_rln_module.$DYLIB_EXT"
LEZ_LIB="$REPO/logos-lez-rln-module/rust-lib/target/release/libliblogos_lez_rln_module.$DYLIB_EXT"

# 3. wallet-ffi at the exact logos-execution-zone pin from this repo's
#    flake.lock (the sibling of the lez_core wallet module logos-core runs).
LEZ_REV="$(python3 - "$REPO/flake.lock" <<'EOF'
import json, sys
lock = json.load(open(sys.argv[1]))
print(lock["nodes"]["logos-execution-zone"]["locked"]["rev"])
EOF
)"
WALLET_SRC="$BUILD/lez-src-$LEZ_REV"
if [ ! -d "$WALLET_SRC" ]; then
  echo "== fetching logos-execution-zone @ $LEZ_REV"
  STORE_PATH="$(nix flake prefetch "github:logos-blockchain/logos-execution-zone?rev=$LEZ_REV" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["storePath"])')"
  cp -R "$STORE_PATH" "$WALLET_SRC"
  chmod -R u+w "$WALLET_SRC"
fi
echo "== building wallet-ffi"
(cd "$WALLET_SRC" && cargo build --release -p wallet-ffi)
WALLET_LIB_DIR="$WALLET_SRC/target/release"

# 4. PoC binaries.
echo "== building nim binaries"
(cd "$HERE" && nim c -d:release --hints:off -o:"$BUILD/register_poc" \
  --passL:"-L$WALLET_LIB_DIR -lwallet_ffi -Wl,-rpath,$WALLET_LIB_DIR" \
  register_poc.nim)
(cd "$HERE" && nim c -d:release --hints:off -o:"$BUILD/smoke" smoke.nim)

cat <<EOF

Built:
  $BUILD/register_poc
  $BUILD/smoke
Module cdylibs (register_poc finds these by default):
  $RLN_LIB
  $LEZ_LIB

Smoke test (no network):
  $BUILD/smoke "$RLN_LIB" "$LEZ_LIB" /tmp/rln-poc-smoke

Testnet probe (no chain writes beyond wallet storage):
  $BUILD/register_poc --registry=logos:testnet:<64-hex config PDA> --mode=probe
EOF
