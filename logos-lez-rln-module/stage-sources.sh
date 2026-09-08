#!/usr/bin/env bash
#
# Refresh the gitignored staged SDK copy this module builds from
# (see README "Staged sources"):
#
#   logos-rust-sdk-src/  <- logos-co/logos-rust-sdk @ SDK_REV
set -euo pipefail

# MUST equal the logos-rust-sdk rev locked in this module's flake.lock
# (logos-module-builder → logos-rust-sdk) — nothing enforces the coupling.
# Bump together with flake.lock and re-run the e2e acceptance ladder.
# Read it with:
#   jq -r '.nodes.root.inputs["logos-module-builder"] as $k
#          | .nodes[.nodes[$k].inputs["logos-rust-sdk"]].locked.rev' flake.lock
SDK_REV=102f86779b010f5bc2e845cf91bb3583e87dcc0c
SDK_REPO=https://github.com/logos-co/logos-rust-sdk
# Excluded dirs are not needed by mkLogosModule.
SDK_EXCLUDES=(--exclude .git --exclude target --exclude doctests --exclude result --exclude tests)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_SRC="${LOGOS_RUST_SDK_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/logos-rln-modules/logos-rust-sdk}"

if [ -n "${LOGOS_RUST_SDK_SRC:-}" ]; then
  # User-supplied checkout: used as-is (never mutated), must sit at the pin.
  sdk_head="$(git -C "$SDK_SRC" rev-parse HEAD)"
  if [ "$sdk_head" != "$SDK_REV" ]; then
    echo "stage-sources: LOGOS_RUST_SDK_SRC is at $sdk_head, expected $SDK_REV" >&2
    exit 1
  fi
else
  if [ ! -d "$SDK_SRC/.git" ]; then
    mkdir -p "$(dirname "$SDK_SRC")"
    git clone "$SDK_REPO" "$SDK_SRC"
  fi
  git -C "$SDK_SRC" rev-parse --verify --quiet "${SDK_REV}^{commit}" >/dev/null \
    || git -C "$SDK_SRC" fetch origin "$SDK_REV"
  git -C "$SDK_SRC" -c advice.detachedHead=false checkout --quiet "$SDK_REV"
fi


echo "stage-sources: syncing logos-rust-sdk-src/ (sdk @ $SDK_REV)"
rsync -ai --checksum --delete "${SDK_EXCLUDES[@]}" \
  "$SDK_SRC/" "$HERE/logos-rust-sdk-src/"

diff -r "${SDK_EXCLUDES[@]}" "$SDK_SRC" "$HERE/logos-rust-sdk-src" || {
  echo "stage-sources: staged copy disagrees with its source after sync" >&2
  exit 1
}
echo "stage-sources: staged copy verified in sync"
