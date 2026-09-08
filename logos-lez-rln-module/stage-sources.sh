#!/usr/bin/env bash
#
# Compatibility wrapper: the staged SDK copy (logos-rust-sdk-src/) and the
# provider scaffold (rust-lib/generated/provider_gen.rs) are both produced by
# `nix run .#generate`, straight from the logos-module-builder rev flake.lock
# pins — there is no separate SDK_REV to keep in step any more.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
# Inside a work tree nix reads the tracked files (git+file); a staged copy
# without .git needs the plain path fetcher.
if git rev-parse --show-toplevel >/dev/null 2>&1; then ref="$HERE"; else ref="path:$HERE"; fi
exec nix run "$ref#generate" -L -- "$HERE"
