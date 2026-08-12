#!/usr/bin/env bash
# Build → (sign) → catalog → stage a GitHub release for the RLN membership
# stack. Produces dist/catalog/ (logos-repo.json + index.json + the portable
# .lgx bundles) and PRINTS the `gh release create` command — it never pushes or
# publishes anything itself.
#
# The wallet (logos_execution_zone) is NOT republished: it resolves from the
# official catalog, which is enabled by default. This catalog carries our three.
#
# Usage:
#   tools/publish.sh --tag v0.3.1 [--sign] [--key <name>] [--keys-dir <dir>]
#                    [--repo <owner/name>] [--base-url <url>]
#
# Signing (--sign) uses the `lgx` CLI from github:logos-co/logos-package. Keep
# the private .jwk OUT of git; generate it once with:
#   lgx keygen --name <name> --output-dir ~/.config/logos/keys
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

SIGN=0
KEY="rln-signer"
KEYS_DIR="${HOME}/.config/logos/keys"
TAG=""
RELEASE_REPO="logos-co/logos-rln-membership-release"
BASE_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --sign) SIGN=1; shift ;;
    --key) KEY="$2"; shift 2 ;;
    --keys-dir) KEYS_DIR="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --repo) RELEASE_REPO="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

if [ -z "$BASE_URL" ]; then
  [ -n "$TAG" ] || { echo "provide --base-url <url>, or --tag <tag> for a GitHub release" >&2; exit 2; }
  BASE_URL="https://github.com/${RELEASE_REPO}/releases/download/${TAG}"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/lgx"

# The two Rust modules build from gitignored staged sources; stage them on
# demand so this works from a fresh clone. logos-lez-rln-module stages via
# stage-sources.sh; logos-rln-module codegens + stages via `nix run .#generate`.
if [ ! -d "${REPO_ROOT}/logos-lez-rln-module/logos-rust-sdk-src" ]; then
  echo "== Staging sources for logos-lez-rln-module =="
  bash "${REPO_ROOT}/logos-lez-rln-module/stage-sources.sh"
fi
echo "== Staging sources for logos-rln-module (codegen) =="
nix run "path:${REPO_ROOT}/logos-rln-module#generate" -L

echo "== Building portable .lgx bundles =="
for sub in logos-lez-rln-module logos-rln-module logos-rln-membership-ui; do
  echo "  -> $sub#lgx-portable"
  out="$(nix build "path:${REPO_ROOT}/${sub}#lgx-portable" --no-link --print-out-paths)"
  cp "$(find "$out" -name '*.lgx' | head -1)" "$STAGE/lgx/"
done
# store outputs are read-only; signing rewrites the .lgx in place.
chmod -R u+w "$STAGE/lgx"

if [ "$SIGN" -eq 1 ]; then
  echo "== Signing =="
  LGX="$(nix build 'github:logos-co/logos-package#lgx' --no-link --print-out-paths)/bin/lgx"
  if [ ! -f "${KEYS_DIR}/${KEY}.jwk" ]; then
    echo "no signing key at ${KEYS_DIR}/${KEY}.jwk" >&2
    echo "generate one: lgx keygen --name ${KEY} --output-dir ${KEYS_DIR}" >&2
    exit 1
  fi
  for f in "$STAGE"/lgx/*.lgx; do
    "$LGX" sign "$f" --key "$KEY" --keys-dir "$KEYS_DIR" \
      --name "Logos RLN Membership" --url "https://github.com/logos-co/logos-rln-modules"
  done
  echo "  signer DID: $(cat "${KEYS_DIR}/${KEY}.did")"
fi

echo "== Generating catalog =="
DIST="${REPO_ROOT}/dist/catalog"
python3 "${REPO_ROOT}/tools/catalog-gen.py" \
  --files-dir "$STAGE/lgx" \
  --base-url "$BASE_URL" \
  --out "$DIST" \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo
echo "== Staged in ${DIST} =="
echo "This script does NOT push. To publish (review first):"
echo
if [ -n "$TAG" ]; then
  echo "  gh release create ${TAG} --repo ${RELEASE_REPO} \\"
  echo "    --title 'RLN Membership ${TAG}' --notes 'RLN membership stack' \\"
  echo "    ${DIST}/logos-repo.json ${DIST}/index.json ${DIST}/files/*.lgx"
else
  echo "  Commit ${DIST}/{logos-repo.json,index.json,files/*.lgx} to the branch"
  echo "  that serves ${BASE_URL} and push it."
fi
echo
echo "Users then add the repo in Basecamp's Package Manager:"
echo "  ${BASE_URL}/logos-repo.json"
