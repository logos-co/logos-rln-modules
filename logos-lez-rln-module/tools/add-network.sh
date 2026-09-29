#!/usr/bin/env bash
# Add a registry to rust-lib/networks.json from a logos-rln-e2e / logos-lez-rln
# deployment.json descriptor.
#
#   tools/add-network.sh <reference> <deployment.json> [description]
#
# A new <reference> becomes a new network (description required); an existing
# one gains the registry, and its sequencer must match the descriptor's.
# Refuses a config account the table already lists, under any network.
# Run `cargo test networks` afterwards: the tests pin the table's invariants.
set -euo pipefail

usage() { echo "usage: $0 <reference> <deployment.json> [description]" >&2; exit 2; }
[ $# -ge 2 ] && [ $# -le 3 ] || usage
reference="$1" descriptor="$2" description="${3:-}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

table="$(cd "$(dirname "$0")/.." && pwd)/rust-lib/networks.json"
[ -f "$descriptor" ] || { echo "no such descriptor: $descriptor" >&2; exit 1; }

# The membership module lowercases a logos reference before sending it, so a
# capital letter here could never be selected.
[[ "$reference" =~ ^[-_a-z0-9]{1,32}$ ]] \
    || { echo "reference must match [-_a-z0-9]{1,32}: $reference" >&2; exit 1; }

for field in name sequencer config_account tree_id registration_program_id merkle_program_id; do
    jq -e --arg f "$field" '.[$f] | strings | length > 0' "$descriptor" >/dev/null \
        || { echo "$descriptor has no $field" >&2; exit 1; }
done

config=$(jq -r .config_account "$descriptor")
if jq -e --arg c "$config" '[.networks[].registries[].config_account] | index($c)' "$table" >/dev/null; then
    echo "config account $config is already in $table" >&2
    exit 1
fi

# The table's sequencers end in '/', like the configs stage.sh writes.
sequencer=$(jq -r '.sequencer | if endswith("/") then . else . + "/" end' "$descriptor")

if jq -e --arg r "$reference" 'any(.networks[]; .reference == $r)' "$table" >/dev/null; then
    existing=$(jq -r --arg r "$reference" '.networks[] | select(.reference == $r) | .sequencer' "$table")
    [ "$existing" = "$sequencer" ] || {
        echo "network $reference uses $existing, the descriptor says $sequencer" >&2
        exit 1
    }
else
    [ -n "$description" ] || { echo "a new network needs a description (third argument)" >&2; exit 1; }
fi

tmp="$table.tmp"
jq --arg r "$reference" --arg d "$description" --arg s "$sequencer" \
   --slurpfile dep "$descriptor" '
    ($dep[0] | {
        deployment: .name,
        config_account,
        tree_id,
        registration_program_id,
        merkle_program_id
    }) as $reg
    | if any(.networks[]; .reference == $r)
      then .networks |= map(if .reference == $r then .registries += [$reg] else . end)
      else .networks += [{reference: $r, description: $d, sequencer: $s, registries: [$reg]}]
      end
' "$table" > "$tmp"
mv "$tmp" "$table"
echo "added $(jq -r .name "$descriptor") ($config) to network $reference"
