#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/prepare-chart.sh [OUTPUT_DIR [DEPENDENCY_DIR]]
Assemble the upstream PeerPods chart; defaults to .local/charts/peerpods and HANDOFF/charts.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq helm
chart="${1:-.local/charts/peerpods}"
cache="${2:-$HANDOFF/charts}"
mkdir -p "$chart/charts"
cp -a repos/cloud-api-adaptor/src/cloud-api-adaptor/install/charts/peerpods/. "$chart/"
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "$cache/$name" | sha256sum -c -
  cp "$cache/$name" "$chart/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
