#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/prepare-chart.sh
Assemble the upstream PeerPods chart with the verified handoff dependencies.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq helm
mkdir -p .local/charts/peerpods
cp -a repos/cloud-api-adaptor/src/cloud-api-adaptor/install/charts/peerpods/. .local/charts/peerpods/
mkdir -p .local/charts/peerpods/charts
CHART_CACHE="$HANDOFF/charts"
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "$CHART_CACHE/$name" | sha256sum -c -
  cp "$CHART_CACHE/$name" ".local/charts/peerpods/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
