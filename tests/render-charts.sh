#!/usr/bin/env bash
# Render CAA from unchanged committed chart sources; test the packaged patched CSI handoff.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="${PEERPODS_CHART_CACHE:-$root/artifacts/cache/helm}"
mkdir -p "$root/.local"
chart="$(mktemp -d "$root/.local/chart-check.XXXXXX")"
trap 'rm -rf -- "$chart"' EXIT
git -C "$root/repos/cloud-api-adaptor" archive HEAD src/cloud-api-adaptor/install/charts/peerpods | tar -x -C "$chart" --strip-components=5
mkdir -p "$chart/charts"
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "$cache/$name" | sha256sum -c -
  cp "$cache/$name" "$chart/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' "$root/deployment/runtime/artifacts.lock.json")
helm template peerpods "$chart" --namespace confidential-containers-system --values "$root/deployment/peerpods/peerpods-values.example.yaml" >/dev/null
python3.11 "$root/deployment/build/package-csi-chart.py"
python3.11 "$root/tests/check-chart-handoff.py"
printf 'PeerPods rendered and packaged CSI handoff resource assertions passed offline\n'
