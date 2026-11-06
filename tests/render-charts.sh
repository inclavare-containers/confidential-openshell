#!/usr/bin/env bash
# Render the production-prepared PeerPods chart; test the packaged patched CSI handoff.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="${PEERPODS_CHART_CACHE:-$root/artifacts/cache/helm}"
mkdir -p "$root/.local"
chart="$(mktemp -d "$root/.local/chart-check.XXXXXX")"
trap 'rm -rf -- "$chart"' EXIT
bash "$root/deployment/peerpods/prepare-chart.sh" "$chart" "$cache"
helm template peerpods "$chart" --namespace confidential-containers-system --values "$root/deployment/peerpods/peerpods-values.example.yaml" > "$chart/rendered.yaml"
python3 - "$chart/rendered.yaml" <<'PY'
import sys
import yaml

with open(sys.argv[1]) as source:
    daemonsets = {item['metadata']['name']: item for item in yaml.safe_load_all(source)
                 if item and item['kind'] == 'DaemonSet'}
for name in ('kata-deploy', 'cloud-api-adaptor-daemonset'):
    selector = daemonsets[name]['spec']['template']['spec']['nodeSelector']
    assert selector == {'node.kubernetes.io/worker': ''}, (name, selector)
PY
python3 "$root/deployment/build/package-csi-chart.py"
python3 "$root/tests/check-chart-handoff.py"
printf 'PeerPods rendered and packaged CSI handoff resource assertions passed offline\n'
