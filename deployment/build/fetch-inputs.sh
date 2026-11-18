#!/usr/bin/env bash
usage='Usage: bash deployment/build/fetch-inputs.sh
Fetch the fixed upstream sources and Helm inputs; prepare separate, verified patch trees.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need git jq curl sha256sum python3 gzip
git submodule update --init repos/openshell repos/cloud-api-adaptor repos/caa-csi-block-driver
mkdir -p artifacts/cache/helm
CHART_CACHE="$ROOT/artifacts/cache/helm"
kata_chart=kata-deploy-4.4.0.tgz
download "https://github.com/kata-containers/kata-containers/releases/download/4.4.0/$kata_chart" \
    "$(jq -er --arg n "$kata_chart" '.charts[$n]' "$LOCK")" "$CHART_CACHE/$kata_chart"
CAA_BASE=$(jq -er '."cloud-api-adaptor".base' deployment/build/sources.lock.json)
CAA_MTIME=$(git -C repos/cloud-api-adaptor show -s --format=%cI "$CAA_BASE")
for entry in peerpodctrl:src/peerpod-ctrl/chart peerpods-webhook:src/webhook/chart; do
    name=${entry%%:*}; chart_path=${entry#*:}
    git -c tar.umask=0022 -C repos/cloud-api-adaptor archive --format=tar \
        --mtime="$CAA_MTIME" --prefix="$name/" "$CAA_BASE:$chart_path" \
        | gzip -n > "$CHART_CACHE/$name-0.5.0.tgz"
done
(cd "$CHART_CACHE" && jq -r '.charts | to_entries[] | "\(.value)  \(.key)"' "$LOCK" | sha256sum -c -)
for component in cloud-api-adaptor caa-csi-block-driver peerpod-ctrl; do
    bash deployment/build/prepare-sources.sh "$component"
done
python3 deployment/build/package-csi-chart.py
printf 'Source trees and charts ready. Original repos/ checkouts are unchanged.\n'
