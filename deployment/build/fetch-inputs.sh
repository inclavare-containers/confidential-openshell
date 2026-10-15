#!/usr/bin/env bash
usage='Usage: bash deployment/build/fetch-inputs.sh
Fetch the fixed upstream sources and Helm inputs; prepare separate, verified patch trees.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need git jq helm python3 gzip
git submodule update --init repos/openshell repos/cloud-api-adaptor repos/caa-csi-block-driver
mkdir -p .local/dependencies artifacts/cache/helm
KATA_COMMIT=$(jq -er '."kata-containers".base' deployment/build/sources.lock.json)
KATA_SOURCE="$ROOT/.local/dependencies/kata-containers"
if [[ ! -e $KATA_SOURCE ]]; then
    # Fetch one complete source revision, rather than all upstream history.
    staging=$(mktemp -d "$ROOT/.local/dependencies/.kata.XXXXXX")
    git init "$staging"
    git -C "$staging" remote add origin https://github.com/kata-containers/kata-containers.git
    git -C "$staging" fetch --depth=1 origin "$KATA_COMMIT"
    git -C "$staging" checkout --detach FETCH_HEAD
    mv "$staging" "$KATA_SOURCE"
fi
CHART_CACHE="$ROOT/artifacts/cache/helm"
kata_chart=kata-deploy-4.2.0.tgz
if ! checked "$(jq -er --arg n "$kata_chart" '.charts[$n]' "$LOCK")" "$CHART_CACHE/$kata_chart"; then
    helm pull oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
        --version 4.2.0 --destination "$CHART_CACHE"
fi
CAA_BASE=$(jq -er '."cloud-api-adaptor".base' deployment/build/sources.lock.json)
CAA_MTIME=$(git -C repos/cloud-api-adaptor show -s --format=%cI "$CAA_BASE")
for entry in peerpodctrl:src/peerpod-ctrl/chart peerpods-webhook:src/webhook/chart; do
    name=${entry%%:*}; chart_path=${entry#*:}
    git -c tar.umask=0022 -C repos/cloud-api-adaptor archive --format=tar \
        --mtime="$CAA_MTIME" --prefix="$name/" "$CAA_BASE:$chart_path" \
        | gzip -n > "$CHART_CACHE/$name-0.5.0.tgz"
done
python3 deployment/build/check-inputs.py
for component in cloud-api-adaptor caa-csi-block-driver peerpod-ctrl; do
    bash deployment/build/prepare-sources.sh "$component"
done
bash deployment/build/prepare-sources.sh kata-containers "$KATA_SOURCE"
python3 deployment/build/package-csi-chart.py
printf 'Source trees and charts ready. Original repos/ checkouts are unchanged.\n'
