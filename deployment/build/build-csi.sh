#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-csi.sh
Compile CSI and build its runtime image.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need docker jq
bash deployment/build/prepare-sources.sh caa-csi-block-driver
CSI_TREE=$(git -C .local/build-sources/caa-csi-block-driver write-tree)
CSI_UPSTREAM_COMMIT=$(git -C .local/build-sources/caa-csi-block-driver rev-parse HEAD)
CSI_TAG="csi-${CSI_TREE:0:8}"
docker build --platform linux/amd64 --output type=docker \
  --build-arg VERSION="tree-$CSI_TREE" \
  --label "org.opencontainers.image.revision=$CSI_UPSTREAM_COMMIT" \
  --label "org.confidential-openshell.patched-tree=$CSI_TREE" \
  -f .local/build-sources/caa-csi-block-driver/Dockerfile \
  -t "openshell/caa-csi-block-driver:$CSI_TAG" .local/build-sources/caa-csi-block-driver
python3 deployment/build/package-csi-chart.py
printf "CSI image ready: openshell/caa-csi-block-driver:%s\n" "$CSI_TAG"
