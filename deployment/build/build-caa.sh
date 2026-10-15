#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-caa.sh
Compile the Alibaba adapter and build its runtime image.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need go make docker jq
bash deployment/build/prepare-sources.sh cloud-api-adaptor
set -euo pipefail
CAA_SOURCE="$PWD/.local/build-sources/cloud-api-adaptor"
CAA_TREE=$(git -C "$CAA_SOURCE" write-tree)
CAA_UPSTREAM_COMMIT=$(git -C "$CAA_SOURCE" rev-parse HEAD)
CAA_VERSION=$(jq -er .build_outputs.caa.build_args.VERSION deployment/runtime/artifacts.lock.json)
CAA_RUNTIME=$(jq -er .images.caa deployment/runtime/artifacts.lock.json)
CAA_TAG="caa-$(printf '%s' "$CAA_TREE" | cut -c1-8)"
printf 'CAA_TAG=%s\n' "$CAA_TAG"
env -u GOFLAGS make -C "$CAA_SOURCE/src/cloud-api-adaptor" \
  RELEASE_BUILD=true BUILTIN_CLOUD_PROVIDERS=alibabacloud \
  GOOPTIONS='GOOS=linux GOARCH=amd64 CGO_ENABLED=0' \
  VERSION="$CAA_VERSION" COMMIT="$CAA_UPSTREAM_COMMIT" cloud-api-adaptor
CAA_CONTEXT="$PWD/artifacts/caa-context"

install -d -m 0700 "$CAA_CONTEXT"
install -m 0755 "$CAA_SOURCE/src/cloud-api-adaptor/cloud-api-adaptor" "$CAA_CONTEXT/cloud-api-adaptor"
sha256sum "$CAA_CONTEXT/cloud-api-adaptor"
docker build --platform linux/amd64 --build-arg "RUNTIME_IMAGE=$CAA_RUNTIME" \
  -f deployment/build/Dockerfile.caa \
  -t "openshell/cloud-api-adaptor:$CAA_TAG" "$CAA_CONTEXT"

printf "CAA image ready: openshell/cloud-api-adaptor:%s\n" "$CAA_TAG"
