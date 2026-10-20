#!/usr/bin/env bash
usage='Usage: bash deployment/build/cache-test-dependencies.sh
Fetch locked Cargo and Go modules before running the offline test suite.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need cargo go
cargo fetch --locked
for component in cloud-api-adaptor peerpod-ctrl caa-csi-block-driver; do
  bash deployment/build/prepare-sources.sh "$component"
done
for module in \
  .local/build-sources/cloud-api-adaptor/src/cloud-api-adaptor \
  .local/build-sources/peerpod-ctrl/src/cloud-providers \
  .local/build-sources/peerpod-ctrl/src/peerpod-ctrl \
  .local/build-sources/caa-csi-block-driver tests; do
  (cd "$module" && go mod download)
done
printf 'Dependency cache ready. Next: ./cos build test\n'
