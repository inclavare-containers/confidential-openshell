#!/usr/bin/env bash
# Offline checks only: no cloud, quote, KBS resource, model API or deployment.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
test_tmp="$(mktemp -d "${TMPDIR:-/tmp}/co-tests.XXXXXX")"
export TMPDIR="$test_tmp"
fixture="$(mktemp -d "$root/.local/initdata-check.XXXXXX")"
trap 'rm -rf -- "$fixture" "$test_tmp"' EXIT
for component in cloud-api-adaptor peerpod-ctrl caa-csi-block-driver; do
  test -d ".local/build-sources/$component" || bash deployment/build/prepare-sources.sh "$component"
done
python3.11 deployment/build/manifest.py --check-test-sources > "$fixture/source-manifest.json"
python3.11 tests/check-layout.py
components/confidential-driver/controlled-diff.sh
cargo fmt --all -- --check
OPENSHELL_INITDATA_FIXTURE_OUT="$fixture/initdata" cargo test --offline --locked -p openshell-driver-confidential-kubernetes
python3.11 tests/check-driver-initdata.py "$fixture/initdata"
(cd tests && go test -mod=readonly ./policy -count=1)
PYTHONPATH=deployment/runtime python3.11 -m unittest discover -s tests/contracts -v
python3.11 -m unittest discover -s tests/e2e -v
(umask 022; cd .local/build-sources/cloud-api-adaptor/src/cloud-api-adaptor && go test -mod=readonly ./pkg/forwarder/interceptor ./cmd/agent-protocol-forwarder ./pkg/adaptor/cloud ./pkg/podnetwork)
(cd .local/build-sources/peerpod-ctrl/src/cloud-providers && go test -mod=readonly -tags=alibabacloud ./alibabacloud)
# The upstream controller suite needs envtest's API server and etcd. Compile its
# import graph here; provider behavior runs above and controller cleanup runs live.
(cd .local/build-sources/peerpod-ctrl/src/peerpod-ctrl && go test -mod=readonly -tags=alibabacloud -run '^$' ./...)
(cd .local/build-sources/caa-csi-block-driver && go test -mod=readonly ./...)

bash tests/render-charts.sh
