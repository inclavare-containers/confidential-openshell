#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-driver.sh
Compile the confidential driver and optional attestation observer into artifacts/.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need cargo
mkdir -p artifacts
cargo build --release --locked -p openshell-driver-confidential-kubernetes -p openshell-attestation-observer
install -m 0755 target/release/openshell-driver-confidential-kubernetes artifacts/
install -m 0755 target/release/openshell-attestation-observer artifacts/
printf "Driver ready: artifacts/openshell-driver-confidential-kubernetes\n"
