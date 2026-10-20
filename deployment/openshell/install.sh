#!/usr/bin/env bash
usage='Usage: ./cos gateway install
Install native binaries, create/check the operator identity, configure the driver and install restricted Kubernetes access.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
bash deployment/openshell/install-binaries.sh
bash deployment/openshell/create-identity.sh
bash deployment/openshell/configure-driver.sh
bash deployment/openshell/install-kubeconfig.sh
printf 'Gateway installation complete: binaries, native identity, driver configuration, restricted kubeconfig and RBAC preflight passed.\n'
