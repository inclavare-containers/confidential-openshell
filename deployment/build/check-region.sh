#!/usr/bin/env bash
# Supported public deployment profile; the guest's measurements are not region-specific.
set -euo pipefail
if [[ ${1:-} != cn-beijing ]]; then
  printf 'This deployment profile supports cn-beijing (ecs.g9i.xlarge, Zone I). Select it before building or importing a guest.\n' >&2
  exit 1
fi
