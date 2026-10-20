#!/usr/bin/env bash
usage='Usage: ./cos registry publish
Publish all runtime/dependency images and the verified Kata shim; stop if either publication fails.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
bash deployment/peerpods/publish-images.sh
bash deployment/build/package-kata-shim.sh
printf 'Registry publication complete: runtime/dependency images and kata-deploy digest records are ready in %s.\n' "$OPERATOR_DIR"
