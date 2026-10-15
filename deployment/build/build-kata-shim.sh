#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-kata-shim.sh
Compile and test the patched Kata host shim; write artifacts/containerd-shim-kata-v2.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need go make jq
bash deployment/build/prepare-sources.sh kata-containers .local/dependencies/kata-containers
set -euo pipefail
KATA_SRC="$PWD/.local/build-sources/kata-containers"
make -C "$KATA_SRC/src/runtime" clean-generated-files
make -C "$KATA_SRC/src/runtime" PREFIX=/opt/kata \
  QEMUCMD=qemu-system-x86_64 STATIC=yes containerd-shim-v2
(cd "$KATA_SRC/src/runtime" && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)
KATA_STAGE="$PWD/.local/kata-shim-install"
make -C "$KATA_SRC/src/runtime" PREFIX=/opt/kata DESTDIR="$KATA_STAGE" \
  STATIC=yes install-containerd-shim-v2
file "$KATA_STAGE/opt/kata/bin/containerd-shim-kata-v2"
SHIM_TRANSFER="$PWD/artifacts"
install -d -m 0700 "$SHIM_TRANSFER"
install -m 0755 "$KATA_STAGE/opt/kata/bin/containerd-shim-kata-v2" \
  "$SHIM_TRANSFER/containerd-shim-kata-v2"
(cd "$SHIM_TRANSFER" && sha256sum containerd-shim-kata-v2 > shim.sha256)
printf "Kata shim ready: artifacts/containerd-shim-kata-v2\n"
