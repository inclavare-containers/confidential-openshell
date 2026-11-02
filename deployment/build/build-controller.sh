#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-controller.sh
Compile the Alibaba controller and create artifacts/images/peerpod-controller.tar.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need go make crane jq
ROOT=$(git rev-parse --show-toplevel)
CONTROLLER_BUILD="$ROOT/.local/peerpod-controller"

mkdir -p "$CONTROLLER_BUILD/context"
bash "$ROOT/deployment/build/prepare-sources.sh" peerpod-ctrl
CONTROLLER_SOURCE="$ROOT/.local/build-sources/peerpod-ctrl"
test "$(git -C "$CONTROLLER_SOURCE" write-tree)" = \
  "$(jq -er '.["peerpod-ctrl"].result_tree' "$ROOT/deployment/build/sources.lock.json")"
GOCACHE="$CONTROLLER_BUILD/go-cache" make -C "$CONTROLLER_SOURCE/src/peerpod-ctrl" \
  build BUILTIN_CLOUD_PROVIDERS=alibabacloud
(cd "$CONTROLLER_SOURCE/src/peerpod-ctrl" && go mod verify)
install -m 0755 "$CONTROLLER_SOURCE/src/peerpod-ctrl/bin/manager" "$CONTROLLER_BUILD/context/manager"
cp "$ROOT/deployment/peerpods/Dockerfile.controller" "$CONTROLLER_BUILD/context/Dockerfile"
go version -m "$CONTROLLER_BUILD/context/manager"
sha256sum "$CONTROLLER_BUILD/context/manager"
python3 - "$CONTROLLER_BUILD" <<'PY'
from pathlib import Path
import sys, tarfile
work = Path(sys.argv[1])
binary = work / 'context/manager'
with tarfile.open(work / 'manager.layer.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
    entry = tarfile.TarInfo('manager')
    entry.size, entry.mode, entry.mtime = binary.stat().st_size, 0o755, 0
    with binary.open('rb') as source:
        archive.addfile(entry, source)
PY
CONTROLLER_REPOSITORY=$(jq -er '.build.peerpod_ctrl.repository' "$ROOT/deployment/runtime/artifacts.lock.json")
PEERPOD_CTRL_TAG=$(jq -er '.build.peerpod_ctrl.tag' "$ROOT/deployment/runtime/artifacts.lock.json")
CONTROLLER_RUNTIME=$(jq -er '.images.peerpod_ctrl_runtime' "$ROOT/deployment/runtime/artifacts.lock.json")
mkdir -p "$ROOT/artifacts/images"
CONTROLLER_IMAGE_ARCHIVE="$ROOT/artifacts/images/peerpod-controller.tar"
crane append --platform=linux/amd64 --base "$CONTROLLER_RUNTIME" \
  --new_layer "$CONTROLLER_BUILD/manager.layer.tar" --new_tag "$CONTROLLER_REPOSITORY:$PEERPOD_CTRL_TAG" \
  --output "$CONTROLLER_IMAGE_ARCHIVE"
crane digest --tarball "$CONTROLLER_IMAGE_ARCHIVE"
sha256sum "$CONTROLLER_IMAGE_ARCHIVE"
