#!/usr/bin/env bash
usage='Usage: bash deployment/build/package-release.sh
Package public outputs with source provenance. Select a guest first; requires a clean committed checkout.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq docker git python3
build_tags
AGENT_IMAGE_ID=$(docker image inspect "$AGENT_TAG" --format '{{.Id}}')
selection=.local/guest-selection.json
PODVM_MODE=$(jq -er .mode "$selection")
PODVM_REGION=$(jq -er .region "$selection")
PODVM_IMAGE_ID=$(jq -r .image_id "$selection")
PODVM_QCOW2=$(jq -r .qcow "$selection")
PODVM_REFERENCE_VALUES=$(jq -er .references "$selection")
GUEST_BUILD_RECEIPT=$(jq -r .receipt "$selection")
cd "$BUILD_ROOT"
HANDOFF="$BUILD_ROOT/artifacts/handoff"
test ! -e "$HANDOFF" # A fresh handoff cannot include stale or private files.
mkdir -p "$HANDOFF/source" "$HANDOFF/outputs" "$HANDOFF/charts" artifacts/images
docker save -o artifacts/images/caa.tar "openshell/cloud-api-adaptor:$CAA_TAG"
docker save -o artifacts/images/csi.tar "openshell/caa-csi-block-driver:$CSI_TAG"
docker save -o artifacts/images/agent.tar "$AGENT_IMAGE_ID"
AGENT_CONFIG_DIGEST=$(python3 - artifacts/images/agent.tar <<'PYCONFIG'
import hashlib, json, sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    matches = []
    for image in json.load(archive.extractfile('manifest.json')):
        raw = archive.extractfile(image['Config']).read()
        config = json.loads(raw)
        if config['os'] == 'linux' and config['architecture'] == 'amd64':
            matches.append('sha256:' + hashlib.sha256(raw).hexdigest())
    assert len(matches) == 1, 'expected one Linux/amd64 agent image'
    print(matches[0])
PYCONFIG
)
GUEST_ARTIFACTS=(--artifact "guest-references=$PODVM_REFERENCE_VALUES")
if [[ "$PODVM_MODE" == import ]]; then
  GUEST_ARTIFACTS+=(--artifact "guest-image=$PODVM_QCOW2")
fi
python3 deployment/build/manifest.py --profile release \
  --artifact driver=artifacts/openshell-driver-confidential-kubernetes \
  --artifact kata-shim=artifacts/containerd-shim-kata-v2 \
  "${GUEST_ARTIFACTS[@]}" \
  --artifact caa-image-archive=artifacts/images/caa.tar \
  --artifact csi-image-archive=artifacts/images/csi.tar \
  --artifact peerpod-controller-image-archive=artifacts/images/peerpod-controller.tar \
  --artifact agent-image-archive=artifacts/images/agent.tar \
  --artifact csi-chart=artifacts/charts/caa-csi-block-driver.tgz > artifacts/build-manifest.json
git archive --format=tar HEAD > "$HANDOFF/source/integration.tar"
for repo in openshell cloud-api-adaptor caa-csi-block-driver; do
  git -C "repos/$repo" archive --format=tar HEAD > "$HANDOFF/source/$repo.tar"
done
cp artifacts/build-manifest.json "$HANDOFF/"
cp artifacts/openshell-driver-confidential-kubernetes artifacts/containerd-shim-kata-v2 \
  "$PODVM_REFERENCE_VALUES" artifacts/images/caa.tar artifacts/images/csi.tar artifacts/images/agent.tar \
  artifacts/images/peerpod-controller.tar \
  "$HANDOFF/outputs/"
if [[ "$PODVM_MODE" == import ]]; then
  cp "$PODVM_QCOW2" "$HANDOFF/outputs/"
  cp "$(dirname "$GUEST_BUILD_RECEIPT")/source-manifest.json" "$HANDOFF/guest-manifest.json"
fi
cp artifacts/charts/caa-csi-block-driver.tgz "$HANDOFF/charts/"
# Use the exact published/reproducible archives verified above.
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "artifacts/cache/helm/$name" | sha256sum -c -
  cp "artifacts/cache/helm/$name" "$HANDOFF/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
jq -n --arg caa "$CAA_TAG" --arg csi "$CSI_TAG" --arg peerpod_ctrl "$PEERPOD_CTRL_TAG" \
  --arg agent "$AGENT_TAG" --arg agent_image_id "$AGENT_IMAGE_ID" --arg agent_config_digest "$AGENT_CONFIG_DIGEST" \
  --arg mode "$PODVM_MODE" --arg region "$PODVM_REGION" --arg image_id "$PODVM_IMAGE_ID" \
  --arg guest "${PODVM_QCOW2##*/}" --arg refs "$(basename "$PODVM_REFERENCE_VALUES")" \
  '{caa_tag:$caa,csi_tag:$csi,peerpod_ctrl_tag:$peerpod_ctrl,agent_tag:$agent,agent_image_id:$agent_image_id,agent_config_digest:$agent_config_digest,
    podvm_mode:$mode,podvm_region:$region,podvm_image_id:$image_id,
    guest:(if $mode == "import" then $guest else null end),references:$refs}' > "$HANDOFF/selection.json"
(cd "$HANDOFF" && sha256sum source/*.tar outputs/* charts/* \
  *.json > SHA256SUMS)
sha256sum "$HANDOFF/SHA256SUMS" # Retain through the authenticated administrative channel.
printf 'Handoff ready: %s\n' "$HANDOFF"
printf 'Retain the SHA256SUMS hash above for authenticated transfer.\n'
