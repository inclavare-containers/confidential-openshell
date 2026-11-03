#!/usr/bin/env bash
usage='Usage: bash deployment/build/package-release.sh
Package public outputs with source provenance. Select a guest first; requires a clean committed checkout.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq docker git python3
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
  git status --short
  die 'Release packaging requires a clean committed checkout. Resolve the source changes above before packaging.'
fi
build_tags
selection=.local/guest-selection.json
PODVM_MODE=$(jq -er .mode "$selection")
PODVM_REGION=$(jq -er .region "$selection")
bash deployment/build/check-region.sh "$PODVM_REGION"
PODVM_IMAGE_ID=$(jq -r .image_id "$selection")
PODVM_QCOW2=$(jq -r .qcow "$selection")
PODVM_REFERENCE_VALUES=$(jq -er .references "$selection")
GUEST_BUILD_RECEIPT=$(jq -r .receipt "$selection")
cd "$BUILD_ROOT"
destination="$BUILD_ROOT/artifacts/handoff"
[[ ! -e "$destination" ]] || die "Completed handoff already exists: $destination. Retain it before packaging another release."
mkdir -p "$BUILD_ROOT/artifacts"
HANDOFF=$(mktemp -d "$BUILD_ROOT/artifacts/.handoff.XXXXXX")
trap 'rm -rf -- "$HANDOFF"' EXIT
mkdir -p "$HANDOFF/source" "$HANDOFF/outputs" "$HANDOFF/charts" artifacts/images
docker save -o artifacts/images/caa.tar "openshell/cloud-api-adaptor:$CAA_TAG"
docker save -o artifacts/images/csi.tar "openshell/caa-csi-block-driver:$CSI_TAG"
GUEST_ARTIFACTS=(--artifact "guest-references=$PODVM_REFERENCE_VALUES")
if [[ "$PODVM_MODE" == import ]]; then
  GUEST_ARTIFACTS+=(--artifact "guest-image=$PODVM_QCOW2")
fi
python3 deployment/build/manifest.py --profile release \
  --artifact attestation-observer=artifacts/openshell-attestation-observer \
  --artifact driver=artifacts/openshell-driver-confidential-kubernetes \
  --artifact kata-shim=artifacts/containerd-shim-kata-v2 \
  "${GUEST_ARTIFACTS[@]}" \
  --artifact caa-image-archive=artifacts/images/caa.tar \
  --artifact csi-image-archive=artifacts/images/csi.tar \
  --artifact peerpod-controller-image-archive=artifacts/images/peerpod-controller.tar \
  --artifact csi-chart=artifacts/charts/caa-csi-block-driver.tgz > artifacts/build-manifest.json
git archive --format=tar HEAD > "$HANDOFF/source/integration.tar"
for repo in openshell cloud-api-adaptor caa-csi-block-driver; do
  git -C "repos/$repo" archive --format=tar HEAD > "$HANDOFF/source/$repo.tar"
done
cp artifacts/build-manifest.json "$HANDOFF/"
cp artifacts/openshell-driver-confidential-kubernetes artifacts/openshell-attestation-observer artifacts/containerd-shim-kata-v2 \
  "$PODVM_REFERENCE_VALUES" artifacts/images/caa.tar artifacts/images/csi.tar \
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
  --arg mode "$PODVM_MODE" --arg region "$PODVM_REGION" --arg image_id "$PODVM_IMAGE_ID" \
  --arg guest "${PODVM_QCOW2##*/}" --arg refs "$(basename "$PODVM_REFERENCE_VALUES")" \
  '{caa_tag:$caa,csi_tag:$csi,peerpod_ctrl_tag:$peerpod_ctrl,
    podvm_mode:$mode,podvm_region:$region,podvm_image_id:$image_id,
    guest:(if $mode == "import" then $guest else null end),references:$refs}' > "$HANDOFF/selection.json"
(cd "$HANDOFF" && sha256sum source/*.tar outputs/* charts/* \
  *.json > SHA256SUMS)
(cd "$HANDOFF" && sha256sum -c SHA256SUMS --quiet)
mv -T "$HANDOFF" "$destination"
trap - EXIT
HANDOFF="$destination"
sha256sum "$HANDOFF/SHA256SUMS" # Retain through the authenticated administrative channel.
sha256sum "$HANDOFF/SHA256SUMS" | cut -d ' ' -f1 > "$BUILD_ROOT/artifacts/handoff.sha256"
printf 'Handoff ready: %s\n' "$HANDOFF"
printf 'Retain the SHA256SUMS hash above for authenticated transfer.\n'
