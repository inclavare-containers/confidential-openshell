#!/usr/bin/env bash
usage='Usage: bash deployment/build/unpack-release.sh
Arguments: HANDOFF_DIRECTORY APPROVED_SHA256 [DESTINATION=/opt/confidential-openshell]. Verify and extract public source.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
HANDOFF=$(realpath "${1:?provide handoff directory}")
EXPECTED_HANDOFF_SHA256=${2:?provide the authenticated SHA256SUMS checksum}
SOURCE_ROOT=${3:-/opt/confidential-openshell}
[[ $EXPECTED_HANDOFF_SHA256 =~ ^[0-9a-f]{64}$ ]] || die 'Invalid SHA256SUMS checksum'
printf '%s  %s\n' "$EXPECTED_HANDOFF_SHA256" "$HANDOFF/SHA256SUMS" | sha256sum -c -
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
[[ ! -e $SOURCE_ROOT ]] || die "Deployment source already exists: $SOURCE_ROOT. Continue deployment there; release installation does not replace an existing installation."
install -d -m 0755 "$(dirname "$SOURCE_ROOT")"
staging=$(mktemp -d "$(dirname "$SOURCE_ROOT")/.confidential-openshell.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
tar -xf "$HANDOFF/source/integration.tar" -C "$staging"
for repo in openshell cloud-api-adaptor caa-csi-block-driver; do
  install -d -m 0755 "$staging/repos" "$staging/repos/$repo"
  tar -xf "$HANDOFF/source/$repo.tar" -C "$staging/repos/$repo"
done
install -d -m 0700 "$OPERATOR_DIR"
install -m 0755 "$HANDOFF/outputs/containerd-shim-kata-v2" "$OPERATOR_DIR/"
(cd "$OPERATOR_DIR" && sha256sum containerd-shim-kata-v2 > shim.sha256)
chmod 0755 "$staging"
mv -T "$staging" "$SOURCE_ROOT"
cd "$SOURCE_ROOT"

printf 'Public source installed: %s\n' "$SOURCE_ROOT"
