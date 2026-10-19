#!/usr/bin/env bash
usage='Usage: bash deployment/build/package-kata-shim.sh
Append the checked host-shim replacement to the private kata-deploy image. Set HOST_IP first.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
REGISTRY_ADDR="$HOST_IP:5000"
KATA_DEPLOY_UPSTREAM=$(jq -er .images.kata_deploy deployment/runtime/artifacts.lock.json)
KATA_DEPLOY_DIGEST=${KATA_DEPLOY_UPSTREAM##*@}
KATA_DEPLOY_MIRROR="${REGISTRY_ADDR}/openshell/mirror/kata_deploy:4.2.0"
KATA_DEPLOY_BASE="${REGISTRY_ADDR}/openshell/mirror/kata_deploy@$KATA_DEPLOY_DIGEST"
OVERLAY_DIR="$OPERATOR_DIR/kata-shim-overlay"
install -d -m 0700 "$OVERLAY_DIR/original" "$OVERLAY_DIR/modified"
(cd "$OPERATOR_DIR" && sha256sum -c shim.sha256)
KATA_SHIM_SHA256=$(cut -d ' ' -f1 "$OPERATOR_DIR/shim.sha256")
if ! crane digest "$KATA_DEPLOY_BASE" >/dev/null 2>&1; then
  crane copy --platform linux/amd64 "$KATA_DEPLOY_UPSTREAM" "$KATA_DEPLOY_MIRROR"
fi
test "$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$KATA_DEPLOY_BASE")" = "$KATA_DEPLOY_DIGEST"
docker pull "$KATA_DEPLOY_BASE"
KATA_CONTAINER=$(docker create "$KATA_DEPLOY_BASE")
docker cp "$KATA_CONTAINER:/opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst" "$OVERLAY_DIR/original.tar.zst"
docker rm "$KATA_CONTAINER"
printf '%s  %s\n' 1b8aa859195c33f0c85c8d31dd0dd1aa0ac523d8a9a102c92af248f9e42e6a0d "$OVERLAY_DIR/original.tar.zst" | sha256sum -c -
zstd -dc "$OVERLAY_DIR/original.tar.zst" | tar -xf - -C "$OVERLAY_DIR/original"
cp -a "$OVERLAY_DIR/original/." "$OVERLAY_DIR/modified/"
install -m 0755 "$OPERATOR_DIR/containerd-shim-kata-v2" \
  "$OVERLAY_DIR/modified/opt/kata/bin/containerd-shim-kata-v2"
(cd "$OVERLAY_DIR/original" && find . -printf '%P %y %m %l\n' | LC_ALL=C sort) > "$OVERLAY_DIR/original-layout"
(cd "$OVERLAY_DIR/modified" && find . -printf '%P %y %m %l\n' | LC_ALL=C sort) > "$OVERLAY_DIR/modified-layout"
cmp "$OVERLAY_DIR/original-layout" "$OVERLAY_DIR/modified-layout"
diff -qr "$OVERLAY_DIR/original" "$OVERLAY_DIR/modified" > "$OVERLAY_DIR/content.diff" || test "$?" -eq 1
test "$(wc -l < "$OVERLAY_DIR/content.diff")" -eq 1
grep -Fx "Files $OVERLAY_DIR/original/opt/kata/bin/containerd-shim-kata-v2 and $OVERLAY_DIR/modified/opt/kata/bin/containerd-shim-kata-v2 differ" "$OVERLAY_DIR/content.diff"
tar --sort=name --numeric-owner --owner=0 --group=0 -cf - -C "$OVERLAY_DIR/modified" . \
  | zstd -f -T0 -10 -o "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst"
zstd -dc "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst" \
  | tar -tf - | grep -Fx './opt/kata/bin/containerd-shim-kata-v2'
install -d -m 0700 "$OVERLAY_DIR/layer/opt/kata-artifacts/tarballs"
install -m 0644 "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst" \
  "$OVERLAY_DIR/layer/opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst"
tar -cf "$OVERLAY_DIR/kata-deploy-overlay.layer.tar" -C "$OVERLAY_DIR/layer" \
  opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst
KATA_DEPLOY_PRIVATE="${REGISTRY_ADDR}/openshell/kata-deploy-shim-nnp:4.2.0"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane append --platform linux/amd64 \
  -b "$KATA_DEPLOY_BASE" -f "$OVERLAY_DIR/kata-deploy-overlay.layer.tar" \
  -t "$KATA_DEPLOY_PRIVATE"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$KATA_DEPLOY_PRIVATE"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest "$KATA_DEPLOY_BASE" \
  | jq -r '.layers[].digest' > "$OVERLAY_DIR/base-layers"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest "$KATA_DEPLOY_PRIVATE" \
  | jq -r '.layers[].digest' > "$OVERLAY_DIR/patched-layers"
test "$(wc -l < "$OVERLAY_DIR/patched-layers")" -eq "$(( $(wc -l < "$OVERLAY_DIR/base-layers") + 1 ))"
sed '$d' "$OVERLAY_DIR/patched-layers" | cmp - "$OVERLAY_DIR/base-layers"

printf '%s@%s\n' "${KATA_DEPLOY_PRIVATE%:*}" "$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$KATA_DEPLOY_PRIVATE")" > "$OPERATOR_DIR/kata-deploy-image.txt"
cat "$OPERATOR_DIR/kata-deploy-image.txt"
