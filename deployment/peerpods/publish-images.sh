#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/publish-images.sh
Publish handoff images and locked runtime mirrors. Set HOST_IP and HANDOFF; writes digest records in OPERATOR_DIR.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
private_ip
verify_handoff
load_selection
REGISTRY_ADDR="$HOST_IP:5000"
install -d -m 0700 "$OPERATOR_DIR"
for name in pause supervisor sandbox workload_python; do
  ref=$(jq -er --arg name "$name" '.images[$name]' deployment/runtime/artifacts.lock.json)
  dest="$REGISTRY_ADDR/openshell/mirror/$name:locked"
  crane copy --platform linux/amd64 "$ref" "$dest"
  digest=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$dest")
  printf '%s@%s\n' "${dest%:*}" "$digest" > "$OPERATOR_DIR/$name-image.txt"
done
for archive in caa csi peerpod-controller agent; do
  docker load -i "$HANDOFF/outputs/$archive.tar"
done
test "$(docker image inspect "$AGENT_IMAGE_ID" --format '{{.Id}}')" = "$AGENT_IMAGE_ID"
for pair in "cloud-api-adaptor:$CAA_TAG" "caa-csi-block-driver:$CSI_TAG" "peerpod-ctrl:$PEERPOD_CTRL_TAG"; do
  docker tag "openshell/$pair" "$REGISTRY_ADDR/openshell/$pair"
  docker push "$REGISTRY_ADDR/openshell/$pair"
  digest=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$REGISTRY_ADDR/openshell/$pair")
  printf '%s@%s\n' "${REGISTRY_ADDR}/openshell/${pair%:*}" "$digest" > "$OPERATOR_DIR/${pair%%:*}-image.txt"
done
AGENT_DEST="$REGISTRY_ADDR/openshell/opencode:${AGENT_TAG##*:}"
docker tag "$AGENT_IMAGE_ID" "$AGENT_DEST"
docker push "$AGENT_DEST"
AGENT_DIGEST=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest --platform=linux/amd64 "$AGENT_DEST")
AGENT_IMAGE="${AGENT_DEST%:*}@$AGENT_DIGEST"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest --platform=linux/amd64 "$AGENT_IMAGE" | \
  jq -e --arg id "$AGENT_CONFIG_DIGEST" '.config.digest == $id'
printf '%s\n' "$AGENT_IMAGE" > "$OPERATOR_DIR/agent-image.txt"
