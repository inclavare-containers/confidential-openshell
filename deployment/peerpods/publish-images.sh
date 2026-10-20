#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/publish-images.sh
Publish handoff images and locked runtime mirrors. Set HOST_IP and HANDOFF; writes digest records in OPERATOR_DIR.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
verify_handoff
load_selection
REGISTRY_ADDR="$HOST_IP:5000"
install -d -m 0700 "$OPERATOR_DIR"
for name in pause supervisor sandbox workload agent_sandbox_controller \
  kata_kubectl peerpod_webhook cert_manager_controller cert_manager_webhook \
  cert_manager_cainjector cert_manager_startup csi_provisioner csi_node_registrar; do
  ref=$(jq -er --arg name "$name" '.images[$name]' deployment/runtime/artifacts.lock.json)
  dest="$REGISTRY_ADDR/openshell/mirror/$name:locked"
  printf 'Publishing %s\n' "$name"
  crane copy --platform linux/amd64 "$ref" "$dest"
  digest=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$dest")
  printf '%s@%s\n' "${dest%:*}" "$digest" > "$OPERATOR_DIR/$name-image.txt"
done
for archive in caa csi peerpod-controller; do
  docker load -i "$HANDOFF/outputs/$archive.tar"
done
for pair in "cloud-api-adaptor:$CAA_TAG" "caa-csi-block-driver:$CSI_TAG" "peerpod-ctrl:$PEERPOD_CTRL_TAG"; do
  docker tag "openshell/$pair" "$REGISTRY_ADDR/openshell/$pair"
  docker push "$REGISTRY_ADDR/openshell/$pair"
  digest=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$REGISTRY_ADDR/openshell/$pair")
  printf '%s@%s\n' "${REGISTRY_ADDR}/openshell/${pair%:*}" "$digest" > "$OPERATOR_DIR/${pair%%:*}-image.txt"
done
printf 'Images published. Digest records ready in %s\n' "$OPERATOR_DIR"
