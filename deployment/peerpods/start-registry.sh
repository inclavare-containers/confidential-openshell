#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/start-registry.sh
Start the TLS registry using its configured certificate and key.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
tls_args=()
if [[ -n $REGISTRY_CA ]]; then
    tls_args=(--cacert "$REGISTRY_CA")
    install -d -m 0755 "/etc/docker/certs.d/${REGISTRY_ADDR}"
    install -m 0644 "$REGISTRY_CA" "/etc/docker/certs.d/${REGISTRY_ADDR}/ca.crt"
    if command -v update-ca-trust >/dev/null; then
      install -m 0644 "$REGISTRY_CA" /etc/pki/ca-trust/source/anchors/openshell-registry.crt
      update-ca-trust
    else
      install -m 0644 "$REGISTRY_CA" /usr/local/share/ca-certificates/openshell-registry.crt
      update-ca-certificates
    fi
fi
install -d -m 0700 /var/lib/openshell-confidential/registry
registry_image=$(jq -er .images.registry deployment/runtime/artifacts.lock.json)
if docker inspect openshell-registry >/dev/null 2>&1; then
  docker inspect openshell-registry | jq -e --arg image "$registry_image" --arg key "$REGISTRY_TLS_KEY" '
    .[0] | .Config.Image == $image and
    any(.Mounts[]; .Source == "/var/lib/openshell-confidential/registry" and .Destination == "/var/lib/registry") and
    any(.Mounts[]; .Source == $key and .Destination == "/certs/domain.key")' >/dev/null \
    || die 'Existing openshell-registry container differs from this deployment; inspect it before changing it.'
  printf 'Reusing the existing deployment registry.\n'
  docker start openshell-registry
else
  docker run -d --name openshell-registry --restart unless-stopped \
  -p 0.0.0.0:5000:5000 \
  -v "$REGISTRY_TLS_CERT:/certs/domain.crt:ro" \
  -v "$REGISTRY_TLS_KEY:/certs/domain.key:ro" \
  -v /var/lib/openshell-confidential/registry:/var/lib/registry \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  "$registry_image"
fi
for attempt in $(seq 1 30); do
  if curl "${tls_args[@]}" -fsS "https://${REGISTRY_ADDR}/v2/"; then
    printf '\nRegistry ready: https://%s\n' "$REGISTRY_ADDR"
    exit 0
  fi
  sleep 2
done
die 'Registry did not become ready; inspect docker logs openshell-registry.'
