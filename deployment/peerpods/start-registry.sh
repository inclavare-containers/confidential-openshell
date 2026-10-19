#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/start-registry.sh
Start the TLS registry on HOST_IP:5000 with the Trustee server certificate.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
REGISTRY_ADDR="${HOST_IP}:5000"
install -d -m 0755 "/etc/docker/certs.d/${REGISTRY_ADDR}"
install -m 0644 /etc/trustee/tls/ca.pem "/etc/docker/certs.d/${REGISTRY_ADDR}/ca.crt"
if command -v update-ca-trust >/dev/null; then
  install -m 0644 /etc/trustee/tls/ca.pem /etc/pki/ca-trust/source/anchors/openshell-registry.crt
  update-ca-trust
else
  install -m 0644 /etc/trustee/tls/ca.pem /usr/local/share/ca-certificates/openshell-registry.crt
  update-ca-certificates
fi
install -d -m 0700 /var/lib/openshell-confidential/registry
docker run -d --name openshell-registry --restart unless-stopped \
  -p 0.0.0.0:5000:5000 \
  -v /etc/trustee/tls/server-chain.pem:/certs/domain.crt:ro \
  -v /etc/trustee/tls/server.key:/certs/domain.key:ro \
  -v /var/lib/openshell-confidential/registry:/var/lib/registry \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  "$(jq -er .images.registry deployment/runtime/artifacts.lock.json)"
for attempt in $(seq 1 30); do
  if curl --noproxy '*' --cacert /etc/trustee/tls/ca.pem -fsS "https://${REGISTRY_ADDR}/v2/"; then
    printf '\nRegistry ready: https://%s\n' "$REGISTRY_ADDR"
    exit 0
  fi
  sleep 2
done
die 'Registry did not become ready; inspect docker logs openshell-registry.'
