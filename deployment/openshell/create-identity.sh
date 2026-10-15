#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/create-identity.sh
Generate native Gateway mTLS/JWT credentials and install its configuration using HOST_IP.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
private_ip
install -d -o root -g openshell-gateway -m 0750 /etc/openshell-confidential
install -d -o root -g openshell-gateway -m 0750 /var/lib/openshell-confidential
install -d -o openshell-gateway -g openshell-gateway -m 0700 \
  /var/lib/openshell-confidential/data
test -e /var/lib/openshell-confidential/tls || \
  /usr/local/bin/openshell-gateway generate-certs \
    --output-dir /var/lib/openshell-confidential/tls --server-san "$HOST_IP"
openssl x509 -in /var/lib/openshell-confidential/tls/server/tls.crt \
  -checkip "$HOST_IP" -noout
for name in ca.crt ca.key client/tls.crt client/tls.key \
  server/tls.crt server/tls.key jwt/signing.pem jwt/public.pem jwt/kid; do
  test -f "/var/lib/openshell-confidential/tls/$name"
done
TLS_ROOT=/var/lib/openshell-confidential/tls
for directory in "$TLS_ROOT" "$TLS_ROOT/server" "$TLS_ROOT/jwt"; do
  chown root:openshell-gateway "$directory"
  chmod 0750 "$directory"
done
chown root:openshell-gateway "$TLS_ROOT/server/tls.key" "$TLS_ROOT/jwt/signing.pem"
chmod 0640 "$TLS_ROOT/server/tls.key" "$TLS_ROOT/jwt/signing.pem"
chmod 0644 "$TLS_ROOT/ca.crt" "$TLS_ROOT/server/tls.crt" "$TLS_ROOT/client/tls.crt" \
  "$TLS_ROOT/jwt/public.pem" "$TLS_ROOT/jwt/kid"
chmod 0700 "$TLS_ROOT/client"
install -o root -g openshell-gateway -m 0640 \
  deployment/openshell/gateway.toml /etc/openshell-confidential/gateway.toml
python3 - "$HOST_IP" <<'PYCONFIG'
from pathlib import Path
import ipaddress, sys
address = str(ipaddress.IPv4Address(sys.argv[1]))
assert ipaddress.IPv4Address(address).is_private
path = Path("/etc/openshell-confidential/gateway.toml")
text = path.read_text()
assert 'bind_address = "10.0.0.10:9443"' in text
path.write_text(text.replace('bind_address = "10.0.0.10:9443"', f'bind_address = "{address}:9443"'))
PYCONFIG
