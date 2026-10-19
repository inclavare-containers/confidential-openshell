#!/usr/bin/env bash
usage='Usage: bash deployment/trustee/create-certificates.sh
Create the initial Trustee CA, server certificate and AS signer using HOST_IP. Existing PKI is refused.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
install -d -m 0700 /etc/trustee/tls "$OPERATOR_DIR"
[[ -z $(find /etc/trustee/tls -mindepth 1 -print -quit) ]] || die 'PKI already exists. Retain it; do not regenerate the CA.'
test ! -e /etc/trustee/tls/ca.key && test ! -e /etc/trustee/tls/ca.pem
sed "s/TRUSTED_SERVICE_IP/$HOST_IP/g" deployment/trustee/certificates/server.example.ext > "$OPERATOR_DIR/server.ext"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/trustee/tls/ca.key
openssl req -x509 -new -sha256 -days 3650 \
  -key /etc/trustee/tls/ca.key \
  -config deployment/trustee/certificates/ca.cnf \
  -out /etc/trustee/tls/ca.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/trustee/tls/server.key
openssl req -new -sha256 -key /etc/trustee/tls/server.key \
  -subj /CN=confidential-openshell-trustee -out /etc/trustee/tls/server.csr
openssl x509 -req -sha256 -days 825 -in /etc/trustee/tls/server.csr \
  -CA /etc/trustee/tls/ca.pem -CAkey /etc/trustee/tls/ca.key -CAcreateserial \
  -extfile "$OPERATOR_DIR/server.ext" -out /etc/trustee/tls/server.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/trustee/tls/as-token.key
openssl req -new -sha256 -key /etc/trustee/tls/as-token.key \
  -subj /CN=confidential-openshell-attestation-signer -out /etc/trustee/tls/as-token.csr
openssl x509 -req -sha256 -days 825 -in /etc/trustee/tls/as-token.csr \
  -CA /etc/trustee/tls/ca.pem -CAkey /etc/trustee/tls/ca.key -CAcreateserial \
  -extfile deployment/trustee/certificates/as-token.ext -out /etc/trustee/tls/as-token.pem
cat /etc/trustee/tls/server.pem /etc/trustee/tls/ca.pem > /etc/trustee/tls/server-chain.pem
cat /etc/trustee/tls/as-token.pem /etc/trustee/tls/ca.pem > /etc/trustee/tls/as-token-chain.pem
openssl x509 -in /etc/trustee/tls/as-token.pem -pubkey -noout > /etc/trustee/tls/as-token-public.pem
chown root:root /etc/trustee/tls/*.key
chmod 0600 /etc/trustee/tls/*.key
chmod 0644 /etc/trustee/tls/*.pem
openssl verify -CAfile /etc/trustee/tls/ca.pem /etc/trustee/tls/server.pem /etc/trustee/tls/as-token.pem
openssl x509 -in /etc/trustee/tls/server.pem -checkip "$HOST_IP" -noout
