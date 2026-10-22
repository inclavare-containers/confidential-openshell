#!/usr/bin/env bash
usage='Usage: bash deployment/trustee/install.sh
Install locked Trustee images, directories and deny policies. Does not start services.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
install -d -m 0700 "$OPERATOR_DIR"
test -f /etc/trustee/tls/server.pem
for image in trustee_as trustee_kbs; do
  ref=$(jq -er --arg image "$image" '.images[$image]' deployment/runtime/artifacts.lock.json)
  docker pull --platform linux/amd64 "$ref"
done
id openshell-gateway >/dev/null 2>&1 || useradd --system \
  --home-dir /var/lib/openshell-confidential --shell /usr/sbin/nologin openshell-gateway
install -d -m 0750 -o root -g openshell-gateway \
  /etc/trustee /etc/trustee/tls /opt/trustee \
  /opt/trustee/attestation-service /opt/trustee/attestation-service/storage
install -d -m 0700 -o root -g root /opt/trustee/attestation-service/storage/attestation_service_policy \
  /opt/trustee/kbs/storage \
  /opt/trustee/kbs/storage/kbs
install -d -m 0750 -o root -g openshell-gateway /etc/openshell-confidential
if [[ ! -f /etc/openshell-confidential/trustee-admin.key ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out /etc/openshell-confidential/trustee-admin.key
fi
chown root:openshell-gateway /etc/openshell-confidential/trustee-admin.key
chmod 0640 /etc/openshell-confidential/trustee-admin.key
openssl pkey -in /etc/openshell-confidential/trustee-admin.key -pubout -out /etc/trustee/admin-public.pem
chmod 0644 /etc/trustee/admin-public.pem
for pair in kbs-config.example.toml:kbs-config.toml as-config.json:as-config.json; do
  source_file="deployment/trustee/${pair%:*}"
  target_file="/etc/trustee/${pair#*:}"
  if [[ -e $target_file ]]; then
    printf 'Retaining configured Trustee server settings: %s\n' "$target_file"
  else
    install -m 0600 "$source_file" "$target_file"
  fi
done
# Initial server bootstrap is deny-only. Dynamic policy and resources are
# subsequently managed exclusively through authenticated KBS APIs.
if [[ ! -e /opt/trustee/kbs/storage/kbs/resource-policy.rego ]]; then
  printf 'package policy\ndefault allow = false\n' > /opt/trustee/kbs/storage/kbs/resource-policy.rego
fi

printf 'TRUSTEE_AS_IMAGE=%s\nTRUSTEE_KBS_IMAGE=%s\n' \
  "$(jq -er .images.trustee_as "$LOCK")" "$(jq -er .images.trustee_kbs "$LOCK")" > /etc/trustee/images.env
install -m 0644 deployment/trustee/units/as.service /etc/systemd/system/as.service
install -m 0644 deployment/trustee/units/kbs.service /etc/systemd/system/kbs.service
systemctl daemon-reload
printf 'Trustee installed; authorization state retained. Next: ./cos trustee start\n'
