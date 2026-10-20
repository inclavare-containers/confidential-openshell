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
install -d -m 0700 -o openshell-gateway -g openshell-gateway \
  /opt/trustee/attestation-service/storage/attestation_service_policy \
  /opt/trustee/kbs /opt/trustee/kbs/storage /opt/trustee/kbs/storage/kbs \
  /opt/trustee/kbs/storage/repository /opt/trustee/kbs/signing \
  /opt/trustee/kbs/signing/bindings /opt/trustee/kbs/signing/workspace-bindings
for pair in kbs-config.example.toml:kbs-config.toml as-config.json:as-config.json; do
  source_file="deployment/trustee/${pair%:*}"
  target_file="/etc/trustee/${pair#*:}"
  if [[ -e $target_file ]]; then
    cmp -s "$source_file" "$target_file" || die "Existing $target_file differs from the release; review it before changing it."
  else
    install -m 0600 "$source_file" "$target_file"
  fi
done
runuser -u openshell-gateway -- test -r "$ROOT/deployment/trustee/render-kbs-policy.py" || \
  die "The service account cannot read deployment sources under $ROOT. Continue from the installed release: cd /opt/confidential-openshell && ./cos trustee install"
if [[ ! -e /opt/trustee/kbs/storage/kbs/resource-policy.rego ]]; then
  runuser -u openshell-gateway -- python3 deployment/trustee/render-kbs-policy.py \
  --bindings-dir /opt/trustee/kbs/signing/bindings \
  --workspace-bindings-dir /opt/trustee/kbs/signing/workspace-bindings \
  --as-policy-output /opt/trustee/attestation-service/storage/attestation_service_policy/default_cpu.rego \
  --output /opt/trustee/kbs/storage/kbs/resource-policy.rego
else
  printf 'Existing Trustee resource policy and bindings retained.\n'
fi

printf 'TRUSTEE_AS_IMAGE=%s\nTRUSTEE_KBS_IMAGE=%s\n' \
  "$(jq -er .images.trustee_as "$LOCK")" "$(jq -er .images.trustee_kbs "$LOCK")" > /etc/trustee/images.env
install -m 0644 deployment/trustee/units/as.service /etc/systemd/system/as.service
install -m 0644 deployment/trustee/units/kbs.service /etc/systemd/system/kbs.service
systemctl daemon-reload
printf 'Trustee installed; authorization state retained. Next: ./cos trustee start\n'
