#!/usr/bin/env bash
usage='Usage: bash deployment/guest/install-initdata.sh
Render and install public deny-only base initdata using HOST_IP and the Trustee CA.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
test -f "$KBS_CA"
test -f "$REGISTRY_CA"
install -d -o root -g openshell-gateway -m 0750 /etc/openshell-confidential
initdata_file="$(mktemp)"
python3 deployment/guest/render-guest-initdata.py \
  --kbs-url "$KBS_URL" --kbs-ca "$KBS_CA" --registry-ca "$REGISTRY_CA" > "$initdata_file"
install -o root -g openshell-gateway -m 0640 "$initdata_file" \
  /etc/openshell-confidential/guest-initdata-base.toml
rm "$initdata_file"
