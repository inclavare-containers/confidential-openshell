#!/usr/bin/env bash
usage='Usage: ./cos trustee start
Start the official AS/KBS containers, register selected references and verify anonymous resource denial.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
refs="$HANDOFF/outputs/$(jq -er .references "$HANDOFF/selection.json")"
systemctl enable --now as.service
systemctl enable --now kbs.service
systemctl is-active --quiet as.service kbs.service
code=$(curl --cacert "$KBS_CA" \
  --retry 30 --retry-connrefused --retry-delay 1 --retry-max-time 30 \
  --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' \
  "${KBS_URL}/kbs/v0/resource/default/bootstrap/anonymous-check")
[[ $code == 401 || $code == 403 ]] || die "KBS anonymous denial check failed: HTTP $code (expected 401 or 403)."
python3 deployment/trustee/configure-client.py --url "$KBS_URL" --ca "$KBS_CA" \
  --admin-key /etc/openshell-confidential/trustee-admin.key
python3 deployment/trustee/register-references.py \
  --references "$refs" --references deployment/trustee/ecs-tdx-platform.references.json
printf 'Trustee ready: AS active; references registered and read back; KBS HTTPS denies anonymous access (HTTP %s).\n' "$code"
