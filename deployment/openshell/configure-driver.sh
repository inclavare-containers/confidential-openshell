#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/configure-driver.sh
Generate/check driver.env from HOST_IP and the published runtime digest records.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
service_addresses
test -r /etc/openshell-confidential/trustee-client.json || die "Connect Trustee first: ./cos trustee start or ./cos trustee connect."
install -d -m 0700 -o openshell-gateway -g openshell-gateway /var/lib/openshell-confidential/driver
target=/etc/openshell-confidential/driver.env
install -d -m 0750 -o root -g openshell-gateway /etc/openshell-confidential
python3 - "$HOST_IP" "$OPERATOR_DIR" "$REGISTRY_ADDR" "$REGISTRY_CA" "$target" > "$target.part" <<'PY'
from pathlib import Path
import re, sys
address, directory, registry, registry_ca = sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4]
print(f'REGISTRY_ADDR={registry}')
print(f'REGISTRY_CA={registry_ca}')
print(f'HOST_IP={address}')
for key, name in [('WORKLOAD_IMAGE', 'workload'), ('SANDBOX_IMAGE', 'sandbox'),
                  ('SUPERVISOR_IMAGE', 'supervisor'), ('PAUSE_IMAGE', 'pause')]:
    ref = (directory / f'{name}-image.txt').read_text().strip()
    assert re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', ref), name
    print(f'{key}={ref}')
existing = Path(sys.argv[5])
if existing.exists():
    generated = {'REGISTRY_ADDR', 'REGISTRY_CA', 'HOST_IP', 'WORKLOAD_IMAGE',
                 'SANDBOX_IMAGE', 'SUPERVISOR_IMAGE', 'PAUSE_IMAGE'}
    for line in existing.read_text().splitlines():
        if line.partition('=')[0].strip() not in generated:
            print(line)
PY
install -o root -g openshell-gateway -m 0640 "$target.part" "$target"
rm "$target.part"
printf 'Driver configuration ready: %s\n' "$target"
