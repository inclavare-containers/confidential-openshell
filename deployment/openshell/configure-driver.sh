#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/configure-driver.sh
Generate driver.env from HOST_IP and the published runtime digest records. Refuses to replace an existing file.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
private_ip
target=/etc/openshell-confidential/driver.env
[[ ! -e $target ]] || die 'driver.env exists. Review it rather than replacing an installed configuration.'
install -d -m 0750 -o root -g openshell-gateway /etc/openshell-confidential
python3 - "$HOST_IP" "$OPERATOR_DIR" > "$target.part" <<'PY'
from pathlib import Path
import re, sys
address, directory = sys.argv[1], Path(sys.argv[2])
print(f'HOST_IP={address}')
for key, name in [('WORKLOAD_IMAGE', 'workload_python'), ('SANDBOX_IMAGE', 'sandbox'),
                  ('SUPERVISOR_IMAGE', 'supervisor'), ('PAUSE_IMAGE', 'pause')]:
    ref = (directory / f'{name}-image.txt').read_text().strip()
    assert re.fullmatch(re.escape(address) + r':5000/[a-z0-9_./-]+@sha256:[0-9a-f]{64}', ref), name
    print(f'{key}={ref}')
PY
install -o root -g openshell-gateway -m 0640 "$target.part" "$target"
rm "$target.part"
printf 'Driver configuration ready: %s\n' "$target"
