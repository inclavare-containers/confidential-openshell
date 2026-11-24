#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/start-services.sh
Start the driver and native Gateway using /etc/openshell-confidential/driver.env.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
test -s /etc/openshell-confidential/driver.env
if grep -q REPLACE_WITH /etc/openshell-confidential/driver.env; then
  exit 1
fi
install -m 0644 deployment/openshell/openshell-confidential-driver.service \
  /etc/systemd/system/openshell-confidential-driver.service
install -m 0644 deployment/openshell/openshell-confidential-gateway.service \
  /etc/systemd/system/openshell-confidential-gateway.service
systemctl daemon-reload
systemctl enable --now openshell-confidential-driver.service
for attempt in $(seq 1 60); do
  test -S /run/openshell-confidential/driver.sock && break
  sleep 1
done
test -S /run/openshell-confidential/driver.sock
systemctl enable --now openshell-confidential-gateway.service
for attempt in $(seq 1 60); do
  curl -fsS http://127.0.0.1:17671/readyz && break
  sleep 1
done
curl -fsS http://127.0.0.1:17671/readyz
if [[ ${OPENSHELL_CONFIDENTIAL_RUNTIME_CLASS:-kata-remote} == kata-remote ]]; then
  python3 deployment/peerpods/workers.py --check-gateway
fi
printf 'Gateway and confidential driver are ready.\n'
