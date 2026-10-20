#!/usr/bin/env bash
usage='Usage: ./cos gateway login
Register the local native CLI with the installed private operator identity and check whoami.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
service_addresses
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
export OPENSHELL_GATEWAY=confidential-local
install -d -m 0700 "$XDG_CONFIG_HOME"
endpoint="https://${HOST_IP}:9443"
existing=$(openshell gateway list --output json | jq -c --arg name "$OPENSHELL_GATEWAY" '.[] | select(.name == $name)')
if [[ -n $existing ]]; then
  jq -e --arg endpoint "$endpoint" '.endpoint == $endpoint and .auth == "mtls" and .is_remote == false' <<< "$existing" >/dev/null \
    || die 'The saved Gateway registration differs from this deployment. Review it with openshell gateway list.'
  openshell gateway select "$OPENSHELL_GATEWAY"
else
  openshell gateway add --name "$OPENSHELL_GATEWAY" --local "$endpoint"
fi
openshell whoami --output json
printf 'Native operator identity verified. Coding-agent commands are in docs/first-agent.md.\n'
