#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/fetch-prerequisites.sh
Fetch the pinned Agent Sandbox manifest and cert-manager chart into OPERATOR_DIR.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq curl
install -d -m 0700 "$OPERATOR_DIR"
for item in agent_sandbox_manifest cert_manager_chart; do
  release_download "$item" "$OPERATOR_DIR/$item"
done
install -m 0600 "$OPERATOR_DIR/agent_sandbox_manifest" "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
printf 'Dependencies ready. Set the controller image digest in agent-sandbox-pinned.yaml.\n'
