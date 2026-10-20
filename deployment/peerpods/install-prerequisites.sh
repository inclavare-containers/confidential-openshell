#!/usr/bin/env bash
usage='Usage: ./cos cluster dependencies
Generate pinned dependency manifests, install Agent Sandbox and cert-manager, and wait for readiness.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need kubectl helm
bash deployment/peerpods/fetch-prerequisites.sh
kubectl apply --server-side -f "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
if ! kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller --timeout=10m; then
  kubectl -n agent-sandbox-system get pods -o wide
  kubectl -n agent-sandbox-system get events --sort-by=.lastTimestamp
  die 'Agent Sandbox is not ready. Resolve the reported events; registry trust is configured by ./cos workers registry.'
fi
helm upgrade --install cert-manager "$OPERATOR_DIR/cert_manager_chart" \
  --namespace cert-manager --create-namespace \
  --values "$OPERATOR_DIR/cert-manager-values.json" --wait --timeout=15m
printf 'Cluster dependencies ready: Agent Sandbox controller and cert-manager rollouts passed.\n'
