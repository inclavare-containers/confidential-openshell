#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/install-peerpods.sh
Render and install PeerPods using OPERATOR_DIR/peerpods-values.yaml, then check rollout.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need helm kubectl jq
[[ -s "$OPERATOR_DIR/peerpods-values.yaml" ]] || die 'Create peerpods-values.yaml first.'
! rg -q REPLACE_WITH "$OPERATOR_DIR/peerpods-values.yaml" || die 'Complete all PeerPods values first.'
selected=$(jq -er '.worker_nodes | select(length > 0) | length' "$OPERATOR_DIR/ack-state.json")
labelled=$(kubectl get nodes -l node.kubernetes.io/worker -o json | jq '.items | length')
[[ $labelled == "$selected" ]] || die 'Worker labels differ from the saved selection. Run ./cos workers select and review existing worker labels.'
bash deployment/peerpods/prepare-chart.sh
helm template peerpods .local/charts/peerpods \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/peerpods-values.yaml" \
  > "$OPERATOR_DIR/peerpods-rendered.yaml"
helm upgrade --install peerpods .local/charts/peerpods \
  --namespace confidential-containers-system --create-namespace \
  --values "$OPERATOR_DIR/peerpods-values.yaml" --timeout=25m
kubectl -n confidential-containers-system patch deployment peerpodctrl-controller-manager \
  --type=strategic --patch-file deployment/peerpods/peerpod-controller-rrsa.patch.yaml
kubectl -n confidential-containers-system rollout status daemonset/kata-deploy --timeout=25m
kubectl -n confidential-containers-system rollout status daemonset/cloud-api-adaptor-daemonset --timeout=15m
kubectl -n confidential-containers-system rollout status deployment/peerpodctrl-controller-manager --timeout=15m
kubectl -n peer-pods-webhook-system rollout status deployment/peer-pods-webhook-controller-manager --timeout=15m
for daemonset in kata-deploy cloud-api-adaptor-daemonset; do
  kubectl -n confidential-containers-system get daemonset "$daemonset" -o json \
    | jq -e --argjson selected "$selected" '.status.desiredNumberScheduled == $selected and .status.numberReady == $selected' >/dev/null
done
printf 'PeerPods ready: Kata and CAA cover all %s selected workers; controller and webhook rollouts passed.\n' "$selected"
