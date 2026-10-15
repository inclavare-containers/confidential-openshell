#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/install-csi.sh
Verify the handoff chart, then install CSI with OPERATOR_DIR/csi-values.yaml and check rollout.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need helm kubectl jq
[[ -s "$OPERATOR_DIR/csi-values.yaml" ]] || die 'Create csi-values.yaml first.'
! rg -q REPLACE_WITH "$OPERATOR_DIR/csi-values.yaml" || die 'Complete all CSI values first.'
bash deployment/peerpods/verify-csi-chart.sh
CSI_CHART="$HANDOFF/charts/caa-csi-block-driver.tgz"
kubectl create namespace caa-csi-block --dry-run=client -o yaml | kubectl apply -f -
helm template caa-csi-block "$CSI_CHART" \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/csi-values.yaml" \
  > "$OPERATOR_DIR/csi-rendered.yaml"
helm upgrade --install caa-csi-block "$CSI_CHART" \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/csi-values.yaml" \
  --wait --timeout=20m
kubectl -n caa-csi-block rollout status deployment/caa-csi-block-controller --timeout=15m
kubectl -n caa-csi-block rollout status daemonset/caa-csi-block --timeout=15m
kubectl -n caa-csi-block get pvc
kubectl get storageclass alicloud-disk-essd-peerpod -o yaml
