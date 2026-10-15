#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/verify-csi-chart.sh
Verify the handoff CSI chart checksum and patched-source provenance.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq tar
CSI_CHART="$HANDOFF/charts/caa-csi-block-driver.tgz"
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
CSI_CHART_SHA256=$(jq -er '.artifacts["csi-chart"].sha256' "$HANDOFF/build-manifest.json")
printf '%s  %s\n' "$CSI_CHART_SHA256" "$CSI_CHART" | sha256sum -c -
tar -xOf "$CSI_CHART" caa-csi-block-driver/source-provenance.json > "$OPERATOR_DIR/csi-chart-source.json"
jq -e --slurpfile source "$OPERATOR_DIR/csi-chart-source.json" \
  '.artifacts["csi-chart"].source == $source[0] and
   .sources["caa-csi-block-driver"].patch_check == "verified" and
   $source[0].patched_result_tree == .sources["caa-csi-block-driver"].expected_patched_result_tree and
   $source[0].source_upstream_commit == .sources["caa-csi-block-driver"].source_upstream_commit' \
  "$HANDOFF/build-manifest.json"
