#!/usr/bin/env bash
usage='Usage: ./cos build guest [--region REGION]
Build, verify and select the Ubuntu UKI guest. Default region: cn-beijing.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
region=cn-beijing
if (( $# )); then
  [[ $# == 2 && $1 == --region ]] || die "$usage"
  region=$2
fi
bash deployment/guest/build-image.sh
receipt=$(cat .local/guest-build/latest-receipt)
bash deployment/build/select-guest.sh built "$region" "$receipt"
