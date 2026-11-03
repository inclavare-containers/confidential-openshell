#!/usr/bin/env bash
usage='Usage:
  bash deployment/build/select-guest.sh built REGION BUILD_RECEIPT
  bash deployment/build/select-guest.sh existing REGION IMAGE_ID REFERENCES SHA256
Record the selected image and checksum-verified references in .local/guest-selection.json.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq sha256sum
mode=${1:?"$usage"}; region=${2:?"$usage"}
bash deployment/build/check-region.sh "$region"
image_id=; qcow=; receipt=
mkdir -p artifacts/guest .local
case "$mode" in
    built)
        receipt=${3:?"$usage"}
        [[ $(jq -er .integration_commit "$receipt") == "$(git rev-parse HEAD)" ]] || die 'Guest receipt belongs to another integration commit.'
        qcow=$(jq -er .qcow2.path "$receipt")
        refs=$(jq -er .references.path "$receipt")
        checked "$(jq -er .qcow2.sha256 "$receipt")" "$qcow" || die 'Guest image checksum mismatch.'
        checked "$(jq -er .references.sha256 "$receipt")" "$refs" || die 'Reference checksum mismatch.'
        mode=import
        ;;
    existing)
        image_id=${3:?"$usage"}; original=${4:?"$usage"}; expected=${5:?"$usage"}
        [[ $image_id =~ ^m-[a-z0-9]+$ && $expected =~ ^[0-9a-f]{64}$ ]] || die 'Invalid image ID or reference checksum.'
        checked "$expected" "$original" || die 'Reference checksum mismatch.'
        refs="$ROOT/artifacts/guest/openshell-guest-${expected:0:12}.references.json"
        install -m 0644 "$original" "$refs"
        ;;
    *) die "$usage" ;;
esac
jq -e 'type == "object" and length > 0 and all(.[];
    type == "array" and length > 0 and all(.[]; type == "string" and length > 0))' "$refs" >/dev/null
jq -n --arg mode "$mode" --arg region "$region" --arg image_id "$image_id" \
    --arg qcow "$qcow" --arg refs "$refs" --arg receipt "$receipt" \
    '{mode:$mode,region:$region,image_id:$image_id,qcow:$qcow,references:$refs,receipt:$receipt}' \
    > .local/guest-selection.json
printf 'Guest selected: %s (%s). Ready to package the handoff.\n' "$region" "$mode"
