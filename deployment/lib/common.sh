#!/usr/bin/env bash
# Shared paths and checked downloads for the individual operator steps.
set -eEuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"
LOCK="$ROOT/deployment/runtime/artifacts.lock.json"
TOOL_CACHE="$ROOT/artifacts/cache/host-tools"
BUILD_ROOT="$ROOT"
SOURCE_ROOT="$ROOT"
OPERATOR_DIR="${OPERATOR_DIR:-/var/lib/openshell-confidential/operator/cluster-config}"
HANDOFF="${HANDOFF:-/var/lib/openshell-confidential/operator/handoff}"
if [[ ${1:-} == --help ]]; then
    printf '%s\n' "$usage"
    exit 0
fi
trap 'printf "Failed: %s:%s. Fix the reported error, then repeat this step.\n" "${BASH_SOURCE[0]}" "$LINENO" >&2' ERR
die() { printf '%s\n' "$*" >&2; exit 1; }
require_root() { [[ $EUID == 0 ]] || die 'Run this installation step as root.'; }
need() { local cmd; for cmd in "$@"; do command -v "$cmd" >/dev/null || die "Missing tool: $cmd. See docs/build.md."; done; }
service_addresses() {
    : "${HOST_IP:?export HOST_IP with the trusted service IPv4 reachable from the cloud}"
    HOST_BIND_IP=${HOST_BIND_IP:-$HOST_IP}
    export HOST_BIND_IP
    python3 - "$HOST_IP" "$HOST_BIND_IP" <<'PY'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
assert not (ip.is_loopback or ip.is_unspecified or ip.is_multicast), 'HOST_IP must be a cloud-reachable unicast IPv4'
bind = ipaddress.IPv4Address(sys.argv[2])
assert not bind.is_multicast, 'HOST_BIND_IP must be a local IPv4 bind address'
PY
}
checked() { [[ -f $2 ]] && printf '%s  %s\n' "$1" "$2" | sha256sum -c - >/dev/null 2>&1; }
download() {
    local url=$1 expected=$2 destination=$3
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "Invalid SHA-256 for $destination"
    if checked "$expected" "$destination"; then
        printf 'Using verified cache: %s\n' "$destination"
        return
    fi
    mkdir -p "$(dirname "$destination")"
    curl -fsSL --connect-timeout 15 --max-time 900 --retry 5 --retry-all-errors \
        "$url" -o "$destination.part"
    checked "$expected" "$destination.part" || die "Checksum mismatch: $destination.part"
    mv -f "$destination.part" "$destination"
}
release_download() {
    local name=$1 path=$2
    download "$(jq -er --arg n "$name" '.downloads[$n].url' "$LOCK")" \
        "$(jq -er --arg n "$name" '.downloads[$n].sha256' "$LOCK")" "$path"
}
verify_handoff() { (cd "$HANDOFF" && sha256sum -c SHA256SUMS); }
build_tags() {
    CAA_TAG="caa-$(jq -er '."cloud-api-adaptor".result_tree[:8]' deployment/build/sources.lock.json)"
    CSI_TAG="csi-$(jq -er '."caa-csi-block-driver".result_tree[:8]' deployment/build/sources.lock.json)"
    PEERPOD_CTRL_TAG=$(jq -er .build_outputs.peerpod_ctrl.tag "$LOCK")
}
load_selection() {
    local selection="$HANDOFF/selection.json"
    PODVM_MODE=$(jq -er .podvm_mode "$selection")
    PODVM_REGION=$(jq -er .podvm_region "$selection")
    PODVM_IMAGE_ID=$(jq -r .podvm_image_id "$selection")
    PODVM_REFERENCE_VALUES="$HANDOFF/outputs/$(jq -er .references "$selection")"
    CAA_TAG=$(jq -er .caa_tag "$selection")
    CSI_TAG=$(jq -er .csi_tag "$selection")
    PEERPOD_CTRL_TAG=$(jq -er .peerpod_ctrl_tag "$selection")
}
