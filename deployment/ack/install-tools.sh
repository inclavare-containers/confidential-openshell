#!/usr/bin/env bash
usage='Usage: bash deployment/ack/install-tools.sh
Install the checksum-pinned Alibaba Cloud CLI from its official China CDN.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
need curl jq tar
version=$(jq -er '.tools.aliyun.version' "$LOCK")
expected=$(jq -er '.tools.aliyun.sha256' "$LOCK")
if ! checked "$expected" /usr/local/bin/aliyun; then
    mkdir -p "$TOOL_CACHE"
    if ! checked "$expected" "$TOOL_CACHE/aliyun"; then
        curl -fsSL --connect-timeout 15 --max-time 900 --retry 5 --retry-all-errors \
            "https://aliyuncli.alicdn.com/aliyun-cli-linux-${version}-amd64.tgz" \
            -o "$TOOL_CACHE/aliyun.download.part"
        tar -xzOf "$TOOL_CACHE/aliyun.download.part" aliyun > "$TOOL_CACHE/aliyun.part"
        checked "$expected" "$TOOL_CACHE/aliyun.part" || die 'Checksum mismatch: aliyun'
        mv "$TOOL_CACHE/aliyun.part" "$TOOL_CACHE/aliyun"
    fi
    install -m 0755 "$TOOL_CACHE/aliyun" /usr/local/bin/aliyun
fi
aliyun version
printf 'Alibaba Cloud CLI ready. Configure your operator credentials with aliyun configure.\n'
