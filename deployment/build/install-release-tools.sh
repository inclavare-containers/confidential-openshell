#!/usr/bin/env bash
usage='Usage: bash deployment/build/install-release-tools.sh
Install checksum-pinned Helm, kubectl, crane, GitHub CLI, ORAS and the upstream-required yq.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
need jq curl tar
mkdir -p "$TOOL_CACHE"
for tool in helm kubectl crane gh oras yq; do
    version=$(jq -er --arg t "$tool" '.tools[$t].version' "$LOCK")
    expected=$(jq -er --arg t "$tool" '.tools[$t].sha256' "$LOCK")
    member=
    case "$tool" in
        helm) url="https://get.helm.sh/helm-v${version}-linux-amd64.tar.gz"; member=linux-amd64/helm ;;
        kubectl) url="https://dl.k8s.io/release/v${version}/bin/linux/amd64/kubectl" ;;
        crane) url="https://github.com/google/go-containerregistry/releases/download/v${version}/go-containerregistry_Linux_x86_64.tar.gz"; member=crane ;;
        gh) url="https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_amd64.tar.gz"; member="gh_${version}_linux_amd64/bin/gh" ;;
        yq) url="https://github.com/mikefarah/yq/releases/download/v${version}/yq_linux_amd64" ;;
        oras) url="https://github.com/oras-project/oras/releases/download/v${version}/oras_${version}_linux_amd64.tar.gz"; member=oras ;;
    esac
    if ! checked "$expected" "/usr/local/bin/$tool"; then
        if ! checked "$expected" "$TOOL_CACHE/$tool"; then
            curl -fsSL --connect-timeout 15 --max-time 900 --retry 5 --retry-all-errors \
                "$url" -o "$TOOL_CACHE/$tool.download.part"
            if [[ -n $member ]]; then
                tar -xzOf "$TOOL_CACHE/$tool.download.part" "$member" > "$TOOL_CACHE/$tool.part"
            else
                cp "$TOOL_CACHE/$tool.download.part" "$TOOL_CACHE/$tool.part"
            fi
            checked "$expected" "$TOOL_CACHE/$tool.part" || die "Checksum mismatch: $tool"
            mv "$TOOL_CACHE/$tool.part" "$TOOL_CACHE/$tool"
        fi
        install -m 0755 "$TOOL_CACHE/$tool" "/usr/local/bin/$tool"
    fi
    printf '%s %s verified\n' "$tool" "$version"
done
gh attestation verify --help >/dev/null
