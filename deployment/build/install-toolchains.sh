#!/usr/bin/env bash
usage='Usage: bash deployment/build/install-toolchains.sh
Install the locked Go and Rust toolchains. Reuse matching installations and verified downloads.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
need rustup python3 jq curl tar
GO_VERSION=$(jq -er .build_outputs.caa.go_version "$LOCK")
if [[ $(/usr/local/go/bin/go version 2>/dev/null || true) != "go version go$GO_VERSION linux/amd64" ]]; then
    [[ ! -e /usr/local/go ]] || die '/usr/local/go contains a different installation; move it aside before continuing.'
    mkdir -p "$TOOL_CACHE"
    curl -fsSL --connect-timeout 15 --max-time 120 --retry 5 --retry-all-errors \
        'https://go.dev/dl/?mode=json&include=all' -o "$TOOL_CACHE/go-releases.json.part"
    GO_SHA256=$(jq -er --arg version "go$GO_VERSION" \
        '.[] | select(.version == $version) | .files[] |
         select(.os == "linux" and .arch == "amd64" and .kind == "archive") | .sha256' \
        "$TOOL_CACHE/go-releases.json.part")
    download "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" "$GO_SHA256" "$TOOL_CACHE/go-$GO_VERSION.tgz"
    tar -xzf "$TOOL_CACHE/go-$GO_VERSION.tgz" -C /usr/local
fi
install -m 0644 /dev/stdin /etc/profile.d/openshell-go.sh <<'PROFILE'
export PATH=/usr/local/go/bin:$PATH
PROFILE
RUST_VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')
# Apt owns /usr/bin/rustup; upstream self-update assumes ~/.cargo/bin/rustup.
rustup set auto-self-update disable
rustup toolchain install "$RUST_VERSION" --profile minimal
rustup default "$RUST_VERSION"
rustup component add --toolchain "$RUST_VERSION" rustfmt rust-src rust-analyzer clippy
rustc --version
go version
printf 'Toolchains ready. In a new shell, /etc/profile.d/openshell-go.sh sets the Go PATH.\n'
