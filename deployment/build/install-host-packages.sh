#!/usr/bin/env bash
usage='Usage: bash deployment/build/install-host-packages.sh [build|service]
Install Ubuntu 24.04 packages and start Docker. Default: build (includes compiler dependencies).'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(uname -m) == x86_64 ]] || die 'This recipe requires Ubuntu 24.04 on amd64.'
role=${1:-build}
case "$role" in build|service) ;; *) die "$usage" ;; esac
packages=(ca-certificates curl git git-lfs jq openssl openssh-client python3 python3-cryptography python3-yaml
    tar gzip xz-utils zstd file binutils ripgrep rsync docker.io docker-buildx runc cryptsetup-bin util-linux)
if [[ $role == build ]]; then
    packages+=(build-essential cmake pkg-config clang libclang-dev libssl-dev rustup)
fi
apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update
DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 \
    install -y --no-install-recommends "${packages[@]}"
systemctl enable --now docker
python3 -c 'import sys, tomllib, cryptography, yaml; assert sys.version_info >= (3, 11); print("Python:", sys.version.split()[0])'
docker version --format 'Docker server: {{.Server.Version}}'
printf 'Host packages ready (%s).\n' "$role"
