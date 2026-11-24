#!/usr/bin/env bash
# Build the unmodified upstream ttRPC client in the pinned toolchain.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="$root/deployment/artifacts.lock.json"
work="$(realpath -m "$1")"
repo="$(jq -er '.guest_components.repository' "$lock")"
commit="$(jq -er '.guest_components.commit' "$lock")"
builder="$(jq -er '.guest_components.binaries["ttrpc-cdh-tool"].builder' "$lock")"
git init -q "$work"
git -C "$work" fetch --depth=1 "https://github.com/$repo.git" "$commit"
git -C "$work" checkout --detach "$commit"
docker run --rm --volume "$work:/guest-components" --workdir /guest-components \
    --env SOURCE_DATE_EPOCH=0 --env CARGO_PROFILE_RELEASE_STRIP=symbols \
    "$builder" cargo build --release --locked --no-default-features --features bin,ttrpc \
    --package confidential-data-hub --bin ttrpc-cdh-tool
