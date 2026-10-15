#!/usr/bin/env bash
usage='Usage: bash deployment/build/build-agent.sh
Build and version-check the credential-free OpenCode work image.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq curl docker tar
mkdir -p artifacts/cache/agent artifacts/agent-context
AGENT_VERSION=$(jq -er .version deployment/agent/agent.lock.json)
AGENT_TAG="confidential-opencode:$AGENT_VERSION"
AGENT_ARCHIVE="artifacts/cache/agent/opencode-$AGENT_VERSION.tar.gz"
download "$(jq -er .release_url deployment/agent/agent.lock.json)" \
  "$(jq -er .release_sha256 deployment/agent/agent.lock.json)" "$AGENT_ARCHIVE"
printf '%s  %s\n' "$(jq -er .release_sha256 deployment/agent/agent.lock.json)" \
  "$AGENT_ARCHIVE" | sha256sum -c -
test "$(tar -tzf "$AGENT_ARCHIVE")" = opencode
tar --no-same-owner --no-same-permissions -xzf "$AGENT_ARCHIVE" \
  -C artifacts/agent-context opencode
test -f artifacts/agent-context/opencode && test ! -L artifacts/agent-context/opencode
chmod 0755 artifacts/agent-context/opencode
docker build --platform linux/amd64 -f deployment/agent/Dockerfile \
  -t "$AGENT_TAG" artifacts/agent-context
AGENT_IMAGE_ID=$(docker image inspect "$AGENT_TAG" --format '{{.Id}}')
docker run --rm --network=none "$AGENT_IMAGE_ID" --version
docker run --rm --network=none --entrypoint python3 "$AGENT_IMAGE_ID" --version
