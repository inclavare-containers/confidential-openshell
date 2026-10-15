#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/install-binaries.sh
Install the released Gateway/CLI, the handoff driver and official Kata policy tools.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
need jq curl tar zstd
install -d -m 0700 /var/lib/openshell-confidential/downloads
for release in gateway cli; do
  release_download "$release" "/var/lib/openshell-confidential/downloads/$release.tar.gz"
done
tar --no-same-owner -xzf /var/lib/openshell-confidential/downloads/gateway.tar.gz \
  -C /usr/local/bin openshell-gateway
tar --no-same-owner -xzf /var/lib/openshell-confidential/downloads/cli.tar.gz \
  -C /usr/local/bin openshell
chmod 0755 /usr/local/bin/openshell-gateway /usr/local/bin/openshell
chown root:root /usr/local/bin/openshell-gateway /usr/local/bin/openshell
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
install -m 0755 "$HANDOFF/outputs/openshell-driver-confidential-kubernetes" \
  /usr/local/bin/openshell-driver-confidential-kubernetes
/usr/local/bin/openshell-driver-confidential-kubernetes --version
DOWNLOADS=/var/lib/openshell-confidential/downloads
POLICY_TOOLS=/opt/openshell/kata-policy
release_download kata_tools "$DOWNLOADS/kata-tools.tar.zst"
zstd -dc "$DOWNLOADS/kata-tools.tar.zst" > "$DOWNLOADS/kata-tools.tar"
install -d -m 0755 "$POLICY_TOOLS"
for name in genpolicy rules.rego genpolicy-settings.json; do
  if [[ "$name" == genpolicy ]]; then path=./opt/kata/bin/$name; else path=./opt/kata/share/defaults/kata-containers/$name; fi
  tar -xOf "$DOWNLOADS/kata-tools.tar" "$path" > "$POLICY_TOOLS/$name"
done
rm "$DOWNLOADS/kata-tools.tar"
chmod 0755 "$POLICY_TOOLS/genpolicy"
chmod 0644 "$POLICY_TOOLS/rules.rego" "$POLICY_TOOLS/genpolicy-settings.json"
python3 - "$POLICY_TOOLS" <<'PYTOOLS'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("agent_policy", "deployment/runtime/agent_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
policy._checked_tools(pathlib.Path(sys.argv[1]))
PYTOOLS
