#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/fetch-prerequisites.sh
Fetch the pinned cluster dependencies and configure their published image mirrors.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need jq curl python3
install -d -m 0700 "$OPERATOR_DIR"
for item in agent_sandbox_manifest cert_manager_chart; do
  release_download "$item" "$OPERATOR_DIR/$item"
done
python3 - "$OPERATOR_DIR" <<'PY'
import json, pathlib, re, sys, yaml
directory = pathlib.Path(sys.argv[1])
def image(name):
    value = (directory / f'{name}-image.txt').read_text().strip()
    assert re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', value), name
    return value
documents = [d for d in yaml.safe_load_all((directory / 'agent_sandbox_manifest').read_text()) if d is not None]
controllers = [d for d in documents if d.get('kind') == 'Deployment' and
               d['metadata']['name'] == 'agent-sandbox-controller']
assert len(controllers) == 1
containers = controllers[0]['spec']['template']['spec']['containers']
assert len(containers) == 1
containers[0]['image'] = image('agent_sandbox_controller')
(directory / 'agent-sandbox-pinned.yaml').write_text(yaml.safe_dump_all(documents, sort_keys=False))
values = json.loads(pathlib.Path('deployment/peerpods/cert-manager-values.json').read_text())
for name, key in [('controller', None), ('webhook', 'webhook'),
                  ('cainjector', 'cainjector'), ('startup', 'startupapicheck')]:
    repository, digest = image(f'cert_manager_{name}').split('@')
    target = values if key is None else values[key]
    target['image'] = {'repository': repository, 'digest': digest}
(directory / 'cert-manager-values.json').write_text(json.dumps(values, indent=2) + '\n')
PY
printf 'Cluster dependencies ready in %s\n' "$OPERATOR_DIR"
