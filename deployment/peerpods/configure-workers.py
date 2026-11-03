#!/usr/bin/env python3
"""Configure and verify selected ACK workers through ECS Cloud Assistant."""
import argparse
import base64
import json
import re
import shlex

from workers import execute, selected
from cloud import Cloud, OPERATOR, ROOT, require, run


def main():
    argparse.ArgumentParser(prog='./cos workers configure', description=__doc__).parse_args()
    cloud = Cloud()
    pause = (OPERATOR / 'pause-image.txt').read_text().strip()
    shim = (OPERATOR / 'shim.sha256').read_text().split()[0]
    require(re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', pause) and re.fullmatch(r'[0-9a-f]{64}', shim),
            'Publish the verified release first: ./cos registry publish.')
    source = (ROOT / 'deployment/peerpods/worker-profile.py').read_bytes()
    runtime_version = json.loads((ROOT / 'deployment/ack/ack.example.json').read_text())['containerd_version']
    command = '\n'.join([
        '#!/bin/bash', 'set -euo pipefail',
        'printf %s ' + shlex.quote(base64.b64encode(source).decode()) + ' | base64 -d | python3 - ' + shlex.quote(pause) + ' ' + shlex.quote(shim) + ' ' + shlex.quote(runtime_version),
        '',
    ])
    for name, instance in selected(cloud):
        execute(cloud, instance, command, 'Kata profile configuration and verification', timeout=300)
        run(['kubectl', 'wait', '--for=condition=Ready', 'node/' + name, '--timeout=180s'])
        config = json.loads(run(['kubectl', '--request-timeout=30s', 'get', '--raw',
                                 '/api/v1/nodes/' + name + '/proxy/configz'], capture_output=True).stdout)
        require(config['kubeletconfig']['runtimeRequestTimeout'] == '10m0s',
                f'Worker {name} has not applied the 600-second kubelet runtime request timeout.')
        print(f'{name}: effective kubelet runtime request timeout is 600 seconds.', flush=True)
    runtime = json.loads(run(['kubectl', 'get', 'runtimeclass', 'kata-remote', '-o', 'json'], capture_output=True).stdout)
    require(runtime['handler'] == 'kata-remote' and
            runtime.get('overhead', {}).get('podFixed') == {'cpu': '250m', 'memory': '120Mi'},
            'kata-remote RuntimeClass must use the remote handler with cpu=250m and memory=120Mi overhead.')
    run(['kubectl', 'label', 'runtimeclass', 'kata-remote', 'openshell.ai/sandbox-attachable=true', '--overwrite'])
    print('Selected worker profiles verified; kata-remote is attachable. Repeat after kata-deploy upgrades or adding workers.', flush=True)


if __name__ == '__main__':
    main()
