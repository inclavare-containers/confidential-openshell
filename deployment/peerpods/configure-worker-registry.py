#!/usr/bin/env python3
"""Install the registry's public CA on ACK workers and verify an actual CRI pull."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ack'))
from cloud import Cloud, OPERATOR, ROOT, require
from workers import execute, selected

TRUSTEE_CLIENT = Path('/etc/openshell-confidential/trustee-client.json')


def worker_command(registry, ca, image, kbs_url, kbs_ca):
    hosts = (ROOT / 'deployment/peerpods/registry-hosts.example.toml').read_text()
    hosts = hosts.replace('PRIVATE_REGISTRY', registry)
    target = '/etc/containerd/certs.d/' + registry
    return '\n'.join([
        '#!/bin/bash', 'set -euo pipefail',
        'command -v crictl >/dev/null',
        f'install -d -m 0755 {shlex.quote(target)}',
        f"printf '%s' {shlex.quote(base64.b64encode(ca).decode())} | base64 -d > {shlex.quote(target + '/ca.crt')}",
        f"printf '%s' {shlex.quote(base64.b64encode(hosts.encode()).decode())} | base64 -d > {shlex.quote(target + '/hosts.toml')}",
        f'chmod 0644 {shlex.quote(target + "/ca.crt")} {shlex.quote(target + "/hosts.toml")}',
        'install -d -m 0755 /etc/openshell-confidential',
        f"printf '%s' {shlex.quote(base64.b64encode(kbs_ca).decode())} | base64 -d > /etc/openshell-confidential/kbs-ca.pem",
        'chmod 0644 /etc/openshell-confidential/kbs-ca.pem',
        'crictl --runtime-endpoint unix:///run/containerd/containerd.sock '
        '--image-endpoint unix:///run/containerd/containerd.sock pull ' + shlex.quote(image),
        'code=$(curl --noproxy "*" --cacert /etc/openshell-confidential/kbs-ca.pem' +
        ' --connect-timeout 10 --max-time 20 -sS -o /dev/null -w "%{http_code}" ' +
        shlex.quote(kbs_url.rstrip('/') + '/kbs/v0/resource/default/bootstrap/anonymous-check') + ')',
        '[[ $code == 401 || $code == 403 ]] || { echo "Worker KBS reachability/anonymous denial failed: HTTP $code" >&2; exit 1; }',
        'printf "Worker KBS HTTPS reachable; anonymous access denied (HTTP %s).\\n" "$code"',
        '',
    ])


def main():
    argparse.ArgumentParser(prog='./cos workers registry', description=__doc__).parse_args()
    cloud = Cloud()
    require(cloud.state.get('cluster_id'), 'Run prepare-cluster.py first.')
    require(os.environ.get('HOST_IP'), 'Set the trusted service address first: ./cos deploy configure.')
    address = ipaddress.IPv4Address(os.environ['HOST_IP'])
    registry = os.environ.get('REGISTRY_ADDR', str(address) + ':5000')
    ca = Path(os.environ.get('REGISTRY_CA', '/etc/trustee/tls/ca.pem')).read_bytes()
    require(b'-----BEGIN CERTIFICATE-----' in ca and b'PRIVATE KEY' not in ca,
            'Use the public registry CA certificate, without private keys.')
    trustee = json.loads(TRUSTEE_CLIENT.read_text())
    kbs_ca = Path(trustee['ca_cert']).read_bytes()
    require(b'-----BEGIN CERTIFICATE-----' in kbs_ca and b'PRIVATE KEY' not in kbs_ca,
            'Use the public KBS CA certificate, without private keys.')
    record = OPERATOR / 'pause-image.txt'
    require(record.is_file(), 'Run bash deployment/peerpods/publish-images.sh first.')
    image = record.read_text().strip()
    require(image.startswith(registry + '/') and re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image),
            'pause-image.txt must contain the published private registry image digest.')
    command = worker_command(registry, ca, image, trustee['kbs_url'], kbs_ca)
    for node, instance in selected(cloud):
        execute(cloud, instance, command, 'Registry trust and CRI pull', timeout=120)
        print(f'Registry trust and CRI image pull ready: {node}')


if __name__ == '__main__':
    main()
