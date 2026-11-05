#!/usr/bin/env python3
"""Offline CSI handoff test: the T subprocess receives only a bundle and test tools."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

COMPONENT = 'caa-csi-block-driver'
ARCHIVE = 'charts/caa-csi-block-driver.tgz'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def consume(bundle, expected_checksums):
    require(shutil.which('git') is None, 'simulated T must not have Git')
    source = Path(__file__).resolve().parent / 'source'
    spec = importlib.util.spec_from_file_location('install_release', source / 'deployment/build/install-release.py')
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    installed = bundle.parent / 'installed-handoff'
    release.copy_handoff(bundle, installed, expected_checksums)
    operator = bundle.parent / 'operator'
    operator.mkdir()
    subprocess.run(['bash', str(source / 'deployment/peerpods/verify-csi-chart.sh')],
                   env={**os.environ, 'HANDOFF': str(installed), 'OPERATOR_DIR': str(operator)},
                   stdout=subprocess.PIPE, check=True, text=True)
    rendered = subprocess.check_output([
        'helm', 'template', 'caa-csi-block', str(installed / ARCHIVE),
        '--namespace', 'confidential-containers-system',
        '--values', str(installed / 'csi-values.yaml')], text=True)
    (bundle / 'rendered.yaml').write_text(rendered)
    resources = [document for document in yaml.safe_load_all(rendered) if document is not None]
    assert_resources(resources)
    provenance = json.loads((operator / 'csi-chart-source.json').read_text())
    print(json.dumps({'result': 'passed', 'resources': len(resources), 'source': provenance,
                      'chart_sha256': sha256(installed / ARCHIVE),
                      'rendered_sha256': sha256(bundle / 'rendered.yaml')}, sort_keys=True))


def assert_resources(resources):
    def one(kind, name):
        matches = [r for r in resources if r['kind'] == kind and r['metadata']['name'] == name]
        require(len(matches) == 1, f'expected one {kind}/{name}, got {len(matches)}')
        return matches[0]
    node = one('DaemonSet', 'caa-csi-block')
    storage = one('StorageClass', 'alicloud-disk-essd-peerpod')
    require(not any(r['kind'] in ('Deployment', 'PersistentVolumeClaim') for r in resources),
            'combined CSI must not require a controller Deployment or state PVC')
    require(node['metadata']['namespace'] == 'caa-csi-block', 'wrong CSI resource namespace')
    node_pod = node['spec']['template']['spec']
    containers = {c['name']: c for c in node_pod['containers']}
    require(set(containers) == {'csi-provisioner', 'node-driver-registrar', 'caa-csi-block-driver'},
            'combined CSI containers changed')
    driver = containers['caa-csi-block-driver']
    require('--nodeid=$(KUBE_NODE_NAME)' in driver['args'], 'node identity missing')
    require(not any(a.startswith('--component=') for a in driver['args']), 'unexpected split service mode')
    require('--leader-election=true' in containers['csi-provisioner']['args'], 'provisioner leader election missing')
    one('CSIDriver', 'caa-csi-block.csi.confidentialcontainers.io')
    binding = one('ClusterRoleBinding', 'caa-csi-block')
    require(binding['subjects'] == [{'kind': 'ServiceAccount', 'name': node_pod['serviceAccountName'], 'namespace': 'caa-csi-block'}],
            'CSI ServiceAccount binding is incorrect')
    volumes = {v['name']: v for v in node_pod['volumes']}
    mounts = {m['name']: m for m in driver['volumeMounts']}
    require(volumes['csi-data']['hostPath']['path'] == '/var/lib/caa-csi-block'
            and mounts['csi-data']['mountPath'] == '/var/lib/caa-csi-block', 'upstream node-local store missing')
    require(not any(m['name'] == 'rrsa-oidc-token' for name, c in containers.items()
                    if name != 'caa-csi-block-driver' for m in c.get('volumeMounts', [])),
            'CSI sidecars must not receive the cloud token')
    env = {e['name']: e.get('value') for e in driver['env']}
    require(env['CSI_CLOUD_PROVIDER'] == 'alibabacloud', 'wrong CSI cloud provider')
    require(env['ALIBABA_CLOUD_ROLE_ARN'] == 'CSI_RAM_ROLE_ARN' and env['ALIBABA_CLOUD_OIDC_PROVIDER_ARN'] == 'ACK_OIDC_PROVIDER_ARN',
            'RRSA role/provider configuration missing')
    require(env['ALIBABA_CLOUD_OIDC_TOKEN_FILE'] == '/var/run/secrets/ack.alibabacloud.com/rrsa-tokens/token', 'wrong RRSA token file')
    token = volumes['rrsa-oidc-token']['projected']['sources']
    require(token == [{'serviceAccountToken': {'audience': 'sts.aliyuncs.com', 'expirationSeconds': 3600, 'path': 'token'}}],
            'RRSA must use projected short-lived audience-bound token')
    require(mounts['rrsa-oidc-token']['readOnly'] is True and mounts['rrsa-oidc-token']['mountPath'] == '/var/run/secrets/ack.alibabacloud.com/rrsa-tokens',
            'RRSA token mount missing')
    require(not any('ACCESS_KEY' in key for key in env), 'static cloud credentials must not accompany RRSA')
    require(storage['provisioner'] == 'caa-csi-block.csi.confidentialcontainers.io' and storage['allowVolumeExpansion'] is False
            and storage['volumeBindingMode'] == 'Immediate' and storage['reclaimPolicy'] == 'Delete', 'incorrect PeerPod StorageClass semantics')
    expected = {'cloudProvider': 'alibabacloud', 'region': 'REGION', 'zoneId': 'ZONE', 'clusterId': 'ACK_CLUSTER_ID'}
    require(storage['parameters'] == expected, 'Alibaba storage parameters missing or changed')
    config = one('ConfigMap', volumes['bootstrap-params']['configMap']['name'])
    bootstrap = json.loads(config['data']['bootstrap-params.json'])
    require(all(bootstrap[k] == value for k, value in expected.items()), 'bootstrap Alibaba configuration mismatch')
    require(env['CSI_BOOTSTRAP_PARAMS_FILE'] == '/etc/caa-csi-block/bootstrap-params.json'
            and mounts['bootstrap-params']['mountPath'] == '/etc/caa-csi-block' and mounts['bootstrap-params']['readOnly'],
            'bootstrap configuration is not mounted read-only')


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        temporary = self.root / '.local/test-tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.temp.cleanup)
        self.trusted = Path(self.temp.name)
        self.bundle = self.trusted / 'handoff'
        (self.bundle / 'charts').mkdir(parents=True)
        shutil.copyfile(self.root / 'artifacts' / ARCHIVE, self.bundle / ARCHIVE)
        shutil.copyfile(self.root / 'deployment/peerpods/csi-values.example.yaml', self.bundle / 'csi-values.yaml')
        # Use the real inventory/provenance readers. This is a synthetic handoff
        # inventory, not a claim that a release was built from dirty source.
        spec = importlib.util.spec_from_file_location('manifest', self.root / 'deployment/build/manifest.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source_report = json.loads(subprocess.check_output([sys.executable, str(self.root / 'deployment/build/manifest.py'), '--check-test-sources'], text=True))
        source_report['scope'] = 'synthetic offline chart handoff fixture'
        source_report['artifacts']['csi-chart'] = {'path': 'artifacts/' + ARCHIVE, 'sha256': sha256(self.bundle / ARCHIVE),
            'source': module.csi_chart_provenance(self.bundle / ARCHIVE, source_report['sources'])}
        (self.bundle / 'build-manifest.json').write_text(json.dumps(source_report))
        self.checksums()
        shutil.copyfile(__file__, self.trusted / 'consumer.py')
        for name in ('deployment/build/install-release.py', 'deployment/lib/common.sh',
                     'deployment/peerpods/verify-csi-chart.sh'):
            destination = self.trusted / 'source' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root / name, destination)
        tools = self.trusted / 'tools'
        tools.mkdir()
        for name in ('helm', 'bash', 'dirname', 'sha256sum', 'tar', 'gzip', 'jq'):
            executable = shutil.which(name)
            self.assertIsNotNone(executable, f'{name} is required')
            (tools / name).symlink_to(executable)
        self.env = {**os.environ, 'PATH': str(tools), 'HELM_CACHE_HOME': str(self.trusted / 'helm-cache'),
                    'HELM_CONFIG_HOME': str(self.trusted / 'helm-config'), 'HELM_DATA_HOME': str(self.trusted / 'helm-data'),
                    'HELM_PLUGINS': str(self.trusted / 'no-plugins'), 'KUBECONFIG': str(self.trusted / 'no-kubeconfig')}

    def checksums(self):
        names = [ARCHIVE, 'build-manifest.json', 'csi-values.yaml']
        (self.bundle / 'SHA256SUMS').write_text(''.join(f'{sha256(self.bundle / n)}  {n}\n' for n in names))
        self.approved = sha256(self.bundle / 'SHA256SUMS')

    def run_consumer(self):
        return subprocess.run([sys.executable, str(self.trusted / 'consumer.py'), '--consume', str(self.bundle),
                               '--expected-checksums', self.approved], cwd=self.trusted, env=self.env, text=True, capture_output=True)

    def test_only_delivered_package_renders_required_resources(self):
        result = self.run_consumer()
        self.assertEqual(result.returncode, 0, result.stderr)
        print(result.stdout.strip())
        evidence = self.root / '.local/checks'
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / 'csi-handoff-result.json').write_text(result.stdout)
        shutil.copyfile(self.bundle / 'rendered.yaml', evidence / 'csi-handoff-rendered.yaml')

    def test_missing_package_fails_before_render(self):
        (self.bundle / ARCHIVE).unlink()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No such file', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_changed_package_hash_fails_before_render(self):
        with (self.bundle / ARCHIVE).open('ab') as output:
            output.write(b'corruption')
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum did NOT match', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_wrong_source_tree_fails_even_with_matching_transport_checksums(self):
        path = self.bundle / 'build-manifest.json'
        report = json.loads(path.read_text())
        report['sources'][COMPONENT]['expected_patched_result_tree'] = '0' * 40
        path.write_text(json.dumps(report))
        self.checksums()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('verify-csi-chart.sh', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_upstream_chart_is_rejected_by_resource_assertions_even_if_mislabeled(self):
        # Reproduce the original handoff bug. Deliberately retain the correct
        # provenance label in this negative fixture so metadata alone cannot
        # make a clean upstream chart pass the actual resource assertions.
        payload = subprocess.check_output(['git', '-C', str(self.root / 'repos' / COMPONENT),
                                          'archive', '--format=tar', '--prefix=' + COMPONENT + '/',
                                          'HEAD:charts/caa-csi-block-driver'])
        path = self.bundle / 'build-manifest.json'
        report = json.loads(path.read_text())
        provenance = json.dumps(report['artifacts']['csi-chart']['source']).encode()
        with tarfile.open(self.bundle / ARCHIVE, 'w:gz') as output:
            with tarfile.open(fileobj=io.BytesIO(payload)) as original:
                for member in original.getmembers():
                    output.addfile(member, original.extractfile(member) if member.isfile() else None)
            entry = tarfile.TarInfo(COMPONENT + '/source-provenance.json')
            entry.size = len(provenance)
            output.addfile(entry, io.BytesIO(provenance))
        report['artifacts']['csi-chart']['sha256'] = sha256(self.bundle / ARCHIVE)
        path.write_text(json.dumps(report))
        self.checksums()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('provisioner leader election missing', result.stderr)
        self.assertTrue((self.bundle / 'rendered.yaml').exists(), 'Helm must succeed while the semantic assertion rejects the upstream chart')

    def test_unapproved_checksum_list_fails_before_render(self):
        self.approved = '0' * 64
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Handoff changed while copying', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_unsafe_archive_member_fails_even_with_matching_transport_checksums(self):
        chart = self.bundle / ARCHIVE
        payload = chart.read_bytes()
        with tarfile.open(chart, 'w:gz') as output:
            with tarfile.open(fileobj=io.BytesIO(payload)) as original:
                for member in original.getmembers():
                    output.addfile(member, original.extractfile(member) if member.isfile() else None)
            output.addfile(tarfile.TarInfo(COMPONENT + '/../escape'), io.BytesIO(b''))
        path = self.bundle / 'build-manifest.json'
        report = json.loads(path.read_text())
        report['artifacts']['csi-chart']['sha256'] = sha256(chart)
        path.write_text(json.dumps(report))
        self.checksums()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Error:', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())
        self.assertFalse((self.bundle / 'extracted/escape').exists())


if __name__ == '__main__':
    if '--consume' in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument('--consume', type=Path, required=True)
        parser.add_argument('--expected-checksums', required=True)
        args = parser.parse_args()
        try:
            consume(args.consume, args.expected_checksums)
        except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
            raise SystemExit(str(error)) from error
    else:
        unittest.main(verbosity=2)
