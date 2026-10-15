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

COMPONENT = 'caa-csi-block-driver'
ARCHIVE = 'charts/caa-csi-block-driver.tgz'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def consume(bundle, expected_checksums):
    """No checkout/Git/B path is read here; all data inputs are inside bundle."""
    require(shutil.which('git') is None, 'simulated T must not have Git')
    checksums = bundle / 'SHA256SUMS'
    require(sha256(checksums) == expected_checksums, 'handoff checksum-list identity mismatch')
    verified = set()
    for line in checksums.read_text().splitlines():
        expected, name = line.split('  ', 1)
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name
                and name not in verified, 'unsafe or duplicate handoff path')
        path = bundle / relative
        require(path.is_file(), f'missing handoff file: {name}')
        require(not any(p.is_symlink() for p in [path, *path.parents]) and path.stat().st_nlink == 1,
                'handoff files must not contain symlinks or hardlinks')
        require(sha256(path) == expected, f'handoff hash mismatch: {name}')
        verified.add(name)
    require({ARCHIVE, 'build-manifest.json', 'csi-values.yaml'} <= verified, 'incomplete handoff checksum list')
    manifest = json.loads((bundle / 'build-manifest.json').read_text())
    source = manifest['sources'][COMPONENT]
    require(source['upstream_checkout'] == source['patch_check'] == 'verified', 'unverified CSI source')
    artifact = manifest['artifacts']['csi-chart']
    require(artifact['path'] == 'artifacts/' + ARCHIVE, 'unexpected CSI artifact path')
    require(sha256(bundle / ARCHIVE) == artifact['sha256'], 'CSI manifest hash mismatch')
    extracted = bundle / 'extracted'
    extracted.mkdir()
    seen = set()
    with tarfile.open(bundle / ARCHIVE, 'r:gz') as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts
                    and path.parts[0] == COMPONENT and path.as_posix() == member.name and member.name not in seen,
                    'unsafe or duplicate chart member path')
            require(member.isfile() or member.isdir(), 'chart must not contain links or devices')
            seen.add(member.name)
            target = extracted / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
    provenance = json.loads((extracted / COMPONENT / 'source-provenance.json').read_text())
    require(provenance == artifact['source'], 'packaged CSI provenance differs from manifest')
    require(provenance['patched_result_tree'] == source['expected_patched_result_tree'] == source['observed_patched_result_tree'],
            'CSI patched result tree mismatch')
    require(provenance['source_upstream_commit'] == source['source_upstream_commit'] == source['observed_patch_base_commit'],
            'CSI upstream commit mismatch')
    args = ['helm', 'template', 'caa-csi-block', '--namespace', 'confidential-containers-system',
            '--values', str(bundle / 'csi-values.yaml')]
    # T installs the archive directly. Also render its extracted tree to prove
    # that the package is self-contained and the two forms have identical resources.
    rendered = subprocess.check_output([*args, str(bundle / ARCHIVE)], text=True)
    unpacked = subprocess.check_output([*args, str(extracted / COMPONENT)], text=True)
    require(rendered == unpacked, 'archive and extracted chart renders differ')
    (bundle / 'rendered.yaml').write_text(rendered)
    documents = subprocess.check_output(['yq', 'eval', '-o=json', '-I=0', '.', '-'], input=rendered, text=True)
    resources = [json.loads(line) for line in documents.splitlines() if line.strip() and line != 'null']
    assert_resources(resources)
    print(json.dumps({'result': 'passed', 'resources': len(resources), 'source': provenance,
                      'chart_sha256': artifact['sha256'], 'rendered_sha256': sha256(bundle / 'rendered.yaml')}, sort_keys=True))


def assert_resources(resources):
    def one(kind, name):
        matches = [r for r in resources if r['kind'] == kind and r['metadata']['name'] == name]
        require(len(matches) == 1, f'expected one {kind}/{name}, got {len(matches)}')
        return matches[0]
    controller = one('Deployment', 'caa-csi-block-controller')
    node = one('DaemonSet', 'caa-csi-block')
    pvc = one('PersistentVolumeClaim', 'caa-csi-block-controller-state')
    storage = one('StorageClass', 'alicloud-disk-essd-peerpod')
    require(sum(r['kind'] == 'Deployment' for r in resources) == 1, 'unexpected extra CSI deployment')
    require(controller['spec']['replicas'] == 1 and controller['spec']['strategy']['type'] == 'Recreate',
            'controller must be single-replica/Recreate')
    for resource in [controller, node, pvc]:
        require(resource['metadata']['namespace'] == 'caa-csi-block', 'wrong CSI resource namespace')
    require(pvc['metadata']['annotations']['helm.sh/resource-policy'] == 'keep', 'controller PVC must survive Helm uninstall')
    require(pvc['spec']['accessModes'] == ['ReadWriteOnce'] and pvc['spec']['storageClassName'] == 'ACK_HOST_ESSD_STORAGE_CLASS'
            and pvc['spec']['resources']['requests']['storage'] == '20Gi', 'incorrect durable controller storage')
    control_pod = controller['spec']['template']['spec']
    node_pod = node['spec']['template']['spec']
    control = {c['name']: c for c in control_pod['containers']}
    nodes = {c['name']: c for c in node_pod['containers']}
    require(set(control) == {'csi-provisioner', 'caa-csi-block-controller'}, 'controller sidecar split changed')
    require(set(nodes) == {'node-driver-registrar', 'caa-csi-block-driver'}, 'node must not run provisioner/controller')
    driver = control['caa-csi-block-controller']
    require('--component=controller' in driver['args'] and '--volume-store-dir=/var/lib/caa-csi-block/volumes' in driver['args'],
            'controller is not using durable journal mode')
    require('--leader-election=true' in control['csi-provisioner']['args'], 'provisioner leader election missing')
    require('--component=node' in nodes['caa-csi-block-driver']['args'] and '--nodeid=$(KUBE_NODE_NAME)' in nodes['caa-csi-block-driver']['args'],
            'node mode/identity missing')
    require(node_pod['automountServiceAccountToken'] is False, 'node token automount must stay disabled')
    require(control_pod['serviceAccountName'] != node_pod['serviceAccountName'], 'controller/node service accounts must differ')
    node_sa = one('ServiceAccount', node_pod['serviceAccountName'])
    require(node_sa['automountServiceAccountToken'] is False, 'node ServiceAccount token automount enabled')
    binding = one('ClusterRoleBinding', 'caa-csi-block')
    require(binding['subjects'] == [{'kind': 'ServiceAccount', 'name': control_pod['serviceAccountName'], 'namespace': 'caa-csi-block'}],
            'controller privileges must not be granted to node')
    volumes = {v['name']: v for v in control_pod['volumes']}
    mounts = {m['name']: m for m in driver['volumeMounts']}
    require(volumes['controller-state'] == {'name': 'controller-state', 'persistentVolumeClaim': {'claimName': pvc['metadata']['name']}},
            'controller journal must use the durable PVC, not emptyDir/hostPath')
    require(mounts['controller-state']['mountPath'] == '/var/lib/caa-csi-block', 'durable journal mount missing')
    require(all('hostPath' not in v for v in control_pod['volumes']), 'controller must not mount worker host paths')
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
    serialized_node = json.dumps(node_pod)
    require(all(value not in serialized_node for value in ['ALIBABA_CLOUD_', 'rrsa-oidc-token', 'controller-state', 'bootstrap-params']),
            'controller credentials/state leaked into node spec')
    require(storage['provisioner'] == 'caa-csi-block.csi.confidentialcontainers.io' and storage['allowVolumeExpansion'] is False
            and storage['volumeBindingMode'] == 'Immediate' and storage['reclaimPolicy'] == 'Delete', 'incorrect PeerPod StorageClass semantics')
    expected = {'cloudProvider': 'alibabacloud', 'region': 'REGION', 'zoneId': 'ZONE', 'clusterId': 'ACK_CLUSTER_ID',
                'diskCategory': 'cloud_essd', 'performanceLevel': 'PL0'}
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
        tools = self.trusted / 'tools'
        tools.mkdir()
        for tool in ['helm', 'yq']:
            executable = shutil.which(tool)
            self.assertIsNotNone(executable, f'existing trusted {tool} is required')
            (tools / tool).symlink_to(executable)
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
        self.assertIn('missing handoff file', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_changed_package_hash_fails_before_render(self):
        with (self.bundle / ARCHIVE).open('ab') as output:
            output.write(b'corruption')
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('handoff hash mismatch', result.stderr)
        self.assertFalse((self.bundle / 'rendered.yaml').exists())

    def test_wrong_source_tree_fails_even_with_matching_transport_checksums(self):
        path = self.bundle / 'build-manifest.json'
        report = json.loads(path.read_text())
        report['sources'][COMPONENT]['expected_patched_result_tree'] = '0' * 40
        path.write_text(json.dumps(report))
        self.checksums()
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CSI patched result tree mismatch', result.stderr)
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
        self.assertIn('expected one Deployment/caa-csi-block-controller, got 0', result.stderr)
        self.assertTrue((self.bundle / 'rendered.yaml').exists(), 'Helm must succeed while the semantic assertion rejects the upstream chart')

    def test_unapproved_checksum_list_fails_before_render(self):
        self.approved = '0' * 64
        result = self.run_consumer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('handoff checksum-list identity mismatch', result.stderr)
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
        self.assertIn('unsafe or duplicate chart member path', result.stderr)
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
