"""Exercise user-facing step execution, worker selection and configuration preservation."""
from copy import deepcopy
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deployment/peerpods'))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = load('operator_cli', 'deployment/cli.py')
selection = load('operator_workers', 'deployment/peerpods/select-workers.py')
profile = load('worker_profile', 'deployment/peerpods/worker-profile.py')


class PublicSteps(unittest.TestCase):
    def test_help_does_not_execute_a_build_or_installation(self):
        with patch.object(cli, 'STEPS', {'build test': ('Run tests', 'must-not-run.sh', [], None)}), \
                patch.object(cli.subprocess, 'call', side_effect=AssertionError('help must not execute a shell recipe')):
            self.assertEqual(cli.run_step('build test', ['--help']), 0)

    def test_failed_substep_streams_diagnostic_and_never_reports_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / 'step.py'
            script.write_text('import sys\nprint("registry upload failed",flush=True)\nsys.exit(7)\n')
            steps = {'registry publish': ('Publish images', 'step.py', [], 'workers registry')}
            with patch.object(cli, 'ROOT', root), patch.object(cli, 'OPERATOR', root / 'operator'), \
                    patch.object(cli, 'STEPS', steps):
                code = cli.run_step('registry publish', [])
            self.assertEqual(code, 7)
            result = json.loads((root / 'operator/steps.json').read_text())['registry publish']
            self.assertEqual(result['status'], 'FAILED')
            self.assertIn('registry upload failed', Path(result['log']).read_text())

    def test_new_command_loads_saved_address_profile_and_kubeconfig(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            operator = root / 'operator'
            operator.mkdir()
            (operator / 'operator.json').write_text(json.dumps({'host_ip': '203.0.113.9', 'profile': 'operator'}))
            with patch.object(cli, 'ROOT', root), patch.object(cli, 'OPERATOR', operator), patch.dict(os.environ, {'HOST_IP': '192.0.2.1'}):
                env = cli.environment()
            self.assertEqual(env['HOST_IP'], '203.0.113.9')
            self.assertEqual(env['ALIBABA_CLOUD_PROFILE'], 'operator')
            self.assertEqual(env['KUBECONFIG'], str(operator / 'administrator-kubeconfig'))


class WorkerSelection(unittest.TestCase):
    @staticmethod
    def node(name, ready=True, labels=None):
        return {'metadata': {'name': name, 'labels': labels or {}},
                'status': {'nodeInfo': {'operatingSystem': 'linux', 'architecture': 'amd64'},
                           'conditions': [{'type': 'Ready', 'status': 'True' if ready else 'False'}]}}

    def test_shared_cluster_requires_choice_and_excludes_control_plane_and_unready_nodes(self):
        nodes = [self.node('worker-a'), self.node('worker-b'), self.node('starting', False),
                 self.node('control-plane', labels={'node-role.kubernetes.io/control-plane': ''})]
        prompts = []
        def choose(prompt):
            prompts.append(prompt)
            return '2'
        self.assertEqual(selection.choose(nodes, False, None, None, prompt=choose), ['worker-b'])
        self.assertEqual(len(prompts), 1)
        with self.assertRaises(SystemExit):
            selection.choose(nodes, False, ['starting'], None)

    def test_owned_new_cluster_and_single_worker_do_not_need_names_or_input(self):
        def no_prompt(_):
            self.fail('A new or single-worker cluster should be discovered automatically')
        nodes = [self.node('worker-a'), self.node('worker-b')]
        self.assertEqual(selection.choose(nodes, True, None, None, prompt=no_prompt), ['worker-a', 'worker-b'])
        self.assertEqual(selection.choose(nodes[:1], False, None, None, prompt=no_prompt), ['worker-a'])


class WorkerProfile(unittest.TestCase):
    def test_kubelet_deadline_preserves_other_arguments_and_environment(self):
        for value in ('"--max-pods=110 --runtime-request-timeout=2m --v=3"',
                      '--max-pods=110 --runtime-request-timeout 2m --v=3'):
            original = '# ACK custom options\nOTHER="keep this"\nKUBELET_CUSTOMIZED_ARGS=' + value + '\n'
            merged = profile.kubelet_timeout(original)
            self.assertTrue(merged.startswith('# ACK custom options\nOTHER="keep this"\n'))
            assignment = merged.split('KUBELET_CUSTOMIZED_ARGS=', 1)[1].strip()
            self.assertEqual(profile.shlex.split(json.loads(assignment)),
                             ['--max-pods=110', '--v=3', '--runtime-request-timeout=600s'])
            self.assertEqual(profile.kubelet_timeout(merged), merged)

    def test_kubelet_deadline_handles_empty_configuration_and_quoted_arguments(self):
        merged = profile.kubelet_timeout('')
        self.assertEqual(profile.kubelet_timeout(merged), merged)
        arguments = "--resolv-conf='/etc/custom directory/resolv.conf'"
        merged = profile.kubelet_timeout('KUBELET_CUSTOMIZED_ARGS=' + json.dumps(arguments) + '\n')
        self.assertEqual(profile.shlex.split(json.loads(merged.split('=', 1)[1])),
                         ['--resolv-conf=/etc/custom directory/resolv.conf', '--runtime-request-timeout=600s'])

    def test_invalid_custom_arguments_stop_before_any_write(self):
        with self.assertRaises(SystemExit):
            profile.kubelet_timeout('KUBELET_CUSTOMIZED_ARGS="unterminated\n')
        with self.assertRaises(SystemExit):
            profile.kubelet_timeout('KUBELET_CUSTOMIZED_ARGS="--runtime-request-timeout"\n')

    def test_new_custom_arguments_file_is_private_and_repeatable(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'kubelet-customized-args.conf'
            text = profile.kubelet_timeout('')
            self.assertTrue(profile.replace(path, text))
            self.assertFalse(profile.replace(path, text))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_merge_preserves_unrelated_containerd_settings_and_is_idempotent(self):
        original = '''version = 3
imports = ["/etc/containerd/conf.d/*.toml"]
[plugins.'io.containerd.cri.v1.images'.registry]
config_path = "/etc/containerd/cert.d:/etc/containerd/certs.d"
[plugins.'io.containerd.cri.v1.images'.pinned_images]
sandbox = "original/pause:3.9" # old image
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
runtime_type = "io.containerd.runc.v2"
'''
        changes = [(('plugins', 'io.containerd.cri.v1.images', 'pinned_images'), 'sandbox', 'private/pause@sha256:abcd')]
        merged = profile.merge(original, changes)
        expected = deepcopy(tomllib.loads(original))
        expected['plugins']['io.containerd.cri.v1.images']['pinned_images']['sandbox'] = 'private/pause@sha256:abcd'
        self.assertEqual(tomllib.loads(merged), expected)
        self.assertEqual(profile.merge(merged, changes), merged)

    def test_kata_merge_adds_missing_sections_and_retains_existing_values(self):
        original = '# upstream profile\n[hypervisor.remote]\nsocket = "/run/peerpod/hypervisor.sock"\n'
        changes = [(('hypervisor', 'remote'), 'shared_fs', 'none'),
                   (('runtime',), 'experimental_force_guest_pull', True),
                   (('runtime',), 'create_container_timeout', 600)]
        merged = profile.merge(original, changes)
        result = tomllib.loads(merged)
        self.assertEqual(result['hypervisor']['remote']['socket'], '/run/peerpod/hypervisor.sock')
        self.assertEqual(result['runtime'], {'experimental_force_guest_pull': True, 'create_container_timeout': 600})
        self.assertEqual(profile.merge(merged, changes), merged)

    def test_repeated_write_preserves_the_first_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'configuration-remote.toml'
            path.write_text('first')
            path.chmod(0o640)
            self.assertTrue(profile.replace(path, 'second'))
            self.assertFalse(profile.replace(path, 'second'))
            self.assertTrue(profile.replace(path, 'third'))
            self.assertEqual(path.with_name(path.name + '.before-openshell').read_text(), 'first')
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)


@unittest.skipUnless(os.geteuid() == 0, 'Release installation requires root, as documented')
class ReleaseInstallation(unittest.TestCase):
    def make_handoff(self, root, broken=False):
        source = root / 'handoff'
        (source / 'source').mkdir(parents=True, exist_ok=True)
        (source / 'outputs').mkdir(exist_ok=True)
        for name in ('integration', 'openshell', 'cloud-api-adaptor', 'caa-csi-block-driver'):
            path = source / 'source' / (name + '.tar')
            with tarfile.open(path, 'w') as archive:
                data = b'public source fixture'
                entry = tarfile.TarInfo('README')
                entry.mode, entry.size = 0o644, len(data)
                archive.addfile(entry, io.BytesIO(data))
            if broken and name == 'cloud-api-adaptor':
                path.write_bytes(b'broken archive with a valid handoff checksum')
        (source / 'outputs/containerd-shim-kata-v2').write_bytes(b'public shim fixture')
        contents = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(source)) + '\n'
                           for p in sorted(source.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS')
        (source / 'SHA256SUMS').write_text(contents)
        return source, hashlib.sha256(contents.encode()).hexdigest()

    def unpack(self, root, broken=False):
        source, checksum = self.make_handoff(root, broken=broken)
        destination = root / 'installed'
        result = subprocess.run(['bash', str(ROOT / 'deployment/build/unpack-release.sh'),
                                 str(source), checksum, str(destination)],
                                env={**os.environ, 'OPERATOR_DIR': str(root / 'operator')},
                                capture_output=True, text=True)
        return result, destination

    def test_failed_extraction_leaves_no_installation_and_the_step_can_be_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failure, destination = self.unpack(root, broken=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob('.confidential-openshell.*')), [])
            success, destination = self.unpack(root)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual((destination / 'README').read_bytes(), b'public source fixture')
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            self.assertTrue((root / 'operator/shim.sha256').is_file())

    def test_existing_deployment_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / 'installed'
            destination.mkdir()
            (destination / 'keep').write_text('existing deployment')
            result, _ = self.unpack(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((destination / 'keep').read_text(), 'existing deployment')
            self.assertFalse((root / 'operator').exists())


if __name__ == '__main__':
    unittest.main()
