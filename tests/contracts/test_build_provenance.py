"""Public-output boundary and independent object storage regressions."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_manifest', ROOT / 'deployment/build/manifest.py')
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        local_tmp = ROOT / '.local/test-tmp'
        local_tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=local_tmp)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.override = patch.object(manifest, 'ROOT', self.root)
        self.override.start()
        self.addCleanup(self.override.stop)
        (self.root / 'artifacts').mkdir()

    def put(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic public test bytes')
        return path

    def test_approved_artifact_and_absolute_path(self):
        path = self.put('artifacts/openshell-driver-confidential-kubernetes')
        self.assertEqual(manifest.artifact_path('driver', str(path)), path)
        self.assertEqual(manifest.artifact_path('driver', str(path.relative_to(self.root))), path)
        chart = self.put('artifacts/charts/caa-csi-block-driver.tgz')
        self.assertEqual(manifest.artifact_path('csi-chart', str(chart)), chart)

    def test_real_private_paths_traversal_and_escape_rejected_before_hash(self):
        paths = [self.put('state/private.key'), self.put('artifacts/state/private.key'),
                 self.put('artifacts/build-work/private.key'), self.put('artifacts/private.key')]
        public = self.put('artifacts/openshell-driver-confidential-kubernetes')
        paths += [self.root / 'artifacts/../artifacts' / public.name]
        with patch.object(manifest, 'digest', side_effect=AssertionError('must not read rejected bytes')):
            for path in paths:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    manifest.artifact_path('driver', str(path))

    def test_parent_symlink_inside_and_outside_output_domain(self):
        for target_name in ['artifacts/real-guest', 'private-guest']:
            with self.subTest(target=target_name):
                target = self.put(f'{target_name}/openshell-guest-0123456789ab.qcow2').parent
                link = self.root / 'artifacts/guest'
                link.symlink_to(target, target_is_directory=True)
                with self.assertRaises(ValueError):
                    manifest.artifact_path('guest-image', str(link / 'openshell-guest-0123456789ab.qcow2'))
                link.unlink()

    def test_output_root_symlink_and_hardlink_rejected(self):
        (self.root / 'artifacts').rmdir()
        target = self.put('other/openshell-driver-confidential-kubernetes').parent
        (self.root / 'artifacts').symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            manifest.artifact_path('driver', 'artifacts/openshell-driver-confidential-kubernetes')
        (self.root / 'artifacts').unlink()
        (self.root / 'artifacts').mkdir()
        os.link(target / 'openshell-driver-confidential-kubernetes', self.root / 'artifacts/openshell-driver-confidential-kubernetes')
        with self.assertRaises(ValueError):
            manifest.artifact_path('driver', 'artifacts/openshell-driver-confidential-kubernetes')

    def test_missing_checkout_is_explicit(self):
        (self.root / 'repos/openshell').mkdir(parents=True)
        self.assertEqual(manifest.inventory({'openshell': {'base': '0' * 40}})['openshell']['upstream_checkout'], 'not_present')

    def test_source_alias_cannot_escape_repositories(self):
        with self.assertRaises(ValueError):
            manifest.inventory({'peerpod-ctrl': {'source': '../private', 'base': '0' * 40}})

    def test_source_only_refuses_outputs(self):
        with patch('sys.argv', ['manifest.py', '--artifact', 'driver=artifacts/private.key']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                manifest.main()
            self.assertEqual(error.exception.code, 2)

    def test_release_requires_initialized_sources(self):
        self.put('artifacts/openshell-driver-confidential-kubernetes')
        lock = self.root / 'deployment/build/sources.lock.json'
        lock.parent.mkdir(parents=True)
        lock.write_text(json.dumps({'openshell': {'base': '0' * 40}}))
        with patch('sys.argv', ['manifest.py', '--profile', 'release', '--artifact', 'driver=artifacts/openshell-driver-confidential-kubernetes']), patch.object(manifest, 'git', return_value=''):
            with contextlib.redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                manifest.main()
            self.assertIn('missing or mismatched upstream', output.getvalue())

    def test_release_refuses_missing_selected_patch_input(self):
        self.put('artifacts/containerd-shim-kata-v2')
        lock = self.root / 'deployment/build/sources.lock.json'
        lock.parent.mkdir(parents=True)
        lock.write_text('{}')
        observed = {name: {'upstream_checkout': 'verified'} for name in
                    ['openshell', 'cloud-api-adaptor', 'caa-csi-block-driver']}
        observed['kata-containers'] = {'patch_check': 'not_present'}
        with patch('sys.argv', ['manifest.py', '--profile', 'release', '--artifact', 'kata-shim=artifacts/containerd-shim-kata-v2']), patch.object(manifest, 'git', return_value=''), patch.object(manifest, 'inventory', return_value=observed):
            with contextlib.redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                manifest.main()
            self.assertIn('missing or mismatched patched input', output.getvalue())

    def test_controller_output_requires_its_generic_patch_tree(self):
        self.put('artifacts/images/peerpod-controller.tar')
        lock = self.root / 'deployment/build/sources.lock.json'
        lock.parent.mkdir(parents=True)
        lock.write_text('{}')
        observed = {name: {'upstream_checkout': 'verified'} for name in
                    ['openshell', 'cloud-api-adaptor', 'caa-csi-block-driver']}
        observed['peerpod-ctrl'] = {'patch_check': 'not_present'}
        with patch('sys.argv', ['manifest.py', '--profile', 'release', '--artifact', 'peerpod-controller-image-archive=artifacts/images/peerpod-controller.tar']), patch.object(manifest, 'git', return_value=''), patch.object(manifest, 'inventory', return_value=observed):
            with contextlib.redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                manifest.main()
            self.assertIn('missing or mismatched patched input: peerpod-ctrl', output.getvalue())

    def test_clone_dissociates_from_inherited_alternates(self):
        def run(*args):
            return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
        origin = self.root / 'object-origin'
        run('git', 'init', '-q', str(origin))
        self.put('object-origin/file')
        run('git', '-C', str(origin), 'add', 'file')
        run('git', '-C', str(origin), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        base = run('git', '-C', str(origin), 'rev-parse', 'HEAD')
        tree = run('git', '-C', str(origin), 'rev-parse', 'HEAD^{tree}')
        source = self.root / 'repos/cloud-api-adaptor'
        run('git', 'clone', '--shared', str(origin), str(source))
        self.assertTrue((source / '.git/objects/info/alternates').exists())
        build = self.root / 'deployment/build'
        build.mkdir(parents=True)
        shutil.copyfile(ROOT / 'deployment/build/prepare-sources.sh', build / 'prepare-sources.sh')
        (build / 'sources.lock.json').write_text(json.dumps({'cloud-api-adaptor': {'base': base, 'result_tree': tree}}))
        queue = self.root / 'patches/cloud-api-adaptor'
        queue.mkdir(parents=True)
        (queue / 'series').write_text('# fixture empty queue\n')
        (queue / 'SHA256SUMS').write_text(f'{manifest.digest(queue / "series")}  series\n')
        run('bash', str(build / 'prepare-sources.sh'), 'cloud-api-adaptor')
        destination = self.root / '.local/build-sources/cloud-api-adaptor'
        self.assertFalse((destination / '.git/objects/info/alternates').exists())
        origin.rename(self.root / 'unavailable-origin')
        self.assertEqual(run('git', '-C', str(destination), 'show', 'HEAD:file'), 'synthetic public test bytes')
        run('git', '-C', str(destination), 'fsck', '--full')


class StrictTestSourceChecks(unittest.TestCase):
    """Exercise the runner's manifest command against real disposable Git trees."""

    def run_git(self, directory, *args):
        return subprocess.check_output(['git', '-C', str(directory), *args],
                                       text=True, stderr=subprocess.STDOUT).strip()

    @contextlib.contextmanager
    def sources(self):
        local_tmp = ROOT / '.local/test-tmp'
        local_tmp.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=local_tmp) as temp:
            root = Path(temp)
            build = root / 'deployment/build'
            build.mkdir(parents=True)
            shutil.copyfile(ROOT / 'deployment/build/manifest.py', build / 'manifest.py')
            (root / 'deployment/artifacts.lock.json').write_text('{}')
            (root / 'deployment/runtime').mkdir()
            (root / 'deployment/runtime/artifacts.lock.json').write_text('{}')
            lock = {'schema': 1, 'kata-containers': {'base': '0' * 40, 'result_tree': '0' * 40}}
            for name in ['openshell', 'cloud-api-adaptor', 'caa-csi-block-driver']:
                source = root / 'repos' / name
                source.mkdir(parents=True)
                self.run_git(source, 'init', '-q')
                self.run_git(source, 'config', 'user.name', 'Fixture')
                self.run_git(source, 'config', 'user.email', 'fixture@example.invalid')
                (source / 'file').write_text('upstream\n')
                self.run_git(source, 'add', 'file')
                self.run_git(source, 'commit', '-qm', 'fixture')
                lock[name] = {'base': self.run_git(source, 'rev-parse', 'HEAD')}
                if name != 'openshell':
                    patched = root / '.local/build-sources' / name
                    self.run_git(root, 'clone', '--no-hardlinks', str(source), str(patched))
                    (patched / 'file').write_text('approved patch\n')
                    self.run_git(patched, 'add', 'file')
                    lock[name]['result_tree'] = self.run_git(patched, 'write-tree')
            controller = root / '.local/build-sources/peerpod-ctrl'
            upstream = root / 'repos/cloud-api-adaptor'
            self.run_git(root, 'clone', '--no-hardlinks', str(upstream), str(controller))
            (controller / 'file').write_text('generic controller patch\n')
            self.run_git(controller, 'add', 'file')
            lock['peerpod-ctrl'] = {'source': 'cloud-api-adaptor',
                                   'base': lock['cloud-api-adaptor']['base'],
                                   'result_tree': self.run_git(controller, 'write-tree')}
            (build / 'sources.lock.json').write_text(json.dumps(lock))
            self.run_git(root, 'init', '-q')
            self.run_git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '--allow-empty', '-qm', 'integration fixture')
            yield root

    def check(self, root):
        return subprocess.run(['python3.11', str(root / 'deployment/build/manifest.py'),
                               '--check-test-sources'], capture_output=True, text=True)

    def damage(self, target, case):
        if case == 'missing':
            target.rename(target.with_name(target.name + '-unavailable'))
        elif case == 'dirty':
            (target / 'file').write_text('unexpected working tree content\n')
        elif case == 'untracked':
            (target / 'unexpected-source').write_text('not in the pinned result\n')
        elif case == 'tree-mismatch':
            (target / 'file').write_text('unexpected staged source\n')
            self.run_git(target, 'add', 'file')
        elif case == 'commit-mismatch':
            self.run_git(target, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '--allow-empty', '-qm', 'wrong base')

    def test_verified_required_sources_allow_absent_kata(self):
        with self.sources() as root:
            result = self.check(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Kata patch check: not_run', result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report['source_inventory_complete'])
            self.assertEqual(report['sources']['kata-containers']['patch_check'], 'not_present')
            self.assertEqual(report['sources']['peerpod-ctrl']['source_repository'], 'cloud-api-adaptor')
            self.assertEqual(report['sources']['peerpod-ctrl']['upstream_checkout'], 'verified')
            self.assertEqual(report['sources']['peerpod-ctrl']['patch_check'], 'verified')
            self.assertNotEqual(report['sources']['peerpod-ctrl']['observed_patched_result_tree'],
                                report['sources']['cloud-api-adaptor']['observed_patched_result_tree'])

    def test_controller_alias_requires_its_pinned_stock_upstream(self):
        with self.sources() as root:
            lock_path = root / 'deployment/build/sources.lock.json'
            lock = json.loads(lock_path.read_text())
            lock['peerpod-ctrl']['base'] = '0' * 40
            lock_path.write_text(json.dumps(lock))
            result = self.check(root)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('test source check failed: upstream checkout peerpod-ctrl', result.stderr)

    def test_each_required_upstream_rejects_missing_dirty_wrong_commit_and_untracked(self):
        for name in ['openshell', 'cloud-api-adaptor', 'caa-csi-block-driver']:
            for case in ['missing', 'dirty', 'commit-mismatch', 'untracked']:
                with self.subTest(name=name, case=case), self.sources() as root:
                    self.damage(root / 'repos' / name, case)
                    result = self.check(root)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(f'test source check failed: upstream checkout {name}', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_each_patched_input_rejects_missing_dirty_wrong_tree_wrong_base_and_untracked(self):
        for name in ['cloud-api-adaptor', 'peerpod-ctrl', 'caa-csi-block-driver']:
            for case in ['missing', 'dirty', 'tree-mismatch', 'commit-mismatch', 'untracked']:
                with self.subTest(name=name, case=case), self.sources() as root:
                    self.damage(root / '.local/build-sources' / name, case)
                    result = self.check(root)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(f'test source check failed: patched input {name}', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_runner_rejects_untracked_patch_input_before_compilation(self):
        with self.sources() as root:
            tests = root / 'tests'
            tests.mkdir()
            shutil.copyfile(ROOT / 'tests/run.sh', tests / 'run.sh')
            self.damage(root / '.local/build-sources/cloud-api-adaptor', 'untracked')
            result = subprocess.run(['bash', str(tests / 'run.sh')], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('test source check failed: patched input cloud-api-adaptor', result.stderr)

    def prepare_chart_packager(self, root):
        build = root / 'deployment/build'
        shutil.copyfile(ROOT / 'deployment/build/package-csi-chart.py', build / 'package-csi-chart.py')
        source = root / '.local/build-sources/caa-csi-block-driver'
        chart = source / 'charts/caa-csi-block-driver'
        chart.mkdir(parents=True)
        (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: caa-csi-block-driver\nversion: 0.2.0\n')
        (chart / 'values.yaml').write_text('provider: alibabacloud\n')
        self.run_git(source, 'add', 'charts')
        lock_path = build / 'sources.lock.json'
        lock = json.loads(lock_path.read_text())
        lock['caa-csi-block-driver']['result_tree'] = self.run_git(source, 'write-tree')
        lock_path.write_text(json.dumps(lock))
        return build / 'package-csi-chart.py'

    def test_chart_packager_records_verified_tree_and_is_reproducible(self):
        import tarfile
        with self.sources() as root:
            script = self.prepare_chart_packager(root)
            first = json.loads(subprocess.check_output(['python3.11', str(script)], text=True))
            second = json.loads(subprocess.check_output(['python3.11', str(script)], text=True))
            self.assertEqual(first, second)
            self.assertEqual(first['path'], 'artifacts/charts/caa-csi-block-driver.tgz')
            expected = json.loads((root / 'deployment/build/sources.lock.json').read_text())['caa-csi-block-driver']
            self.assertEqual(first['source']['source_upstream_commit'], expected['base'])
            self.assertEqual(first['source']['patched_result_tree'], expected['result_tree'])
            with tarfile.open(root / first['path']) as archive:
                self.assertEqual(archive.extractfile('caa-csi-block-driver/values.yaml').read(), b'provider: alibabacloud\n')
                self.assertEqual(json.load(archive.extractfile('caa-csi-block-driver/source-provenance.json')), first['source'])
                self.assertFalse(any('.git' in Path(name).parts for name in archive.getnames()))

    def test_chart_packager_refuses_missing_dirty_untracked_or_wrong_source(self):
        for case in ['missing', 'dirty', 'tree-mismatch', 'commit-mismatch', 'untracked', 'upstream-dirty', 'upstream-commit-mismatch']:
            with self.subTest(case=case), self.sources() as root:
                script = self.prepare_chart_packager(root)
                if case.startswith('upstream-'):
                    self.damage(root / 'repos/caa-csi-block-driver', case.removeprefix('upstream-'))
                else:
                    self.damage(root / '.local/build-sources/caa-csi-block-driver', case)
                result = subprocess.run(['python3.11', str(script)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('CSI packaging requires the pinned clean upstream and exact patched base/tree', result.stderr)
                self.assertFalse((root / 'artifacts/charts/caa-csi-block-driver.tgz').exists())

    def test_chart_manifest_rejects_payload_tampering_with_correct_provenance(self):
        with self.sources() as root:
            script = self.prepare_chart_packager(root)
            report = json.loads(subprocess.check_output(['python3.11', str(script)], text=True))
            path = root / report['path']
            with tarfile.open(path) as archive:
                original = [(member, archive.extractfile(member).read() if member.isfile() else None)
                            for member in archive.getmembers()]
            lock = json.loads((root / 'deployment/build/sources.lock.json').read_text())
            with patch.object(manifest, 'ROOT', root):
                observed = manifest.inventory(lock)
                self.assertEqual(manifest.csi_chart_provenance(path, observed), report['source'])
                for case in ['content', 'mode', 'missing', 'extra', 'duplicate', 'symlink', 'hardlink', 'traversal']:
                    with self.subTest(case=case):
                        with tarfile.open(path, 'w:gz') as archive:
                            for member, data in original:
                                member = copy.copy(member)
                                if member.name.endswith('/values.yaml'):
                                    if case == 'missing':
                                        continue
                                    if case == 'content':
                                        data = b'provider: wrong-provider\n'
                                        member.size = len(data)
                                    elif case == 'mode':
                                        member.mode |= 0o111
                                    elif case in {'symlink', 'hardlink'}:
                                        member.type = tarfile.SYMTYPE if case == 'symlink' else tarfile.LNKTYPE
                                        member.linkname = 'Chart.yaml'
                                        member.size = 0
                                        data = None
                                archive.addfile(member, io.BytesIO(data) if data is not None else None)
                                if case == 'duplicate' and member.name.endswith('/values.yaml'):
                                    archive.addfile(member, io.BytesIO(data))
                            if case in {'extra', 'traversal'}:
                                member = tarfile.TarInfo('caa-csi-block-driver/' + ('extra.yaml' if case == 'extra' else '../escape'))
                                archive.addfile(member, io.BytesIO(b''))
                        with self.assertRaises(ValueError):
                            manifest.csi_chart_provenance(path, observed)

    def test_manifest_requires_verified_csi_input_for_chart_output(self):
        with self.sources() as root:
            script = self.prepare_chart_packager(root)
            subprocess.check_output(['python3.11', str(script)], text=True)
            (root / '.gitignore').write_text('/.local/\n/repos/\n/artifacts/\n')
            self.run_git(root, 'add', '.gitignore', 'deployment')
            self.run_git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'build fixture')
            self.damage(root / '.local/build-sources/caa-csi-block-driver', 'dirty')
            result = subprocess.run(['python3.11', str(root / 'deployment/build/manifest.py'), '--profile', 'release',
                                     '--artifact', 'csi-chart=artifacts/charts/caa-csi-block-driver.tgz'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('missing or mismatched patched input: caa-csi-block-driver', result.stderr)
