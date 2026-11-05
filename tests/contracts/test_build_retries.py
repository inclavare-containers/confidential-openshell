"""Failure injection at build publication boundaries, without Docker or cloud calls."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AtomicBuild(unittest.TestCase):
    def fixture(self, *files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (root / 'bin').mkdir()
        return root

    def executable(self, root, name, body):
        path = root / 'bin' / name
        path.write_text('#!/usr/bin/env bash\nset -eu\n' + body)
        path.chmod(0o755)

    def test_patch_interruption_retries_from_clean_staging(self):
        root = self.fixture('deployment/build/prepare-sources.sh')
        repo = root / 'repos/cloud-api-adaptor'
        repo.mkdir(parents=True)

        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL).strip()

        git('init')
        git('config', 'user.name', 'Test Fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        (repo / 'input').write_text('base\n')
        git('add', 'input')
        git('commit', '-m', 'base')
        base = git('rev-parse', 'HEAD')
        (repo / 'input').write_text('patched\n')
        diff = git('diff') + '\n'
        git('add', 'input')
        tree = git('write-tree')
        git('reset', '--hard', 'HEAD')
        (root / 'deployment/build/sources.lock.json').write_text(json.dumps({'cloud-api-adaptor': {'base': base, 'result_tree': tree}}))
        queue = root / 'patches/cloud-api-adaptor'
        queue.mkdir(parents=True)
        (queue / '001.patch').write_text(diff)
        (queue / 'series').write_text('001.patch\n')
        (queue / 'SHA256SUMS').write_text(hashlib.sha256(diff.encode()).hexdigest() + '  001.patch\n')
        self.executable(root, 'git', '''for arg in "$@"; do
  if [[ $arg == apply && -e "$FAIL_MARKER" ]]; then rm -- "$FAIL_MARKER"; exit 17; fi
done
exec ''' + shutil.which('git') + ' "$@"\n')
        marker = root / 'fail-once'
        marker.touch()
        env = {**os.environ, 'PATH': str(root / 'bin') + ':' + os.environ['PATH'], 'FAIL_MARKER': str(marker)}
        command = ['bash', str(root / 'deployment/build/prepare-sources.sh'), 'cloud-api-adaptor']
        failed = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(failed.returncode, 17, failed.stderr)
        destination = root / '.local/build-sources/cloud-api-adaptor'
        self.assertFalse(destination.exists())
        succeeded = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(succeeded.returncode, 0, succeeded.stderr)
        self.assertEqual((destination / 'input').read_text(), 'patched\n')
        self.assertEqual(list(destination.parent.glob('.cloud-api-adaptor.*')), [])

    def test_export_failure_does_not_reserve_final_handoff(self):
        root = self.fixture('deployment/build/package-release.sh',
                            'deployment/lib/common.sh', 'deployment/build/sources.lock.json',
                            'deployment/runtime/artifacts.lock.json')
        (root / '.local').mkdir()
        (root / '.local/guest-selection.json').write_text(json.dumps({
            'mode': 'existing', 'region': 'cn-beijing', 'image_id': 'm-test', 'qcow': '',
            'references': 'artifacts/guest/fixture.references.json', 'receipt': '',
        }))
        self.executable(root, 'git', 'exit 0\n')
        self.executable(root, 'docker', 'echo export-attempt >> "$EXPORT_ATTEMPTS"\nexit 17\n')
        env = {**os.environ, 'PATH': str(root / 'bin') + ':' + os.environ['PATH'],
               'EXPORT_ATTEMPTS': str(root / 'attempts')}
        # common.sh prepends toolchain paths. Keep the dependency stubs first
        # in this isolated fixture so this test can never invoke real Docker.
        common = root / 'deployment/lib/common.sh'
        common.write_text(common.read_text().replace('export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"', 'export PATH="$ROOT/bin:$PATH"'))
        for _ in range(2):
            result = subprocess.run(['bash', str(root / 'deployment/build/package-release.sh')], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertFalse((root / 'artifacts/handoff').exists())
            self.assertEqual(list((root / 'artifacts').glob('.handoff.*')), [])
        self.assertEqual((root / 'attempts').read_text().splitlines(), ['export-attempt', 'export-attempt'])


if __name__ == '__main__':
    unittest.main()
