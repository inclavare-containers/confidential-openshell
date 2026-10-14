"""Destructive initialization must reject unbound identities and nonzero raw data."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('workspace_init', str(ROOT/'deployment/guest/files/usr/libexec/peerpod/initialize-workspace-volume'))
spec = importlib.util.spec_from_loader(loader.name, loader)
workspace = importlib.util.module_from_spec(spec)
loader.exec_module(workspace)


class WorkspaceContract(unittest.TestCase):
    def test_initialization_requires_measured_disk_and_key(self):
        policy = {'version':'0.1.0', 'key_uri':'kbs:///default/workspace/key-1',
                  'disk_ids':['d-test1'], 'allow_initialize':True,
                  'encryption_type':'luks2', 'filesystem_type':'ext4'}
        workspace.validate_policy(policy, 'd-test1', 'ext4', policy['key_uri'])
        for disk, fs_type, key in [('d-replaced', 'ext4', policy['key_uri']),
                                   ('d-test1', 'xfs', policy['key_uri']),
                                   ('d-test1', 'ext4', 'kbs:///default/workspace/other')]:
            with self.subTest(disk=disk, fs_type=fs_type, key=key), self.assertRaises(ValueError):
                workspace.validate_policy(policy, disk, fs_type, key)
        with self.assertRaises(ValueError):
            workspace.validate_policy({**policy, 'allow_initialize':False}, 'd-test1', 'ext4', policy['key_uri'])
        with self.assertRaises(ValueError):
            workspace.validate_policy({**policy, 'disk_ids':[]}, 'd-test1', 'ext4', policy['key_uri'])

    def test_blank_scan_checks_entire_device_not_only_signatures_or_edges(self):
        size = 64 * 1024 * 1024
        with tempfile.TemporaryFile() as file:
            file.truncate(size)
            workspace.require_zero_device(file.fileno(), size)
            # An arbitrary raw byte in the middle has no filesystem signature.
            for offset in (0, size//2+1, size-1):
                with self.subTest(offset=offset):
                    os.pwrite(file.fileno(), b'x', offset)
                    with self.assertRaisesRegex(ValueError, 'entirely zero-filled'):
                        workspace.require_zero_device(file.fileno(), size)
                    os.pwrite(file.fileno(), b'\0', offset)

    def test_partition_and_holder_are_never_initializable(self):
        old = workspace.SYS_BLOCK
        with tempfile.TemporaryDirectory() as tmp:
            workspace.SYS_BLOCK = Path(tmp)
            disk = Path(tmp)/'vdb'
            (disk/'device').mkdir(parents=True)
            (disk/'holders').mkdir()
            (disk/'device/serial').write_text('test1')
            try:
                workspace.require_disk_identity('vdb', 'd-test1')
                with self.assertRaises(ValueError):
                    workspace.require_disk_identity('vdb', 'd-replaced')
                (disk/'partition').touch()
                with self.assertRaises(ValueError):
                    workspace.require_disk_identity('vdb', 'd-test1')
                (disk/'partition').unlink()
                (disk/'holders/dm-1').touch()
                with self.assertRaises(ValueError):
                    workspace.require_disk_identity('vdb', 'd-test1')
            finally:
                workspace.SYS_BLOCK = old


if __name__ == '__main__':
    unittest.main()
