"""Destructive initialization must reject unbound identities and nonzero raw data."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
GUEST_LIBEXEC = ROOT / 'deployment/guest/files/usr/libexec/peerpod'
sys.path.insert(0, str(GUEST_LIBEXEC))
import workspace_block


def load_script(name):
    loader = importlib.machinery.SourceFileLoader(name, str(GUEST_LIBEXEC / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


workspace = load_script('initialize-workspace-volume')
native = load_script('open-kata-workspace')


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


    def test_native_blank_disk_with_initialization_disabled_fails_before_key_request(self):
        with (mock.patch.object(native.subprocess, 'run', return_value=mock.Mock(returncode=1)),
              mock.patch.object(native, 'run') as command):
            with self.assertRaisesRegex(ValueError, 'initialization is disabled'):
                native.open_volume(Path('/dev/sdb'), {'allow_initialize': False, 'key_uri': 'unused'})
            command.assert_not_called()

    def test_native_failed_open_leaves_startup_probe_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp)
            (control / 'request').write_text('8:0')
            (control / 'workspace.toml').write_text('allow_initialize = false')
            with (mock.patch.object(native, 'CONTROL', control),
                  mock.patch.object(native, 'RUNTIME', control),
                  mock.patch.object(native, 'run'),
                  mock.patch.object(Path, 'resolve', return_value=Path('/sys/class/block/sda')),
                  mock.patch.object(native, 'require_whole_disk', return_value=Path('/sys/class/block/sda')),
                  mock.patch.object(native, 'open_volume', side_effect=ValueError('open failed'))):
                with self.assertRaisesRegex(ValueError, 'open failed'):
                    native.handoff()
                self.assertFalse((control / 'ready').exists())

    def test_native_mapping_checks_active_parameters_and_backing_disk(self):
        status = ('  type: LUKS2\n  cipher: aes-xts-plain64\n'
                  '  keysize: 512 [bits]\n  sector size: 4096 [bytes]\n')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'dm-0/slaves').mkdir(parents=True)
            (root / 'sdb/slaves').mkdir(parents=True)
            (root / 'dm-0/slaves/sdb').symlink_to(root / 'sdb')
            mapper = root / 'dm-0'
            with (mock.patch.object(workspace_block.subprocess, 'check_output', return_value=status) as inspect,
                  mock.patch.object(workspace_block, 'SYS_BLOCK', root)):
                native.verify_mapper(mapper, Path('/dev/sdb'))
                with self.assertRaisesRegex(ValueError, 'backed by'):
                    native.verify_mapper(mapper, Path('/dev/sdc'))
                inspect.return_value = status.replace('4096', '512')
                with self.assertRaisesRegex(ValueError, '4096-byte sectors'):
                    native.verify_mapper(mapper, Path('/dev/sdb'))


if __name__ == '__main__':
    unittest.main()
