"""Private build umasks must not prevent stock daemon users accessing the image."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('guest_image', ROOT/'deployment/guest/verify-image.py')
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class GuestPermissionContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in image.PUBLIC_DIRECTORIES:
            (self.root/name).mkdir(parents=True, exist_ok=True)
        for name in (*image.PUBLIC_READABLE_FILES, *image.PUBLIC_EXECUTABLES):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'public image input')
            path.chmod(0o755 if name in image.PUBLIC_EXECUTABLES else 0o644)
        for path in self.root.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
        self.root.chmod(0o755)

    def test_public_image_is_usable_by_stock_daemon_users(self):
        modes = image.verify_public_permissions(self.root)
        self.assertEqual(modes['/usr/lib/systemd/systemd-timesyncd'], '0o755')

    def test_private_checkout_directory_modes_are_rejected(self):
        for name in ('usr', 'etc', 'usr/lib/systemd', 'usr/local/bin'):
            with self.subTest(path=name):
                path = self.root/name
                path.chmod(0o700)
                with self.assertRaisesRegex(ValueError, 'directory is not traversable'):
                    image.verify_public_permissions(self.root)
                path.chmod(0o755)

    def test_unreadable_network_config_and_nonexecutable_daemon_are_rejected(self):
        for name, mode in [('usr/lib/systemd/network/20-wired.network', 0o600),
                           ('usr/lib/systemd/systemd-timesyncd', 0o744)]:
            with self.subTest(path=name):
                path = self.root/name
                original = path.stat().st_mode & 0o777
                path.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'daemon input is not accessible'):
                    image.verify_public_permissions(self.root)
                path.chmod(original)


if __name__ == '__main__':
    unittest.main()
