"""Optional plugin registration preserves unrelated Trustee configuration."""
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('configure_reports', ROOT / 'deployment/trustee/configure-reports.py')
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)


class Configuration(unittest.TestCase):
    def test_enable_is_idempotent_and_disable_restores_original(self):
        original = (ROOT / 'deployment/trustee/kbs-config.example.toml').read_text()
        enabled = reports.configure(original, True)
        self.assertEqual(reports.configure(enabled, True), enabled)
        self.assertEqual(reports.configure(enabled, False), original)
        before, after = tomllib.loads(original), tomllib.loads(enabled)
        self.assertEqual(before['storage_backend'], after['storage_backend'])
        self.assertEqual(before['attestation_service'], after['attestation_service'])
        self.assertEqual(before['http_server'], after['http_server'])
        self.assertEqual(before['admin']['authentication'], after['admin']['authentication'])
        self.assertEqual(after['plugins'][-1]['backends'][0]['endpoint'], 'http://127.0.0.1:50005')
        self.assertEqual(len(after['admin']['authorization']['regex_acl']['acls']),
                         len(before['admin']['authorization']['regex_acl']['acls']) + 1)

    def test_custom_or_volatile_layout_requires_explicit_configuration(self):
        original = (ROOT / 'deployment/trustee/kbs-config.example.toml').read_text()
        variants = [original + '\n[[plugins]]\nname = "external"\nbackends = []\n',
                    'session_storage_type = "Memory"\n' + original,
                    original.replace('AuthenticatedAuthorization', 'InsecureAllowAll'),
                    original.replace('/opt/trustee/kbs/storage', '/custom/storage')]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                reports.configure(value, True)

    def test_plugin_proto_matches_pinned_upstream_inventory(self):
        root = ROOT / 'components/attestation-observer'
        inventory = json.loads((root / 'UPSTREAM-SOURCES.json').read_text())
        self.assertEqual(inventory['commit'], '512fed65642015b849f38fb13bfdec7806639987')
        self.assertEqual(hashlib.sha256((root / 'proto/plugin.proto').read_bytes()).hexdigest(),
                         inventory['files']['proto/plugin.proto']['sha256'])


class Installation(unittest.TestCase):
    def test_private_parent_stays_private_under_operator_umask(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            namespace = parent / 'kbs_protocol_session'
            previous = os.umask(0o077)
            try:
                reports.prepare_sessions(namespace)
            finally:
                os.umask(previous)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(namespace.stat().st_mode & 0o777, 0o755)
            record = namespace / 'record'
            record.write_text('synthetic')
            record.chmod(0o600)
            with self.assertRaises(ValueError):
                reports.prepare_sessions(namespace)

    def test_reinstall_atomically_replaces_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = root / 'source', root / 'installed'
            source.write_bytes(b'new binary fixture')
            target.write_bytes(b'previous binary fixture')
            with target.open('rb') as old:
                reports.install_binary(source, target)
                self.assertEqual(old.read(), b'previous binary fixture')
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
