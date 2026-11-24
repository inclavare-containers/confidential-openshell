"""Run the real guest validator on synthetic initdata, without services or quotes."""
import base64
import gzip
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'deployment/guest/files/usr/local/libexec/openshell-guest'
loader = importlib.machinery.SourceFileLoader('guest_check', str(HELPERS / 'check-initdata'))
spec = importlib.util.spec_from_loader(loader.name, loader)
guest_check = importlib.util.module_from_spec(spec)
loader.exec_module(guest_check)

# The validator requires PEM framing, not a live certificate chain; no key is used.
CA = '-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----'

def fixture(role):
    names = guest_check.WORKLOAD_REFS if role == 'workload' else guest_check.SUPERVISOR_REFS - {'upstream-proxy-ca.pem'}
    bootstrap = {'schema': 1, 'role': role, 'sandbox_id': 'sandbox-1', 'namespace': 'openshell',
                 'sandbox_resource_uid': 'cr-1', 'runtime_generation': 'g0001', 'bootstrap_attempt': 'a' * 64,
                 'resource_uris': {n: 'kbs:///default/bootstrap/' + hashlib.sha256(n.encode()).hexdigest() for n in names}}
    aa = '[token_configs.kbs]\nurl="https://10.0.0.1:8443"\ncert=' + json.dumps(CA)
    cdh = '[kbc]\nurl="https://10.0.0.1:8443"\nkbs_cert=' + json.dumps(CA) + '\n[image]\nextra_root_certificates=[' + json.dumps(CA) + ']'
    return {'aa.toml': aa, 'cdh.toml': cdh, 'policy.rego': 'package agent_policy\ndefault allow := false',
            'openshell-bootstrap.json': json.dumps(bootstrap)}

def validate(data, materialized_mutation=None, native=False):
    with tempfile.TemporaryDirectory() as tmp:
        parent = Path(tmp)
        raw = ('version="0.1.0"\nalgorithm="sha384"\n[data]\n' + '\n'.join(json.dumps(k) + '=' + json.dumps(v) for k, v in data.items())).encode()
        (parent / 'initdata').write_bytes(base64.b64encode(gzip.compress(raw, mtime=0)))
        (parent / 'initdata.toml').write_bytes(raw)
        (parent / 'initdata.digest').write_text(hashlib.sha384(raw).hexdigest())
        if not native:
            for k, v in data.items():
                (parent / k).write_text(v)
        if materialized_mutation:
            materialized_mutation(parent)
        args = ["check-initdata", "--kata"] if native else ["check-initdata"]
        with (mock.patch.object(guest_check, 'PARENT', parent),
              mock.patch.object(guest_check, 'KATA_INITDATA', parent / 'initdata.toml'),
              mock.patch.object(guest_check.sys, 'argv', args)):
            guest_check.main()
        return {p.name: p.read_bytes() for p in parent.iterdir()}

class GuestContract(unittest.TestCase):
    def test_both_roles_validate_measured_bootstrap(self):
        for role in ('supervisor', 'workload'):
            with self.subTest(role=role):
                files = validate(fixture(role))
                self.assertEqual(files['workspace-required.env'], b'ENCRYPTED_VOLUMES_REQUIRED=false\n')

    def test_cloud_init_transport_newline_preserves_measurement(self):
        data = fixture('workload')
        data['policy.rego'] += '\n\n'
        original = validate(data)
        for ending in (b'\n', b'\r\n'):
            with self.subTest(ending=ending):
                result = validate(data, lambda p: (p / 'initdata').write_bytes((p / 'initdata').read_bytes() + ending))
                self.assertEqual(result['initdata.digest'], original['initdata.digest'])
                self.assertEqual(result['policy.rego'], original['policy.rego'])
        with self.assertRaises(ValueError):
            validate(data, lambda p: (p / 'initdata').write_bytes((p / 'initdata').read_bytes() + b' '))

    def test_registry_trust_is_independent_of_kbs_trust(self):
        data = fixture('workload')
        other = CA.replace('YQ==', 'Yg==')
        data['cdh.toml'] = data['cdh.toml'].replace('extra_root_certificates=[' + json.dumps(CA),
                                                        'extra_root_certificates=[' + json.dumps(other))
        validate(data)
        for roots in ([], [CA, other]):
            data['cdh.toml'] = '[kbc]\nurl="https://10.0.0.1:8443"\nkbs_cert=' + json.dumps(CA) + '\n[image]\nextra_root_certificates=' + json.dumps(roots)
            validate(data)
        data['aa.toml'] = data['aa.toml'].replace(json.dumps(CA), json.dumps(other))
        with self.assertRaisesRegex(ValueError, 'AA and CDH KBS CA'):
            validate(data)

    def test_core_negative_bindings_remain_enforced(self):
        for key, value, error in [('role', 'unknown', 'role'), ('bootstrap_attempt', 'short', 'attempt'),
                                  ('sandbox_resource_uid', '', 'sandbox_resource_uid')]:
            with self.subTest(key=key):
                data = fixture('workload')
                body = json.loads(data['openshell-bootstrap.json']); body[key] = value
                data['openshell-bootstrap.json'] = json.dumps(body)
                with self.assertRaisesRegex(ValueError, error):
                    validate(data)
        with self.assertRaisesRegex(ValueError, 'differs from initdata'):
            validate(fixture('workload'), lambda p: (p / 'policy.rego').write_text('allow all'))
        with self.assertRaisesRegex(ValueError, 'digest'):
            validate(fixture('workload'), lambda p: (p / 'initdata.digest').write_text('0' * 96))
        with self.assertRaisesRegex(ValueError, 'initdata.toml'):
            validate(fixture('workload'), lambda p: (p / 'initdata.toml').write_text('different input'))

    def test_workspace_binding_remains_required(self):
        data = fixture('workload'); body = json.loads(data['openshell-bootstrap.json'])
        body['resource_uris']['workspace-key'] = 'kbs:///default/workspace/' + 'c' * 64
        data['openshell-bootstrap.json'] = json.dumps(body)
        with self.assertRaisesRegex(ValueError, 'occur together'):
            validate(data)
        data['workspace.toml'] = ('version="0.1.0"\nkey_uri="' + body['resource_uris']['workspace-key'] + '"\n'
                                  'encryption_type="luks2"\nfilesystem_type="ext4"\nallow_initialize=true\ndisk_ids=["d-test123"]')
        self.assertEqual(validate(data)['workspace-required.env'], b'ENCRYPTED_VOLUMES_REQUIRED=true\n')
        data['workspace.toml'] = 'version="0.1.0"\nkey_uri="kbs:///default/workspace/wrong"'
        with self.assertRaisesRegex(ValueError, 'invalid measured workspace'):
            validate(data)
    def test_native_workspace_binds_owner_instead_of_disk_id(self):
        data = fixture('workload')
        body = json.loads(data['openshell-bootstrap.json'])
        key = 'kbs:///default/workspace/' + 'c' * 64
        body['resource_uris']['workspace-key'] = key
        data['openshell-bootstrap.json'] = json.dumps(body)
        common = (f'version="0.1.0"\nkey_uri="{key}"\nencryption_type="luks2"\n'
                  'filesystem_type="ext4"\nallow_initialize=true\n')
        data['workspace.toml'] = common + 'uid=1500\ngid=1600\n'
        files = validate(data, native=True)
        self.assertEqual(files['workspace.toml'], data['workspace.toml'].encode())
        self.assertNotIn('workspace-required.env', files)
        data['workspace.toml'] = common + 'disk_ids=["d-test123"]'
        with self.assertRaisesRegex(ValueError, 'invalid measured workspace'):
            validate(data, native=True)

    def test_supervisor_requires_server_ca_without_user_tls_keys(self):
        files = validate(fixture('supervisor'))
        refs = json.loads(files['openshell-bootstrap.json'])['resource_uris']
        self.assertIn('client-ca.crt', refs)
        self.assertNotIn('client-tls.crt', refs)
        self.assertNotIn('client-tls.key', refs)
        data = fixture('supervisor')
        body = json.loads(data['openshell-bootstrap.json'])
        body['resource_uris'].pop('client-ca.crt')
        data['openshell-bootstrap.json'] = json.dumps(body)
        with self.assertRaisesRegex(ValueError, 'missing role bootstrap resource references'):
            validate(data)

    def test_supervisor_cannot_receive_user_tls_resources(self):
        for name in ('client-tls.crt', 'client-tls.key'):
            with self.subTest(name=name):
                data = fixture('supervisor')
                body = json.loads(data['openshell-bootstrap.json'])
                body['resource_uris'][name] = 'kbs:///default/bootstrap/old'
                data['openshell-bootstrap.json'] = json.dumps(body)
                with self.assertRaisesRegex(ValueError, 'invalid bootstrap resource references'):
                    validate(data)

    def test_core_service_order_measures_initdata_before_secret_release(self):
        import configparser
        units = ROOT / 'deployment/guest/files/etc/systemd/system'
        def unit(name):
            result = configparser.ConfigParser(interpolation=None, strict=False)
            result.read(units / name / '20-confidential.conf')
            return result
        aa = unit('attestation-agent.service.d')
        cdh = unit('confidential-data-hub.service.d')
        kata = unit('kata-agent.service.d')
        self.assertTrue({'process-user-data.service', 'systemd-time-wait-sync.service'}
                        <= set(aa['Unit']['After'].split()))
        self.assertIn('attestation-agent.service', cdh['Unit']['Wants'].split())
        self.assertIn('attestation-agent.service', cdh['Unit']['After'].split())
        self.assertIn('confidential-data-hub.service', kata['Unit']['After'].split())

if __name__ == '__main__':
    unittest.main()
