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
                 'sealed_volume_destination': '/.openshell/bootstrap-input' if role == 'workload' else '/.openshell/supervisor',
                 'sealed_volume_container': 'openshell-sandbox-bootstrap' if role == 'workload' else 'supervisor',
                 'resource_uris': {n: 'kbs:///default/bootstrap/' + hashlib.sha256(n.encode()).hexdigest() for n in names},
                 'sealed_descriptor_sha256': {n: 'b' * 64 for n in names}}
    aa = '[token_configs.kbs]\nurl="https://10.0.0.1:8443"\ncert=' + json.dumps(CA)
    cdh = '[kbc]\nurl="https://10.0.0.1:8443"\nkbs_cert=' + json.dumps(CA) + '\n[image]\nextra_root_certificates=[' + json.dumps(CA) + ']'
    return {'aa.toml': aa, 'cdh.toml': cdh, 'policy.rego': 'package agent_policy\ndefault allow := false',
            'openshell-bootstrap.json': json.dumps(bootstrap)}

def validate(data, materialized_mutation=None):
    with tempfile.TemporaryDirectory() as tmp:
        parent = Path(tmp)
        raw = ('version="0.1.0"\nalgorithm="sha384"\n[data]\n' + '\n'.join(json.dumps(k) + '=' + json.dumps(v) for k, v in data.items())).encode()
        (parent / 'initdata').write_bytes(base64.b64encode(gzip.compress(raw, mtime=0)))
        (parent / 'initdata.digest').write_text(hashlib.sha384(raw).hexdigest())
        for k, v in data.items():
            (parent / k).write_text(v)
        if materialized_mutation:
            materialized_mutation(parent)
        guest_check.PARENT = parent
        guest_check.main()
        return {p.name: p.read_bytes() for p in parent.iterdir()}

class GuestContract(unittest.TestCase):
    def test_both_roles_validate_measured_bootstrap(self):
        for role in ('supervisor', 'workload'):
            with self.subTest(role=role):
                files = validate(fixture(role))
                self.assertEqual(files['workspace-required.env'], b'ENCRYPTED_VOLUMES_REQUIRED=false\n')

    def test_registry_trust_is_independent_of_kbs_trust(self):
        data = fixture('workload')
        other = CA.replace('YQ==', 'Yg==')
        data['cdh.toml'] = data['cdh.toml'].replace('extra_root_certificates=[' + json.dumps(CA),
                                                        'extra_root_certificates=[' + json.dumps(other))
        validate(data)
        data['aa.toml'] = data['aa.toml'].replace(json.dumps(CA), json.dumps(other))
        with self.assertRaisesRegex(ValueError, 'AA and CDH KBS CA'):
            validate(data)

    def test_core_negative_bindings_remain_enforced(self):
        for key, value, error in [('role', 'unknown', 'role'), ('bootstrap_attempt', 'short', 'attempt'),
                                  ('sandbox_resource_uid', '', 'sandbox_resource_uid'),
                                  ('sealed_volume_destination', '/tmp', 'destination'),
                                  ('sealed_volume_container', 'wrong', 'container'),
                                  ('sealed_descriptor_sha256', {}, 'hashes')]:
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
        with self.assertRaisesRegex(ValueError, 'not bound'):
            validate(data)
    def test_supervisor_requires_server_ca_without_user_tls_keys(self):
        files = validate(fixture('supervisor'))
        refs = json.loads(files['openshell-bootstrap.json'])['resource_uris']
        self.assertIn('client-ca.crt', refs)
        self.assertNotIn('client-tls.crt', refs)
        self.assertNotIn('client-tls.key', refs)
        data = fixture('supervisor')
        body = json.loads(data['openshell-bootstrap.json'])
        body['resource_uris'].pop('client-ca.crt')
        body['sealed_descriptor_sha256'].pop('client-ca.crt')
        data['openshell-bootstrap.json'] = json.dumps(body)
        with self.assertRaisesRegex(ValueError, 'missing role bootstrap resource references'):
            validate(data)

    def test_supervisor_cannot_receive_user_tls_resources(self):
        for name in ('client-tls.crt', 'client-tls.key'):
            with self.subTest(name=name):
                data = fixture('supervisor')
                body = json.loads(data['openshell-bootstrap.json'])
                body['resource_uris'][name] = 'kbs:///default/bootstrap/old'
                body['sealed_descriptor_sha256'][name] = 'b' * 64
                data['openshell-bootstrap.json'] = json.dumps(body)
                with self.assertRaisesRegex(ValueError, 'invalid bootstrap resource references'):
                    validate(data)

    def test_core_service_order_measures_initdata_before_secret_release(self):
        units = ROOT / 'deployment/guest/files/etc/systemd/system'
        aa = (units / 'attestation-agent.service.d/20-confidential.conf').read_text()
        cdh = (units / 'confidential-data-hub.service.d/20-confidential.conf').read_text()
        kata = (units / 'kata-agent.service.d/20-confidential.conf').read_text()
        self.assertIn('After=process-user-data.service systemd-time-wait-sync.service', aa)
        self.assertIn('ExecStartPost=/usr/local/libexec/openshell-guest/extend-initdata', aa)
        self.assertIn('Requires=attestation-agent.service', cdh)
        self.assertIn('After=attestation-agent.service', cdh)
        self.assertIn('After=confidential-data-hub.service', kata)
        extension = (HELPERS / 'extend-initdata').read_text()
        self.assertIn('process-user-data measure-initdata', extension)

    def test_reference_namespace_ingress_default_deny_is_retained(self):
        policy = (ROOT / 'deployment/openshell/network-fence.example.yaml').read_text()
        self.assertIn('namespace: openshell', policy)
        self.assertIn('podSelector: {}', policy)
        self.assertIn('policyTypes: [Ingress]', policy)
        self.assertIn('ingress: []', policy)
        self.assertIn('--workspace-mode shared', (ROOT / 'deployment/openshell/openshell-confidential-driver.service').read_text())

if __name__ == '__main__':
    unittest.main()
