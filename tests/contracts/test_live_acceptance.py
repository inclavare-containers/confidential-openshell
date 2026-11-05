"""The live probe must reject stale/tampered evidence and old trusted attempts."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('live_probe', ROOT / 'tests/acceptance/check-live-release.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class LiveEvidence(unittest.TestCase):
    def test_signed_current_ear_and_rejection_cases(self):
        key = ec.generate_private_key(ec.SECP256R1())
        digest = 'a' * 96
        claims = {'iat': int(time.time()), 'exp': int(time.time()) + 300, 'submods': {'cpu0': {
            'ear.status': 'affirming', 'ear.appraisal-policy-id': 'openshell-tdx',
            'ear.trustworthiness-vector': {'hardware': 2, 'configuration': 2, 'executables': 3, 'file-system': 2},
            'ear.veraison.annotated-evidence': {'runtime_data_claims': {'tee-pubkey': {}}, 'tdx': {
                'uefi_event_logs': [{'type_name': 'EV_EVENT_TAG', 'details': {'unicode_name': 'AAEL',
                    'data': {'domain': 'github.com/confidential-containers', 'operation': 'InitData', 'content': {'digest': 'sha384:' + digest}}}}]}}}}}

        def signed():
            content = b64(b'{"alg":"ES256"}') + '.' + b64(json.dumps(claims).encode())
            r, s = utils.decode_dss_signature(key.sign(content.encode(), ec.ECDSA(hashes.SHA256())))
            return content + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

        self.assertEqual(probe.verify_ear(signed(), key.public_key()), digest)
        with self.assertRaises(InvalidSignature):
            probe.verify_ear(signed(), ec.generate_private_key(ec.SECP256R1()).public_key())
        claims['exp'] = int(time.time()) - 1
        with self.assertRaisesRegex(ValueError, 'expired'):
            probe.verify_ear(signed(), key.public_key())
        claims['exp'] = int(time.time()) + 300
        claims['submods']['cpu0']['ear.status'] = 'warning'
        with self.assertRaisesRegex(ValueError, 'non-affirming'):
            probe.verify_ear(signed(), key.public_key())

    def test_current_attempt_only_and_no_key_in_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('bindings', 'active-attempts', 'revoked', 'revoking'):
                (root / name).mkdir()
            active = {'sandbox_id': 'native-id', 'sandbox_cr_uid': 'cr-uid', 'generation': 'generation', 'attempt': 'fresh'}
            (root / 'active-attempts/owner.json').write_text(json.dumps(active))
            for role in ('supervisor', 'workload'):
                row = {**active, 'attempt_id': 'fresh', 'role': role, 'resource_path': 'resource/' + role,
                       'initdata_sha384': role, 'identity_sha256': role, 'key': 'must-not-export'}
                (root / ('bindings/' + role + '.json')).write_text(json.dumps(row))
                (root / ('bindings/old-' + role + '.json')).write_text(json.dumps({**row, 'attempt_id': 'old'}))
            result = probe.current_bindings(root, 'cr-uid')
            self.assertEqual(set(result), {'supervisor', 'workload'})
            self.assertNotIn('must-not-export', json.dumps(result))
            extra = {**row, 'resource_path': 'resource/another-workload-file'}
            extra_path = root / 'bindings/z-workload.json'
            extra_path.write_text(json.dumps(extra))
            self.assertEqual(probe.current_bindings(root, 'cr-uid'), result)
            extra_path.write_text(json.dumps({**extra, 'initdata_sha384': 'conflicting'}))
            with self.assertRaisesRegex(ValueError, 'conflicting current role'):
                probe.current_bindings(root, 'cr-uid')
            extra_path.unlink()
            (root / 'revoking/workload').touch()
            with self.assertRaisesRegex(ValueError, 'both current role'):
                probe.current_bindings(root, 'cr-uid')
