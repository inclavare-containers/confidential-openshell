#!/usr/bin/env python3
"""Local released Trustee integration: TLS/admin auth, RVPS, publication and revoke.

Uses temporary certificates and synthetic EAR claims, not hardware attestation.
Both official processes listen only on loopback and are stopped on exit.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deployment/trustee'))
from admin_client import AdminClient, synchronize
spec = importlib.util.spec_from_file_location('policy_check', Path(__file__).with_name('check-policy-denials.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def cert(area, name, parent=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(parent[1].subject if parent else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=parent is None, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False))
    certificate = builder.sign(parent[0] if parent else key, hashes.SHA256())
    (area / (name + '.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (area / (name + '.pem')).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key, certificate


def signed(issuer, parent, tee):
    numbers = issuer[0].public_key().public_numbers()
    jwk = {'kty': 'EC', 'alg': 'ES256', 'crv': 'P-256',
           'x': h.b64url(numbers.x.to_bytes(32, 'big')), 'y': h.b64url(numbers.y.to_bytes(32, 'big')),
           'x5c': [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in [issuer[1], parent[1]]]}
    return h.signed_token(issuer[0], jwk, tee, 'a' * 96)


def check(kbs_root, as_root):
    processes = []
    logs = []
    result = {'scope': 'released KBS/AS management API with synthetic EAR; no TDX quote', 'checks': {}}
    with tempfile.TemporaryDirectory(prefix='cos-trustee-api-') as temp:
        area = Path(temp)
        ca = cert(area, 'tls-ca')
        server = cert(area, 'server', ca)
        as_ca = cert(area, 'as-ca')
        signer = cert(area, 'as-signer', as_ca)
        admin_key, _ = cert(area, 'admin')
        (area / 'admin-public.pem').write_bytes(admin_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        (area / 'as-chain.pem').write_bytes((area / 'as-signer.pem').read_bytes() + (area / 'as-ca.pem').read_bytes())
        kbs_port, as_port = port(), port()
        as_config = json.loads((ROOT / 'deployment/trustee/as-config.json').read_text())
        as_config['storage_backend']['backends']['local_fs']['dir_path'] = str(area / 'as-storage')
        as_config['attestation_token_broker']['signer'] = {'key_path': str(area / 'as-signer.key'), 'cert_path': str(area / 'as-chain.pem')}
        (area / 'as.json').write_text(json.dumps(as_config))
        config = (ROOT / 'deployment/trustee/kbs-config.example.toml').read_text()
        for old, new in {
            '0.0.0.0:8443': f'127.0.0.1:{kbs_port}', '/etc/trustee/tls/server.key': str(area / 'server.key'),
            '/etc/trustee/tls/server-chain.pem': str(area / 'server.pem'), '/etc/trustee/tls/ca.pem': str(area / 'as-ca.pem'),
            '/etc/trustee/admin-public.pem': str(area / 'admin-public.pem'),
            'http://127.0.0.1:50004': f'http://127.0.0.1:{as_port}', '/opt/trustee/kbs/storage': str(area / 'kbs-storage')}.items():
            config = config.replace(old, new)
        (area / 'kbs.toml').write_text(config)
        client_config = {'kbs_url': f'https://127.0.0.1:{kbs_port}', 'ca_cert': str(area / 'tls-ca.pem'),
                         'admin_key': str(area / 'admin.key'), 'exclusive_policy_owner': True}
        (area / 'client.json').write_text(json.dumps(client_config))
        try:
            for root, binary, args in [(as_root, 'grpc-as', ['--config-file', str(area / 'as.json'), '--socket', f'127.0.0.1:{as_port}']),
                                       (kbs_root, 'kbs', ['--config-file', str(area / 'kbs.toml')])]:
                log = (area / (binary + '.log')).open('wb'); logs.append(log)
                processes.append(subprocess.Popen(h.release_command(root / 'usr/local/bin' / binary, root) + args,
                    stdout=log, stderr=log, env={**os.environ, 'RUST_LOG': 'error'}))
            client = AdminClient(area / 'client.json')
            for _ in range(100):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('released service failed: ' + '\n'.join((area / (n + '.log')).read_text()[-3000:] for n in ['kbs', 'grpc-as']))
                try:
                    client.request('GET', 'resource-policy')
                    break
                except RuntimeError:
                    time.sleep(.1)
            else:
                raise RuntimeError('KBS did not become ready')
            result['checks']['admin_authentication'] = True
            url = client.endpoint + '/kbs/v0/resource/default/bootstrap/' + 'a' * 64
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=client.context))
            def get(token=None):
                req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token} if token else {})
                try:
                    with opener.open(req, timeout=5) as response:
                        return response.status, response.read()
                except urllib.error.HTTPError as error:
                    return error.code, error.read()
            assert get()[0] == 401
            result['checks']['anonymous_denied'] = True
            bad = dict(client_config, admin_key=str(area / 'server.key'))
            (area / 'bad.json').write_text(json.dumps(bad))
            try:
                AdminClient(area / 'bad.json').request('GET', 'resource-policy')
                raise AssertionError('wrong admin key accepted')
            except RuntimeError as error:
                assert 'HTTP 401' in str(error) or 'HTTP 403' in str(error), error
            result['checks']['wrong_admin_denied'] = True
            policy = b'package policy\ndefault allow = false\nallow if { input.submods.cpu0["ear.status"] == "affirming" }\n'
            as_policy = b'package policy\ndefault hardware = 0\n'
            resource = 'resource/default/bootstrap/' + 'a' * 64
            fixture = b'synthetic-resource-via-admin-api'
            journal = area / 'driver-private' / 'publication.json'
            synchronize(client, {resource: fixture}, policy, as_policy, journal)
            result['checks']['resource_and_as_policy_published'] = True
            # The actual deployment reference registration path, through KBS.
            refs = area / 'refs.json'
            refs.write_text(json.dumps({'measurement.test.image.sha384': ['a' * 96]}))
            subprocess.run([sys.executable, str(ROOT / 'deployment/trustee/register-references.py'),
                '--trustee-config', str(area / 'client.json'), '--references', str(refs)], check=True, capture_output=True)
            result['checks']['rvps_register_readback'] = True
            recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            nums = recipient.public_key().public_numbers()
            tee = {'kty': 'RSA', 'alg': 'RSA-OAEP-256',
                   'n': h.b64url(nums.n.to_bytes((nums.n.bit_length()+7)//8, 'big')), 'e': h.b64url(nums.e.to_bytes(3, 'big'))}
            token = signed(signer, as_ca, tee)
            status, body = get(token)
            assert status == 200, (status, body)
            jwe = json.loads(body)
            cek = recipient.decrypt(h.unb64url(jwe['encrypted_key']), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
            assert AESGCM(cek).decrypt(h.unb64url(jwe['iv']), h.unb64url(jwe['ciphertext']) + h.unb64url(jwe['tag']), jwe['protected'].encode()) == fixture
            result['checks']['approved_signer_resource_decrypted'] = True
            assert get(signed(server, ca, tee))[0] == 401
            result['checks']['tls_signer_not_as_signer'] = True
            wrong_ca = dict(client_config, ca_cert=str(area / 'as-ca.pem'))
            (area / 'wrong-ca.json').write_text(json.dumps(wrong_ca))
            try:
                AdminClient(area / 'wrong-ca.json').request('GET', 'resource-policy')
                raise AssertionError('wrong server CA accepted')
            except RuntimeError:
                pass
            result['checks']['wrong_server_ca_denied'] = True
            synchronize(client, {}, b'package policy\ndefault allow = false\n', as_policy, journal)
            assert get(token)[0] != 200
            result['checks']['revocation_denies_previous_token'] = True
            # Exercise the production Rust store + renderer + API client, with
            # its staging directory separate from both server storage roots.
            driver_state = area / 'driver-state'
            driver_env = {**os.environ, 'OPENSHELL_TEST_API_STATE': str(driver_state),
                          'OPENSHELL_TEST_TRUSTEE_CONFIG': str(area / 'client.json')}
            command = ['cargo', 'test', '--offline', '--locked', '-p', 'openshell-driver-confidential-kubernetes',
                       '--lib', 'released_trustee_api_driver_publication', '--', '--ignored', '--exact']
            # Match the single test by its suffix (without --exact).
            command.remove('--exact')
            completed = subprocess.run(command, cwd=ROOT, env=driver_env, capture_output=True, text=True)
            if completed.returncode:
                raise RuntimeError(completed.stdout[-6000:] + completed.stderr[-6000:])
            path = json.loads((driver_state / 'receipt.json').read_text())['resource_path']
            url = client.endpoint + '/kbs/v0/' + path
            status, body = get(token)
            assert status == 200, (status, body)
            jwe = json.loads(body)
            cek = recipient.decrypt(h.unb64url(jwe['encrypted_key']), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
            assert AESGCM(cek).decrypt(h.unb64url(jwe['iv']), h.unb64url(jwe['ciphertext']) + h.unb64url(jwe['tag']), jwe['protected'].encode()) == b'driver-api-integration-fixture'
            completed = subprocess.run(command, cwd=ROOT, env={**driver_env, 'OPENSHELL_TEST_API_ACTION': 'revoke'}, capture_output=True, text=True)
            if completed.returncode:
                raise RuntimeError(completed.stdout[-6000:] + completed.stderr[-6000:])
            assert get(token)[0] != 200
            result['checks']['rust_store_publish_restart_revoke'] = True
            result['passed'] = True
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            for log in logs:
                log.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kbs-rootfs', type=Path, required=True)
    parser.add_argument('--as-rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.kbs_rootfs.resolve(), args.as_rootfs.resolve())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
