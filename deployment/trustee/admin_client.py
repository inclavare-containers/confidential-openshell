"""Authenticated official KBS management API; no access to Trustee storage files."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

RESOURCE = re.compile(r"resource/default/(?:bootstrap/[0-9a-f]{64}|workspace/[0-9a-f]{64}|bootstrap-signer/key)\Z")
DENY = b"package policy\ndefault allow = false\n"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Trustee management redirects are not allowed')


class AdminClient:
    def __init__(self, config: Path):
        settings = json.loads(config.read_text())
        self.endpoint = settings['kbs_url'].rstrip('/')
        address = urllib.parse.urlsplit(self.endpoint)
        if (address.scheme != 'https' or not address.hostname or address.username or address.password
                or address.path or address.query or address.fragment):
            raise ValueError('kbs_url must be an HTTPS origin')
        if settings.get('exclusive_policy_owner') is not True:
            raise ValueError('this driver requires exclusive ownership of the KBS resource policy and AS default policy')
        self.key = serialization.load_pem_private_key(Path(settings['admin_key']).read_bytes(), password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey) or self.key.curve.name != 'secp256r1':
            raise ValueError('KBS admin key must be a P-256 PEM private key')
        self.context = ssl.create_default_context(cafile=settings['ca_cert'])
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
        self.deadline = time.monotonic() + 120

    def request(self, method: str, path: str, body: bytes | None = None, *, json_body=False) -> bytes:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Trustee management operation exceeded 120 seconds; retry is safe')
        now = int(time.time())
        header = {'alg': 'ES256', 'typ': 'JWT'}
        claims = {'iss': 'confidential-openshell-driver', 'aud': 'kbs-admin',
                  'role': 'confidential-openshell', 'nbf': now - 10, 'exp': now + 120}
        unsigned = b64(json.dumps(header).encode()) + '.' + b64(json.dumps(claims).encode())
        r, s = utils.decode_dss_signature(self.key.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256())))
        token = unsigned + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
        request = urllib.request.Request(self.endpoint + '/kbs/v0/' + path, data=body, method=method,
            headers={'Authorization': 'Bearer ' + token,
                     'Content-Type': 'application/json' if json_body else 'application/octet-stream'})
        try:
            with self.opener.open(request, timeout=min(10, remaining)) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if method == 'DELETE' and error.code == 404:
                return b''
            # Error bodies can include request material; keep diagnostics bounded and secret-free.
            raise RuntimeError(f'Trustee {method} {path}: HTTP {error.code}') from None
        except urllib.error.URLError as error:
            raise RuntimeError(f'Trustee {method} {path}: connection or TLS failure') from error

    def policy(self, value: bytes, *, attestation=False) -> None:
        body = {'policy': b64(value)}
        if attestation:
            body['policy_id'] = 'default_cpu'
        self.request('POST', 'attestation-policy' if attestation else 'resource-policy',
                     json.dumps(body).encode(), json_body=True)


def staged_resources(directory: Path) -> dict[str, bytes]:
    result = {}
    for file in directory.iterdir():
        if file.name.startswith('.'):
            continue
        name = file.name
        if name == 'bootstrap-signer-key':
            resource = 'resource/default/bootstrap-signer/key'
        elif re.fullmatch(r'(bootstrap|workspace)-[0-9a-f]{64}', name):
            kind, identity = name.split('-', 1)
            resource = f'resource/default/{kind}/{identity}'
        else:
            raise ValueError('unexpected resource in private publication staging')
        if file.is_symlink() or not file.is_file():
            raise ValueError('publication staging must contain regular files')
        result[resource] = file.read_bytes()
    return result


def synchronize(client: AdminClient, resources: dict[str, bytes], policy: bytes,
                as_policy: bytes, journal_path: Path) -> None:
    # The HTTP publisher owns this lock itself. If its parent driver dies,
    # a replacement cannot overtake the still-running publisher subprocess.
    journal_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with journal_path.with_suffix('.lock').open('a') as lock:
        deadline = time.monotonic() + 120
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('previous Trustee publication is still running')
                time.sleep(.05)
        _synchronize_locked(client, resources, policy, as_policy, journal_path)


def _synchronize_locked(client: AdminClient, resources: dict[str, bytes], policy: bytes,
                        as_policy: bytes, journal_path: Path) -> None:
    state = json.loads(journal_path.read_text()) if journal_path.exists() else {
        'endpoint': client.endpoint, 'resources': {}, 'initialized': False}
    if state['endpoint'] != client.endpoint:
        raise ValueError('Trustee endpoint differs from the publication journal; use a separate deployment state')
    if not all(RESOURCE.fullmatch(path) for path in resources.keys() | state['resources'].keys()):
        raise ValueError('publication contains an unowned resource path')
    if not state.get('initialized'):
        # Stock KBS policy is broader than this deployment. Close it before the
        # first resource is uploaded, including on retry after a lost response.
        client.policy(DENY)
        state['initialized'] = True
        atomic_json(journal_path, state)
    for path in sorted(state['resources'].keys() - resources.keys()):
        client.request('DELETE', path)
        del state['resources'][path]
        atomic_json(journal_path, state)
    for path, contents in sorted(resources.items()):
        digest = hashlib.sha256(contents).hexdigest()
        if state['resources'].get(path) == digest:
            continue
        # Record the cleanup obligation before HTTP: POST may succeed while its
        # response is lost. A later rollback must still DELETE this resource.
        state['resources'][path] = None
        atomic_json(journal_path, state)
        client.request('POST', path, contents)
        state['resources'][path] = digest
        atomic_json(journal_path, state)
    for key, contents, attestation in [('as_policy', as_policy, True), ('policy', policy, False)]:
        digest = hashlib.sha256(contents).hexdigest()
        if state.get(key) != digest:
            client.policy(contents, attestation=attestation)
            state[key] = digest
            atomic_json(journal_path, state)
