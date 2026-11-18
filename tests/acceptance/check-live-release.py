#!/usr/bin/env python3
"""Check real AS sessions and KBS role isolation. Run on a trusted, co-located AS/KBS/driver host.

Optionally stops the named sandbox through the native CLI to check revocation.
Uses naturally issued sessions; never issues auth/attest, prints a token, or reads
resource response bodies. Requires root and python3-cryptography. Evidence is private.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def verify_ear(token, public_key):
    header, payload, signature = token.split('.')
    if json.loads(decode(header)).get('alg') != 'ES256':
        raise ValueError('unexpected signature algorithm')
    raw = decode(signature)
    if len(raw) != 64:
        raise ValueError('invalid signature size')
    public_key.verify(utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
                      (header + '.' + payload).encode(), ec.ECDSA(hashes.SHA256()))
    claims = json.loads(decode(payload))
    if claims.get('iat', time.time() + 60) > time.time() + 30 or claims.get('exp', 0) <= time.time() + 5:
        raise ValueError('expired or future EAR')
    cpu = claims['submods']['cpu0']
    if cpu.get('ear_status') != 'affirming' or cpu.get('ear_appraisal_policy_ids') != ['openshell-tdx']:
        raise ValueError('non-affirming appraisal')
    vector = cpu.get('ear_trustworthiness_vector', {})
    if any(vector.get(key) != value for key, value in {'hardware': 2, 'configuration': 2, 'executables': 3, 'file-system': 2}.items()):
        raise ValueError('unexpected trust vector')
    evidence = cpu['ear_attester_claims']
    if evidence['tee'] != 'tdx' or not isinstance(cpu['ear_verifier_claims']['runtime_data'].get('tee-pubkey'), dict):
        raise ValueError('missing guest recipient key')
    events = [e.get('details', {}).get('data', {}) for e in evidence['claims']['uefi_event_logs']
              if e.get('type_name') == 'EV_EVENT_TAG' and e.get('details', {}).get('unicode_name') == 'AAEL'
              and e.get('details', {}).get('data', {}).get('operation') == 'InitData']
    if len(events) != 1 or events[0].get('domain') != 'github.com/confidential-containers':
        raise ValueError('unexpected initdata event')
    encoded_digest = events[0].get('content', {}).get('digest', '')
    if not re.fullmatch('sha384:[0-9a-f]{96}', encoded_digest):
        raise ValueError('invalid initdata digest')
    return encoded_digest.removeprefix('sha384:')


def current_bindings(state, uid):
    active = [json.loads(p.read_text()) for p in (state / 'active-attempts').glob('*.json')]
    active = [a for a in active if a['sandbox_cr_uid'] == uid]
    if len(active) != 1:
        raise ValueError('no unique active trusted attempt; start the sandbox first')
    active = active[0]
    result = {}
    for path in sorted((state / 'bindings').glob('*.json')):
        row = json.loads(path.read_text())
        if (row['sandbox_cr_uid'], row['sandbox_id'], row['attempt_id'], row['generation']) != (
                uid, active['sandbox_id'], active['attempt'], active['generation']):
            continue
        if any((state / name / row['identity_sha256']).exists() for name in ('revoked', 'revoking')):
            continue
        # Retain only identifiers needed for the probe, never resource keys.
        record = {key: row[key] for key in ('role', 'sandbox_id', 'resource_path', 'initdata_sha384', 'attempt_id', 'generation')}
        if row['role'] in result:
            # One measured role legitimately owns several sealed bootstrap files.
            # Select one stable resource for the allow/cross-role comparison,
            # while rejecting inconsistent identity or measurement metadata.
            if any(result[row['role']][key] != record[key] for key in
                   ('role', 'sandbox_id', 'initdata_sha384', 'attempt_id', 'generation')):
                raise ValueError('conflicting current role bindings')
            continue
        result[row['role']] = record
    if set(result) != {'supervisor', 'workload'}:
        raise ValueError('both current role bindings are required')
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def journal(*args):
    return subprocess.check_output(['journalctl', '-u', 'kbs.service', '--no-pager', '-o', 'cat', *args], text=True)


def request(opener, endpoint, resource, token, allowed):
    cursor = re.search(r'^-- cursor: (.+)$', journal('-n', '1', '--show-cursor'), re.M)
    if cursor is None:
        raise ValueError('KBS journal cursor unavailable')
    req = Request(endpoint.rstrip('/') + '/kbs/v0/' + resource, headers={'Authorization': 'Bearer ' + token})
    try:
        with opener.open(req, timeout=10) as response:
            code = response.status
    except HTTPError as error:
        code = error.code
        error.close()
    time.sleep(0.3)
    log = journal('--after-cursor', cursor[1])
    if any(error in log for error in ('PolicyEngineError', 'TokenVerifierError', 'ParsePolicyError', 'LoadPolicyFailed')):
        raise ValueError('KBS policy or token processing failed')
    if allowed and code != 200:
        raise ValueError(f'current role release returned {code}')
    if not allowed and not (code in (401, 403) or (code == 500 and 'PolicyDeny' in log)):
        raise ValueError(f'cross-role request lacked a policy denial (HTTP {code})')
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', required=True, help='Current sandbox Kubernetes CR UID')
    parser.add_argument('--driver-state', type=Path, default=Path('/var/lib/openshell-confidential/driver'))
    parser.add_argument('--sessions', type=Path, default=Path('/opt/trustee/kbs/storage/kbs_protocol_session'))
    parser.add_argument('--as-public-key', type=Path, default=Path('/etc/trustee/tls/as-token-public.pem'))
    parser.add_argument('--trustee-client', type=Path, default=Path('/etc/openshell-confidential/trustee-client.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--stop-sandbox', help='Stop this native sandbox after capturing current sessions, then check revocation before token expiry')
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        parser.error('run as root on the trusted host')
    args.output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if args.output.exists() or args.output.parent.stat().st_mode & 0o077:
        parser.error('use a new output file in a mode-0700 evidence directory')
    rows = current_bindings(args.driver_state, args.uid)
    client = json.loads(args.trustee_client.read_text())
    if not client['kbs_url'].startswith('https://'):
        raise ValueError('KBS must use HTTPS')
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=client['ca_cert'])))
    public_key = serialization.load_pem_public_key(args.as_public_key.read_bytes())
    results, tokens = {}, {}
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and len(results) < 2:
        for path in args.sessions.glob('*'):
            try:
                token = json.loads(path.read_text()).get('Attested', {}).get('token')
                if not token:
                    continue
                digest = verify_ear(token, public_key)
            except (ValueError, KeyError, TypeError, OSError, InvalidSignature):
                continue
            matched = [r for r in rows.values() if r['initdata_sha384'] == digest]
            if len(matched) != 1 or matched[0]['role'] in results:
                continue
            row = matched[0]
            tokens[row['role']] = token
            other = next(r for r in rows.values() if r['role'] != row['role'])
            results[row['role']] = {**row, 'signature_verified': True,
                'own_resource_http': request(opener, client['kbs_url'], row['resource_path'], token, True),
                'other_role_http': request(opener, client['kbs_url'], other['resource_path'], token, False)}
        if len(results) < 2:
            time.sleep(2)
    if len(results) != 2:
        raise ValueError('no unexpired natural sessions for both current roles; recreate the disposable sandbox and repeat')
    if current_bindings(args.driver_state, args.uid) != rows:
        raise ValueError('attempt changed during the probe; repeat on a stable sandbox')
    if args.stop_sandbox:
        native = json.loads(subprocess.check_output(
            ['openshell', 'sandbox', 'get', args.stop_sandbox, '--output', 'json'], text=True, timeout=30))
        if any(row['sandbox_id'] != native['id'] for row in rows.values()):
            raise ValueError('sandbox name does not match the captured trusted identity')
        subprocess.run(['openshell', 'sandbox', 'stop', args.stop_sandbox], check=True, timeout=900)
        for role, row in rows.items():
            verify_ear(tokens[role], public_key)  # Expiry is not revocation evidence.
            results[role]['after_stop_resource_http'] = request(
                opener, client['kbs_url'], row['resource_path'], tokens[role], False)
    output = {'passed': True, 'sandbox_cr_uid': args.uid, 'roles': results,
              'resource_bodies_read': False, 'observed_at': int(time.time())}
    with args.output.open('x') as stream:
        json.dump(output, stream, indent=2)
        stream.write('\n')
    print(f'PASS: signed current TDX sessions and own/cross-role KBS decisions; evidence: {args.output}')


if __name__ == '__main__':
    main()
