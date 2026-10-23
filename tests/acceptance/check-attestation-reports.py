#!/usr/bin/env python3
"""Released KBS/AS + passive observer + Rust driver query, with synthetic signed EAR.

Uses temporary keys and a stock-format session fixture. This is NOT a TDX test.
No cloud resources; services listen on loopback and are stopped on exit.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('api_check', Path(__file__).with_name('check-trustee-api.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def signed(key, digest):
    claims = {'iat': int(time.time()) - 600, 'exp': int(time.time()) - 300, 'submods': {'cpu0': {
        'ear.status': 'affirming', 'ear.appraisal-policy-id': 'default',
        'ear.trustworthiness-vector': {'hardware': 2, 'configuration': 2, 'executables': 3, 'file-system': 2},
        'ear.veraison.annotated-evidence': {'tdx': {'tcb_status': 'UpToDate', 'quote': {'body': {'mr_td': 'b' * 96}},
            'uefi_event_logs': [{'type_name': 'EV_EVENT_TAG', 'details': {'unicode_name': 'AAEL',
                'data': {'domain': 'confidentialcontainers.org', 'operation': 'initdata', 'content': digest}}}]}}
    }}}
    message = '.'.join(h.h.b64url(json.dumps(v).encode()) for v in [{'alg': 'ES256'}, claims])
    r, s = utils.decode_dss_signature(key.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
    return message + '.' + h.h.b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))


def native_cli(cli, condition_path, area):
    """Use the released CLI against a loopback Gateway fixture carrying driver bytes."""
    from concurrent import futures
    import grpc
    import grpc_tools
    from grpc_tools import protoc
    generated = area / 'generated'
    generated.mkdir()
    proto = ROOT / 'repos/openshell/proto'
    assert protoc.main(['protoc', '-I' + str(proto),
        '-I' + str(Path(grpc_tools.__file__).parent / '_proto'),
        '--python_out=' + str(generated), *map(str, proto.glob('*.proto'))]) == 0
    sys.path.insert(0, str(generated))
    import compute_driver_pb2 as driver_pb
    import openshell_pb2 as public_pb
    import sandbox_pb2 as sandbox_pb
    condition = driver_pb.DriverCondition.FromString(condition_path.read_bytes())
    # Same field mapping as upstream public_condition_from_driver; the Gateway
    # here is a fixture, while KBS, observer, driver query and CLI are real code.
    public = public_pb.SandboxCondition(type=condition.type, status=condition.status,
        reason=condition.reason, message=condition.message)
    sandbox = public_pb.Sandbox(metadata={'name': 'report-fixture'}, status={
        'phase': public_pb.SANDBOX_PHASE_READY, 'conditions': [public]})
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers([grpc.method_handlers_generic_handler('openshell.v1.OpenShell', {
        'GetSandbox': grpc.unary_unary_rpc_method_handler(lambda request, context: public_pb.SandboxResponse(sandbox=sandbox),
            request_deserializer=public_pb.GetSandboxRequest.FromString, response_serializer=public_pb.SandboxResponse.SerializeToString),
        'GetSandboxConfig': grpc.unary_unary_rpc_method_handler(lambda request, context: sandbox_pb.GetSandboxConfigResponse(),
            request_deserializer=sandbox_pb.GetSandboxConfigRequest.FromString, response_serializer=sandbox_pb.GetSandboxConfigResponse.SerializeToString),
    })])
    port = server.add_insecure_port('127.0.0.1:0')
    server.start()
    try:
        environment = {k: v for k, v in os.environ.items() if not k.startswith('OPENSHELL_')}
        environment.update(XDG_CONFIG_HOME=str(area / 'cli-config'), OPENSHELL_TELEMETRY_ENABLED='false')
        completed = subprocess.run([str(cli), '--gateway-endpoint', f'http://127.0.0.1:{port}',
            'sandbox', 'get', 'report-fixture', '--output', 'json'], env=environment, capture_output=True, text=True, timeout=20)
        if completed.returncode: raise RuntimeError('native CLI failed: ' + completed.stderr[-2000:])
        value = json.loads(completed.stdout)
        displayed = next(c for c in value['conditions'] if c['type'] == 'WorkloadAttested')
        assert displayed['message'] == condition.message
        assert displayed['status'] == 'True' and displayed['reason'] == 'Attested'
        assert displayed['message'].startswith('Intel TDX · verified by Trustee · TCB up to date · ref ')
        completed = subprocess.run([str(cli), '--gateway-endpoint', f'http://127.0.0.1:{port}',
            'sandbox', 'get', 'report-fixture'], env=environment, capture_output=True, text=True, timeout=20)
        assert completed.returncode == 0, completed.stderr
        lines = [line for line in completed.stdout.splitlines() if 'WorkloadAttested' in line]
        assert len(lines) == 1 and condition.message in lines[0], completed.stdout
    finally:
        server.stop(0).wait()


def check(kbs_root, as_root, observer, cli=None):
    checks = {}
    processes, logs = [], []
    with tempfile.TemporaryDirectory(prefix='cos-reports-') as temp:
        area = Path(temp)
        ca = h.cert(area, 'ca')
        h.cert(area, 'server', ca)
        signer = h.cert(area, 'as', ca)
        admin = h.cert(area, 'admin')
        for name, key in [('admin', admin[0]), ('as', signer[0])]:
            (area / (name + '-public.pem')).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        (area / 'as-chain.pem').write_bytes((area / 'as.pem').read_bytes() + (area / 'ca.pem').read_bytes())
        kbs_port, as_port, plugin_port = h.port(), h.port(), h.port()
        sessions = area / 'storage/kbs_protocol_session'
        sessions.mkdir(parents=True)
        as_config = json.loads((ROOT / 'deployment/trustee/as-config.json').read_text())
        as_config['storage_backend']['backends']['local_fs']['dir_path'] = str(area / 'as-storage')
        as_config['attestation_token_broker']['signer'] = {'key_path': str(area / 'as.key'), 'cert_path': str(area / 'as-chain.pem')}
        (area / 'as.json').write_text(json.dumps(as_config))
        config = (ROOT / 'deployment/trustee/kbs-config.example.toml').read_text()
        config = config.replace('acls = [', 'acls = [\n { role = "confidential-openshell", allowed_endpoints = "^/kbs/v0/external/attestation-reports/[0-9a-f]{96}$" },')
        config += f'\n[[plugins]]\nname = "external"\nbackends = [{{ name = "attestation-reports", endpoint = "http://127.0.0.1:{plugin_port}", timeout_ms = 1000 }}]\n'
        for old, new in {'0.0.0.0:8443': f'127.0.0.1:{kbs_port}', '/etc/trustee/tls/server.key': str(area / 'server.key'),
            '/etc/trustee/tls/server-chain.pem': str(area / 'server.pem'), '/etc/trustee/tls/ca.pem': str(area / 'ca.pem'),
            '/etc/trustee/admin-public.pem': str(area / 'admin-public.pem'), 'http://127.0.0.1:50004': f'http://127.0.0.1:{as_port}',
            '/opt/trustee/kbs/storage': str(area / 'storage')}.items(): config = config.replace(old, new)
        (area / 'kbs.toml').write_text(config)
        client_config = {'kbs_url': f'https://127.0.0.1:{kbs_port}', 'ca_cert': str(area / 'ca.pem'),
                         'admin_key': str(area / 'admin.key'), 'exclusive_policy_owner': True}
        (area / 'client.json').write_text(json.dumps(client_config))
        def launch(name, command):
            log = (area / (name + '.log')).open('wb'); logs.append(log)
            process = subprocess.Popen(command, stdout=log, stderr=log, env={**os.environ, 'RUST_LOG': 'error'})
            processes.append(process)
            return process
        try:
            plugin = launch('observer', [str(observer), '--sessions', str(sessions), '--output', str(area / 'reports'),
                '--as-public-key', str(area / 'as-public.pem'), '--listen', f'127.0.0.1:{plugin_port}', '--interval-seconds', '1'])
            launch('as', h.h.release_command(as_root / 'usr/local/bin/grpc-as', as_root) + ['--config-file', str(area / 'as.json'), '--socket', f'127.0.0.1:{as_port}'])
            launch('kbs', h.h.release_command(kbs_root / 'usr/local/bin/kbs', kbs_root) + ['--config-file', str(area / 'kbs.toml')])
            client = h.AdminClient(area / 'client.json')
            path = 'external/attestation-reports/' + 'a' * 96
            for _ in range(100):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('service exited: ' + '\n'.join(p.read_text()[-3000:] for p in area.glob('*.log')))
                try:
                    value = json.loads(client.request('GET', path))
                    break
                except RuntimeError: time.sleep(.1)
            else: raise AssertionError('KBS plugin not ready')
            assert value['report'] is None
            checks['official_external_plugin_registered_missing_is_null'] = True
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=client.context))
            def anonymous(path, data=None):
                req = urllib.request.Request(client.endpoint + '/kbs/v0/' + path, data=data, headers={'Content-Type': 'application/json'})
                try:
                    with opener.open(req, timeout=3) as response: return response.status, response.read()
                except urllib.error.HTTPError as error: return error.code, error.read()
            assert anonymous(path)[0] in (401, 403)
            checks['anonymous_query_denied'] = True
            wrong = dict(client_config, admin_key=str(area / 'server.key'))
            (area / 'wrong.json').write_text(json.dumps(wrong))
            try: h.AdminClient(area / 'wrong.json').request('GET', path)
            except RuntimeError: checks['wrong_admin_denied'] = True
            else: raise AssertionError('wrong admin accepted')
            status, _ = anonymous('auth', json.dumps({'version': '0.4.0', 'tee': 'tdx', 'extra-params': ''}).encode())
            assert status == 200, status
            authed = [p for p in sessions.iterdir() if 'Authed' in json.loads(p.read_text())]
            assert authed
            assert all(p.stat().st_mode & 0o004 for p in authed), 'private bind mount requires readable session files'
            checks['official_auth_persists_session_in_expected_namespace'] = True
            token = signed(signer[0], 'a' * 96)
            fixture = sessions / 'synthetic-attested-session'
            fixture.write_text(json.dumps({'Attested': {'token': token, 'id': fixture.name, 'timeout': '2099-01-01T00:00:00Z'}}))
            for _ in range(50):
                value = json.loads(client.request('GET', path))
                if value['report']: break
                time.sleep(.1)
            assert value['report']['initdata_sha384'] == 'a' * 96
            assert value['report']['token_expires_at'] < time.time()
            assert value['report']['measurements']['mr_td'] == 'b' * 96
            assert token not in json.dumps(value)
            checks['signed_expired_ear_reduced_and_queried_over_tls'] = True
            before = {p.name: p.read_bytes() for p in sessions.iterdir()}
            client.request('GET', path)
            assert before == {p.name: p.read_bytes() for p in sessions.iterdir()}
            checks['query_does_not_refresh_session_or_attest'] = True
            command = ['cargo', 'test', '--offline', '--locked', '-p', 'openshell-driver-confidential-kubernetes',
                '--lib', 'released_kbs_attestation_report_query', '--', '--ignored']
            completed = subprocess.run(command, cwd=ROOT, env={**os.environ, 'OPENSHELL_TEST_REPORT_CONFIG': str(area / 'client.json'), 'OPENSHELL_TEST_REPORT_CONDITION': str(area / 'condition.pb')}, capture_output=True, text=True)
            if completed.returncode: raise RuntimeError(completed.stdout[-4000:] + completed.stderr[-4000:])
            checks['production_driver_https_query_and_native_conditions'] = True
            if cli:
                native_cli(cli, area / 'condition.pb', area)
                checks['released_cli_json_with_gateway_fixture'] = True
            plugin.terminate(); plugin.wait(timeout=5)
            try: client.request('GET', path)
            except RuntimeError: pass
            else: raise AssertionError('stopped observer query succeeded')
            client.request('GET', 'resource-policy')
            checks['observer_outage_leaves_kbs_management_available'] = True
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
            for log in logs: log.close()
    return {'scope': 'official KBS/AS binaries, synthetic signed session fixture; no hardware attestation', 'checks': checks, 'passed': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kbs-rootfs', type=Path, required=True)
    parser.add_argument('--as-rootfs', type=Path, required=True)
    parser.add_argument('--observer', type=Path, default=ROOT / 'target/debug/openshell-attestation-observer')
    parser.add_argument('--openshell', type=Path, help='Optional released CLI; requires grpcio-tools for the loopback Gateway fixture.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.kbs_rootfs.resolve(), args.as_rootfs.resolve(), args.observer.resolve(), args.openshell.resolve() if args.openshell else None)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
