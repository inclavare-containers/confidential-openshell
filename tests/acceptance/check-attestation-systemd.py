#!/usr/bin/env python3
"""Run the production observer unit with isolated synthetic fixtures (root/systemd).

Requires cryptography and grpcio-tools. Creates a temporary unit and state, then
removes them; existing Trustee, observer and sandbox services are not changed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import grpc
from grpc_tools import protoc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('report_fixture', Path(__file__).with_name('check-attestation-reports.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stdout}\n{result.stderr}')
    return result


def check(observer):
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('Run as root on a host with systemd as PID 1.')
    if not observer.is_file():
        raise RuntimeError(f'Build the observer first: {observer}')
    systemd_version = run('systemctl', '--version').stdout.splitlines()[0]
    base = Path(tempfile.mkdtemp(prefix='cos-observer-test-', dir='/run'))
    name = base.name + '-unit'
    unit = Path('/run/systemd/system') / (name + '.service')
    result = {'scope': 'production systemd unit with synthetic signed sessions; no hardware attestation',
              'systemd_version': systemd_version, 'checks': {}}
    checks = result['checks']
    try:
        base.chmod(0o755)
        private = base / 'private'
        private.mkdir(mode=0o700)
        sessions, public = private / 'sessions', private / 'as-public.pem'
        (private / 'unrelated-secret').write_text('must-not-be-mounted')
        binary = base / 'observer'
        shutil.copyfile(observer, binary)
        binary.chmod(0o755)
        port = fixture.h.port()
        text = (ROOT / 'deployment/trustee/units/attestation-observer.service').read_text()
        # Substitute fixture paths only; preserve every sandbox/readiness directive
        # and the optional-path prefixes, so removing a prefix fails this test.
        for old, new in [
            ('Before=kbs.service\n', ''),
            ('openshell-attestation-observer', name),
            ('/opt/trustee/kbs/storage/kbs_protocol_session', str(sessions)),
            ('/etc/trustee/tls/as-token-public.pem', str(public)),
            ('/opt/trustee', str(private)),
            ('/etc/trustee', str(base / 'absent-trustee-config')),
            ('/etc/openshell-confidential', str(base / 'absent-gateway-config')),
            ('/usr/local/bin/' + name, str(binary)),
            ('--output ', f'--listen 127.0.0.1:{port} --interval-seconds 1 --output '),
        ]:
            text = text.replace(old, new)
        unit.write_text(text)
        run('systemctl', 'daemon-reload')
        verified = run('systemd-analyze', 'verify', str(unit))
        result['unit_verify'] = verified.stdout + verified.stderr
        security = run('systemd-analyze', 'security', name + '.service', check=False)
        result['unit_security'] = {'exit_code': security.returncode, 'output': security.stdout + security.stderr}
        # Older hosts without the security subcommand still run the runtime tests.
        if security.returncode and 'Unknown operation' not in security.stderr:
            raise RuntimeError(result['unit_security']['output'])

        generated = base / 'generated'
        generated.mkdir()
        proto = ROOT / 'components/attestation-observer/proto'
        if protoc.main(['protoc', '-I' + str(proto), '--python_out=' + str(generated),
                        '--grpc_python_out=' + str(generated), str(proto / 'plugin.proto')]):
            raise RuntimeError('Cannot compile plugin protocol')
        sys.path.insert(0, str(generated))
        import plugin_pb2 as pb
        import plugin_pb2_grpc as rpc

        def query(digest='a' * 96):
            with grpc.insecure_channel(f'127.0.0.1:{port}') as channel:
                client = rpc.KbsPluginStub(channel)
                auth = client.ValidateAuth(pb.ValidateAuthRequest(path=[digest], method='GET'), timeout=2)
                assert auth.requires_admin_auth
                response = client.Handle(pb.PluginRequest(path=[digest], method='GET'), timeout=2)
                assert response.status_code in (0, 200)
                return json.loads(response.body)

        def wait_for(predicate, digest='a' * 96):
            deadline = time.monotonic() + 20
            value = None
            while time.monotonic() < deadline:
                try:
                    value = query(digest)
                    if predicate(value):
                        return value
                except grpc.RpcError:
                    pass
                time.sleep(.2)
            raise AssertionError(f'Observer did not reach expected state: {value}')

        def start():
            run('systemctl', 'restart', name)
            assert run('systemctl', 'is-active', name).stdout.strip() == 'active'
            return int(run('systemctl', 'show', name, '--property=MainPID', '--value').stdout)

        def write_public(key, path=public):
            path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo))
            path.chmod(0o644)

        def write_session(key, digit):
            path = sessions / ('fixture-' + digit)
            path.write_text(json.dumps({'Attested': {'token': fixture.signed(key, digit * 96)}}))
            path.chmod(0o644)

        pid = start()
        assert not query()['collection']['available']
        checks['missing_sources_and_unrelated_directories_do_not_block_notify_start'] = True
        key = ec.generate_private_key(ec.SECP256R1())
        write_public(key)
        sessions.mkdir(mode=0o755)
        sessions.chmod(0o755)
        write_session(key, 'a')
        mounted = Path(f'/proc/{pid}/root/run/{name}')
        assert not (mounted / 'as-public.pem').exists() and not (mounted / 'sessions').exists()
        assert not query()['collection']['available']
        pid = start()
        first = wait_for(lambda v: v['collection']['available'] and v['report'])['report']
        assert first['appraisal'] == 'affirming'
        checks['creating_missing_sources_requires_restart_then_recovers'] = True

        proc = Path('/proc') / str(pid)
        uid = int(next(line.split()[1] for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:')))
        assert uid != 0
        assert not (proc / 'root' / private.relative_to('/') / 'unrelated-secret').exists()
        mountinfo = (proc / 'mountinfo').read_text().splitlines()
        for suffix in ('sessions', 'as-public.pem'):
            mount = next(line.split() for line in mountinfo if line.split()[4] == f'/run/{name}/{suffix}')
            assert 'ro' in mount[5].split(',')
        checks['nonroot_observer_reads_only_narrow_readonly_mounts'] = True
        for setting, expected in [('Type', 'notify'), ('MemoryDenyWriteExecute', 'yes'),
                                  ('ProtectKernelTunables', 'yes'), ('ProtectKernelModules', 'yes'),
                                  ('ProtectControlGroups', 'yes'), ('LockPersonality', 'yes')]:
            assert run('systemctl', 'show', name, '--property=' + setting, '--value').stdout.strip() == expected
        for setting in ('SystemCallFilter', 'IPAddressDeny', 'IPAddressAllow'):
            value = run('systemctl', 'show', name, '--property=' + setting, '--value').stdout.strip()
            assert value, setting
            result[setting] = value
        checks['full_hardening_configuration_runs_real_plugin_queries'] = True

        public.write_text('invalid verification key')
        start()
        assert not query()['collection']['available']
        assert query()['report'] == first
        write_public(key)
        wait_for(lambda v: v['collection']['available'])
        checks['invalid_key_keeps_service_and_history_inplace_repair_recovers'] = True

        new_key = ec.generate_private_key(ec.SECP256R1())
        replacement = private / 'replacement.pem'
        write_public(new_key, replacement)
        replacement.replace(public)
        write_session(new_key, 'b')
        pid = int(run('systemctl', 'show', name, '--property=MainPID', '--value').stdout)
        mounted_key = Path(f'/proc/{pid}/root/run/{name}/as-public.pem')
        assert mounted_key.stat().st_ino != public.stat().st_ino
        scanned = query()['collection']['last_scan_at']
        value = wait_for(lambda v: v['collection']['last_scan_at'] > scanned, 'b' * 96)
        assert value['report'] is None
        start()
        wait_for(lambda v: v['collection']['available'] and v['report'], 'b' * 96)
        checks['atomic_key_rotation_requires_restart_then_new_signature_is_accepted'] = True

        # Exercise each missing mount independently after history exists.
        for source in (public, sessions):
            run('systemctl', 'stop', name)
            saved = source.with_name(source.name + '.saved')
            source.rename(saved)
            try:
                start()
                assert not query()['collection']['available']
                assert query()['report'] == first
            finally:
                run('systemctl', 'stop', name)
                saved.rename(source)
        start()
        wait_for(lambda v: v['collection']['available'])
        checks['each_missing_source_preserves_history_and_plugin_availability'] = True
    except Exception:
        print(run('journalctl', '-u', name, '--no-pager', '-n', '40', check=False).stdout, file=sys.stderr)
        raise
    finally:
        run('systemctl', 'stop', name, check=False)
        unit.unlink(missing_ok=True)
        run('systemctl', 'reset-failed', name, check=False)
        run('systemctl', 'daemon-reload')
        for path in (Path('/var/lib') / name, Path('/var/lib/private') / name, Path('/run') / name):
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
        if base.exists():
            shutil.rmtree(base)
    checks['temporary_unit_and_state_removed'] = True
    result['passed'] = True
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observer', type=Path, default=ROOT / 'target/debug/openshell-attestation-observer')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.observer.resolve())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['checks'], indent=2))
