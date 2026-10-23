#!/usr/bin/env python3
"""Enable/disable optional historical appraisals on the Trustee or driver host."""
import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
ACL = '  { role = "confidential-openshell", allowed_endpoints = "^/kbs/v0/external/attestation-reports/[0-9a-f]{96}$" }, # attestation-observer\n'
PLUGIN = '\n# BEGIN attestation-observer\n[[plugins]]\nname = "external"\nbackends = [{ name = "attestation-reports", endpoint = "http://127.0.0.1:50005", timeout_ms = 2000 }]\n# END attestation-observer\n'


def configure(text, enabled):
    """Preserve operator config text; only change our exact marked additions."""
    clean = text.replace(ACL, '')
    clean = re.sub(r'\n# BEGIN attestation-observer\n.*?# END attestation-observer\n', '', clean, flags=re.S)
    if not enabled:
        tomllib.loads(clean)
        return clean
    parsed = tomllib.loads(clean)
    if any(p.get('name') == 'external' for p in parsed.get('plugins', [])):
        raise ValueError('An external plugin is already configured; merge the attestation-reports backend and scoped ACL manually (see docs/attestation-records.md).')
    storage = parsed.get('session_storage_type', parsed.get('storage_backend', {}).get('storage_type'))
    # This installer supports the repository deployment layout only.
    if storage != 'LocalFs' or parsed.get('storage_backend', {}).get('backends', {}).get('local_fs', {}).get('dir_path') != '/opt/trustee/kbs/storage':
        raise ValueError('Custom session storage requires an explicit observer mount; see docs/attestation-records.md.')
    if parsed.get('admin', {}).get('authorization_mode') != 'AuthenticatedAuthorization':
        raise ValueError('Report queries require authenticated KBS administration.')
    anchor = '[admin.authorization.regex_acl]\nacls = [\n'
    if clean.count(anchor) != 1:
        raise ValueError('Expected the repository regex ACL layout; merge the scoped ACL manually.')
    result = clean.replace(anchor, anchor + ACL) + PLUGIN
    tomllib.loads(result)
    return result


def atomic(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def install_binary(source, target):
    # Rename permits repeat installation while the previous executable is running.
    fd, name = tempfile.mkstemp(dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output, source.open('rb') as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def prepare_sessions(path, *, owner_uid=0):
    # World-readable session files are safe only beneath this private, root-owned
    # parent. Check before creating/exposing the namespace to the observer.
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner_uid or stat.S_IMODE(parent.st_mode) != 0o700:
        owner = 'root' if owner_uid == 0 else f'UID {owner_uid}'
        raise ValueError(f'KBS storage parent must be a real directory owned by {owner} with mode 0700.')
    if not path.exists():
        path.mkdir(mode=0o755)
        # ./cos uses umask 077; only this namespace is readable through the bind.
        path.chmod(0o755)
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o005 != 0o005:
        raise ValueError('Session namespace must be a readable directory in the private observer mount; inspect storage permissions.')
    if any(p.is_file() and p.stat().st_mode & 0o004 == 0 for p in path.iterdir()):
        raise ValueError('Session records are not readable by the observer; inspect the KBS file creation permissions.')


def systemctl(*args):
    subprocess.run(['systemctl', *args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', choices=['trustee', 'gateway'])
    parser.add_argument('--disable', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the selected host.')
    if args.host == 'gateway':
        path = Path('/etc/systemd/system/openshell-confidential-driver.service.d/attestation-reports.conf')
        atomic(path, '[Service]\nEnvironment=OPENSHELL_ATTESTATION_REPORTS=' + ('false' if args.disable else 'true') + '\n', 0o644)
        systemctl('daemon-reload')
        systemctl('try-restart', 'openshell-confidential-driver.service')
        print('Driver report display ' + ('disabled.' if args.disable else 'enabled.'))
        return
    path = Path('/etc/trustee/kbs-config.toml')
    original = path.read_text()
    updated = configure(original, not args.disable)
    ordering = Path('/etc/systemd/system/kbs.service.d/attestation-reports.conf')
    if not args.disable:
        binary = Path(os.environ.get('HANDOFF', '/var/lib/openshell-confidential/operator/handoff')) / 'outputs/openshell-attestation-observer'
        if not binary.is_file():
            binary = ROOT / 'artifacts/openshell-attestation-observer'
        if not binary.is_file():
            raise SystemExit('Observer binary missing; run ./cos build driver and install its release first.')
        public_key = Path('/etc/trustee/tls/as-token-public.pem')
        if not public_key.is_file():
            raise SystemExit('Existing AS public signing key is required.')
        sessions = Path('/opt/trustee/kbs/storage/kbs_protocol_session')
        prepare_sessions(sessions)
        install_binary(binary, Path('/usr/local/bin/openshell-attestation-observer'))
        shutil.copyfile(ROOT / 'deployment/trustee/units/attestation-observer.service', '/etc/systemd/system/attestation-observer.service')
        atomic(ordering, '[Unit]\nWants=attestation-observer.service\nAfter=attestation-observer.service\n', 0o644)
        systemctl('daemon-reload')
        systemctl('enable', 'attestation-observer.service')
        systemctl('restart', 'attestation-observer.service')
    atomic(path, updated)
    if args.disable:
        ordering.unlink(missing_ok=True)
        systemctl('daemon-reload')
    try:
        systemctl('try-restart', 'kbs.service')
    except subprocess.CalledProcessError:
        atomic(path, original)
        systemctl('try-restart', 'kbs.service')
        raise
    if args.disable:
        systemctl('disable', '--now', 'attestation-observer.service')
    print('Trustee report plugin ' + ('disabled; reduced history retained.' if args.disable else 'enabled; existing KBS HTTPS/admin identity retained.'))


if __name__ == '__main__':
    main()
