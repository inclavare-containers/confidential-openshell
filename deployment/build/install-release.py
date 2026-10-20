#!/usr/bin/env python3
"""Install a local build handoff, or authenticate a handoff transferred from another host."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(prog='./cos release install', description=__doc__)
    parser.add_argument('--handoff', type=Path, help='Transferred handoff directory; default: this checkout\'s artifacts/handoff.')
    parser.add_argument('--sha256', help='SHA256SUMS checksum retained on the build host; prompted for transferred releases.')
    args = parser.parse_args()
    source = (args.handoff or ROOT / 'artifacts/handoff').resolve()
    if args.sha256:
        expected = args.sha256
    elif args.handoff is None and (ROOT / 'artifacts/handoff.sha256').is_file():
        expected = (ROOT / 'artifacts/handoff.sha256').read_text().strip()
    else:
        expected = input('SHA256SUMS checksum retained on the trusted build host: ').strip()
    checksum = hashlib.sha256((source / 'SHA256SUMS').read_bytes()).hexdigest()
    if expected != checksum:
        raise SystemExit('Handoff checksum differs from the build record; nothing was installed.')
    subprocess.run(['sha256sum', '-c', 'SHA256SUMS', '--quiet'], cwd=source, check=True)
    target = Path(os.environ.get('HANDOFF', '/var/lib/openshell-confidential/operator/handoff')).resolve()
    if source != target:
        if target.exists():
            if hashlib.sha256((target / 'SHA256SUMS').read_bytes()).hexdigest() != expected:
                raise SystemExit(f'{target} contains another release. Keep its deployment state; use a separate handoff directory.')
            subprocess.run(['sha256sum', '-c', 'SHA256SUMS', '--quiet'], cwd=target, check=True)
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copytree(source, target)
            target.chmod(0o700)
    subprocess.run(['bash', str(ROOT / 'deployment/build/unpack-release.sh'), str(target), expected], check=True)
    print('Release installed. Continue from /opt/confidential-openshell; the build checkout stays unchanged.', flush=True)


if __name__ == '__main__':
    main()
