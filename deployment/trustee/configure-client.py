#!/usr/bin/env python3
"""Connect the driver to a dedicated, authenticated Trustee management endpoint."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from admin_client import AdminClient, atomic_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--ca', required=True, type=Path)
    parser.add_argument('--admin-key', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run this installation step as root')
    root = Path('/etc/openshell-confidential')
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    if subprocess.run(['id', 'openshell-gateway'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run(['useradd', '--system', '--home-dir', '/var/lib/openshell-confidential',
                        '--shell', '/usr/sbin/nologin', 'openshell-gateway'], check=True)
    shutil.chown(root, user='root', group='openshell-gateway')
    config = root / 'trustee-client.json'
    settings = {'kbs_url': args.url.rstrip('/'), 'ca_cert': str(args.ca.resolve()),
                'admin_key': str(args.admin_key.resolve()), 'exclusive_policy_owner': True}
    pending = root / '.trustee-client.json.pending'
    atomic_json(pending, settings)
    try:
        # Check the supplied material before replacing an existing identity.
        AdminClient(pending).request('GET', 'resource-policy')
        for source, destination in [(args.ca, root / 'trustee-ca.pem'), (args.admin_key, root / 'trustee-admin.key')]:
            if source.resolve() != destination.resolve():
                shutil.copyfile(source, destination)
            destination.chmod(0o640)
            shutil.chown(destination, user='root', group='openshell-gateway')
        settings.update(ca_cert=str(root / 'trustee-ca.pem'), admin_key=str(root / 'trustee-admin.key'))
        atomic_json(pending, settings)
        pending.chmod(0o640)
        shutil.chown(pending, user='root', group='openshell-gateway')
        os.replace(pending, config)
    finally:
        pending.unlink(missing_ok=True)
    print('Trustee management authentication verified; client configuration: ' + str(config))


if __name__ == '__main__':
    main()
