#!/usr/bin/env python3
"""Prepare a release guest for local Kata and print its qemu-tdx TOML drop-in."""
import argparse
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('qcow2', type=Path)
    parser.add_argument('directory', type=Path, help='new guest directory at the same path on every worker')
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=directory.parent) as scratch:
        new = Path(scratch) / 'guest'
        new.mkdir()
        disk = new / 'system.raw'
        uki = new / 'system.efi'
        subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', args.qcow2, disk], check=True)
        table = json.loads(subprocess.check_output(['sfdisk', '--json', disk]))['partitiontable']
        partitions = {entry['type'].lower(): entry for entry in table['partitions']}
        esp = partitions['c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
        offset = esp['start'] * table.get('sectorsize', 512)
        subprocess.run(['mcopy', '-i', f'{disk}@@{offset}', '::/EFI/BOOT/BOOTX64.EFI', uki], check=True)
        embedded = subprocess.check_output(['objcopy', '-O', 'binary', '-j', '.cmdline', uki, '/dev/stdout'])
        cmdline = embedded.rstrip(b'\0').decode()
        # The UKI initrd locates the two verity partitions by the embedded roothash.
        cmdline += (' systemd.mask=systemd-resolved.service'
                    ' root=/dev/mapper/root rootfstype=squashfs')
        new.rename(directory)
    print('[hypervisor.qemu]')
    print('kernel =', json.dumps(str(directory / 'system.efi')))
    print('image =', json.dumps(str(directory / 'system.raw')))
    # Clear the packaged Kata image's dm-verity table; the UKI initrd builds its own.
    print('kernel_verity_params = ""')
    print('kernel_params =', json.dumps(cmdline))


if __name__ == '__main__':
    main()
