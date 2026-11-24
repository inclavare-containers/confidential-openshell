"""Checks for the native workspace block device and its active mapping."""
import os
from pathlib import Path
import subprocess

SYS_BLOCK = Path('/sys/class/block')


def require_whole_disk(block):
    if (not block.is_dir() or (block / 'partition').exists() or
            any((child / 'partition').exists() for child in block.iterdir())):
        raise ValueError('workspace source must be a whole disk without partitions')
    return block


def verify_mapper(mapper, device):
    def backed_by(block):
        return block.name == device.name or any(
            backed_by(slave.resolve(strict=True)) for slave in (block / 'slaves').iterdir())

    block = SYS_BLOCK / mapper.resolve(strict=True).name
    if not backed_by(block):
        raise ValueError(f'workspace mapper is not backed by {device}')
    output = subprocess.check_output(['cryptsetup', 'status', mapper], text=True,
                                     env={**os.environ, 'LC_ALL': 'C'})
    fields = dict((key.strip(), ' '.join(value.split()))
                  for key, sep, value in (line.partition(':') for line in output.splitlines()) if sep)
    expected = {'type': 'LUKS2', 'cipher': 'aes-xts-plain64',
                'keysize': '512 [bits]', 'sector size': '4096 [bytes]'}
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError('workspace mapper must use LUKS2 AES-XTS-512 with 4096-byte sectors')
