#!/usr/bin/env python3
"""Derive native Kata 4.4 TDX boot references on the trusted deployment machine."""
import argparse
from hashlib import sha384
import json
from pathlib import Path
import tomllib

# Go qemu-tdx on amd64, virtio root disk, systemd, release mode.
# See the Kata upgrade procedure in README.md before changing this prefix.
KATA_VERSION = '4.4.0'
KATA_CMDLINE = (
    'tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 '
    'i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 '
    'root=/dev/vda1 rootflags=ro rootfstype=erofs console=hvc0 console=hvc1 quiet systemd.show_status=false '
    'panic=1 selinux=0 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service '
    'systemd.mask=systemd-networkd.socket scsi_mod.scan=none agent.launch_process_timeout=6'
)


def extend(register, *digests):
    for digest in digests:
        register = sha384(register + digest).digest()
    return register.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image_references', type=Path, help="verified guest release references.json")
    parser.add_argument('drop_in', type=Path, help="prepare-guest.py output from that release on the trusted system")
    args = parser.parse_args()
    refs = json.loads(args.image_references.read_bytes())
    params = tomllib.loads(args.drop_in.read_text())['hypervisor']['qemu']['kernel_params']
    cmdline = sha384((KATA_CMDLINE + ' ' + params + '\0').encode('utf-16le')).digest()

    def reference(name):
        value, = refs['measurement.uki.' + name]
        return bytes.fromhex(value)

    rtmr1 = extend(bytes(48), reference('sha384'), sha384(b'Calling EFI Application from Boot Option').digest(),
                   sha384(bytes(4)).digest(), sha384(b'Exit Boot Services Invocation').digest(),
                   sha384(b'Exit Boot Services Returned with Success').digest())
    rtmr2 = extend(reference('sections.sha384'), cmdline, cmdline, reference('linux.initrd.sha384'))
    print(json.dumps({'measurement.kata.rtmr_1.sha384': [rtmr1], 'measurement.kata.rtmr_2.sha384': [rtmr2]},
                     indent=2))


if __name__ == '__main__':
    main()
