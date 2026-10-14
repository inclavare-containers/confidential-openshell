#!/usr/bin/env python3
"""Verify upstream UKI/root verity and derive static references without trusting a guest."""
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile

SECTION_ORDER = ('.linux', '.osrel', '.cmdline', '.initrd', '.ucode', '.splash',
                 '.dtb', '.uname', '.sbat', '.pcrpkey')
ESP = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
ROOT = '4f68bce3-e8cd-4db1-96e7-fbcaf984b709'
VERITY = '2c7357ed-ebd2-46d9-aec1-23d437ec2bf5'
PUBLIC_DIRECTORIES = ('', 'usr', 'etc', 'usr/lib', 'usr/lib/systemd',
                      'usr/lib/systemd/network', 'usr/lib/x86_64-linux-gnu',
                      'usr/local', 'usr/local/bin', 'usr/local/libexec',
                      'usr/local/libexec/openshell-guest', 'etc/systemd',
                      'etc/systemd/system', 'etc/systemd/timesyncd.conf.d',
                      'etc/ssl', 'etc/ssl/certs')
PUBLIC_READABLE_FILES = ('etc/passwd', 'etc/group', 'etc/nsswitch.conf',
                         'etc/ssl/certs/ca-certificates.crt',
                         'usr/lib/systemd/network/20-wired.network',
                         'etc/systemd/timesyncd.conf.d/10-alibaba.conf')
PUBLIC_EXECUTABLES = ('usr/lib/systemd/systemd-networkd',
                      'usr/lib/systemd/systemd-resolved',
                      'usr/lib/systemd/systemd-timesyncd')


def verify_public_permissions(rootfs):
    modes = {}
    for name in PUBLIC_DIRECTORIES:
        path = rootfs/name
        mode = stat.S_IMODE(path.stat().st_mode)
        if not path.is_dir() or mode != 0o755:
            raise ValueError('public guest directory is not traversable: /'+name)
        modes['/'+name] = oct(mode)
    for name in (*PUBLIC_READABLE_FILES, *PUBLIC_EXECUTABLES):
        path = rootfs/name
        mode = stat.S_IMODE(path.stat().st_mode)
        required = 0o555 if name in PUBLIC_EXECUTABLES else 0o444
        if not path.is_file() or mode & required != required:
            raise ValueError('public guest daemon input is not accessible: /'+name)
        modes['/'+name] = oct(mode)
    return modes


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def pe_sections(data):
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('UKI is not PE')
    count = struct.unpack_from('<H', data, pe+6)[0]
    optional = struct.unpack_from('<H', data, pe+20)[0]
    sections = {}
    raw_sections = []
    for i in range(count):
        offset = pe + 24 + optional + i * 40
        name = data[offset:offset+8].rstrip(b'\0').decode()
        virtual_size, _, raw_size, pointer = struct.unpack_from('<IIII', data, offset+8)
        if name in sections or pointer + raw_size > len(data):
            raise ValueError('duplicate or out-of-bounds UKI section')
        sections[name] = (data[pointer:pointer+min(raw_size, virtual_size)] +
                          bytes(max(0, virtual_size-raw_size)))
        raw_sections.append((pointer, raw_size))
    optional_offset = pe + 24
    if struct.unpack_from('<H', data, optional_offset)[0] != 0x20b:
        raise ValueError('UKI is not PE32+')
    header_size = struct.unpack_from('<I', data, optional_offset+60)[0]
    checksum_offset = optional_offset+64
    security_offset = optional_offset+112+4*8
    _, certificate_size = struct.unpack_from('<II', data, security_offset)
    chunks = [data[:checksum_offset], data[checksum_offset+4:security_offset],
              data[security_offset+8:header_size]]
    chunks.extend(data[pointer:pointer+size] for pointer, size in sorted(raw_sections) if size)
    hashed_size = header_size + sum(size for _, size in raw_sections)
    chunks.append(data[hashed_size:len(data)-certificate_size])
    return sections, b''.join(chunks)


def section_measurements(sections):
    if not {'.linux', '.osrel', '.cmdline', '.initrd'}.issubset(sections):
        raise ValueError('UKI lacks required boot sections')
    seed = bytes(48)
    events = []
    refs = {}
    for name in SECTION_ORDER:
        if name not in sections:
            continue
        for kind, content in [('name', name.encode()+b'\0'), ('data', sections[name])]:
            hashed = hashlib.sha384(content).digest()
            seed = hashlib.sha384(seed+hashed).digest()
            events.append({'section':name, 'kind':kind, 'sha384':hashed.hex()})
            refs[f'measurement.uki.section.{name[1:]}.{kind}.sha384'] = [hashed.hex()]
    # This is only the systemd-stub section seed, not final TDX RTMR2.
    refs['measurement.uki.sections.sha384'] = [seed.hex()]
    return refs, events, seed.hex()


def align4(data):
    return data + bytes(-len(data) % 4)


def cpio_entry(name, mode, content, inode):
    name = name.encode('ascii') + b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name), 0]
    return (align4(b'070701' + ''.join(f'{n:08x}' for n in fields).encode('ascii') + name) +
            align4(content))


def derive_linux_events(sections):
    # systemd v259.5 src/boot/{cpio,stub}.c; Linux v7.0 EFI libstub.
    # The generated .extra/os-release cpio is passed to Linux with the initrd.
    # No live quote or host-provided reference participates in this derivation.
    stub = sections.get('.sdmagic', b'').decode('ascii').strip('\0')
    if 'systemd-stub 259.5-0ubuntu3.4 ' not in stub:
        raise ValueError('unsupported systemd-stub version for independent Linux event derivation')
    for name in ('.pcrsig', '.pcrpkey', '.profile', '.ucode'):
        if sections.get(name):
            raise ValueError('unsupported additional initrd section: ' + name)
    cmdline = sections['.cmdline'].rstrip(b'\0').decode('ascii')
    if any(char in cmdline for char in '\r\n\t'):
        raise ValueError('command line requires unsupported systemd mangling')
    # Upstream uses a literal uppercase namesize field in the cpio trailer.
    trailer = cpio_entry('TRAILER!!!', 0, b'', 0).replace(b'0000000b', b'0000000B')
    literal = (cpio_entry('.extra', 0o40555, b'', 1) +
               cpio_entry('.extra/os-release', 0o100444, sections['.osrel'], 2) + trailer)
    return [
        {'event':'LOADED_IMAGE::LoadOptions',
         'sha384':hashlib.sha384((cmdline+'\0').encode('utf-16-le')).hexdigest()},
        {'event':'Linux initrd',
         'sha384':hashlib.sha384(align4(sections['.initrd'])+align4(literal)).hexdigest()},
    ]


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT)


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: verify-image.py SYSTEM.raw SCRATCH_DIR EVIDENCE_DIR')
    raw, scratch, evidence = map(Path, sys.argv[1:])
    scratch.mkdir()
    source = Path(__file__).resolve().parents[2]
    lock = json.loads((source/'deployment/artifacts.lock.json').read_text())
    table = json.loads(run('sfdisk', '--json', str(raw)))['partitiontable']
    partitions = table['partitions']
    if table['label'] != 'gpt' or len(partitions) != 3:
        raise ValueError('upstream image must have GPT ESP/root/root-verity partitions')
    found = {}
    for kind in (ESP, ROOT, VERITY):
        matches = [part for part in partitions if part['type'].lower() == kind]
        if len(matches) != 1:
            raise ValueError('missing or duplicate upstream partition type')
        found[kind] = matches[0]
    sector = table.get('sectorsize', 512)
    uki = scratch/'BOOTX64.EFI'
    run('mcopy', '-i', str(raw)+'@@'+str(found[ESP]['start']*sector),
        '::/EFI/BOOT/BOOTX64.EFI', str(uki))
    data = uki.read_bytes()
    sections, auth_bytes = pe_sections(data)
    section_dir = scratch/'sections'
    section_dir.mkdir()
    for name, content in sections.items():
        (section_dir/name[1:]).write_bytes(content)
    cmdline = sections['.cmdline'].rstrip(b'\0').decode()
    roots = re.findall(r'(?:^|\s)roothash=([0-9a-f]{64})(?=\s|$)', cmdline)
    if len(roots) != 1 or 'systemd.volatile=state' not in cmdline.split():
        raise ValueError('UKI command line must bind exactly one root hash and volatile state')
    roothash = roots[0]
    for kind, name in [(ROOT, 'rootfs.squashfs'), (VERITY, 'rootfs.verity')]:
        part = found[kind]
        with raw.open('rb') as src, (scratch/name).open('wb') as dst:
            src.seek(part['start']*sector)
            left = part['size']*sector
            while left:
                chunk = src.read(min(left, 8*1024*1024))
                if not chunk:
                    raise ValueError('truncated upstream partition')
                dst.write(chunk)
                left -= len(chunk)
    run('veritysetup', 'verify', str(scratch/'rootfs.squashfs'),
        str(scratch/'rootfs.verity'), roothash)
    # Independent PE hash implementation versus the released pesign tool.
    pesign = run('pesign', '--hash', '--in', str(uki), '--digest_type', 'sha256').decode()
    if re.search(r'[0-9a-f]{64}', pesign).group() != hashlib.sha256(auth_bytes).hexdigest():
        raise ValueError('Authenticode hash disagrees with pesign')
    refs, events, seed = section_measurements(sections)
    refs['measurement.uki.sha384'] = [hashlib.sha384(auth_bytes).hexdigest()]
    # The reviewed ECS index2 profile contains one measured application: UKI.
    refs['measurement.ecs.rtmr_1.sha384'] = [
        hashlib.sha384(bytes(48)+bytes.fromhex(refs['measurement.uki.sha384'][0])).hexdigest()]
    linux_events = derive_linux_events(sections)
    refs['measurement.uki.linux.load_options.sha384'] = [linux_events[0]['sha384']]
    refs['measurement.uki.linux.initrd.sha384'] = [linux_events[1]['sha384']]
    rtmr2 = bytes.fromhex(seed)
    for event in linux_events:
        rtmr2 = hashlib.sha384(rtmr2+bytes.fromhex(event['sha384'])).digest()
    refs['measurement.uki.rtmr2.sha384'] = [rtmr2.hex()]
    run('unsquashfs', '-processors', '2', '-d', str(scratch/'rootfs'), str(scratch/'rootfs.squashfs'))
    rootfs = scratch/'rootfs'
    public_modes = verify_public_permissions(rootfs)
    distro = json.loads((evidence/'distro-manifest.json').read_text())
    if (distro.get('manifest_version') != 1 or
            distro.get('config', {}).get('distribution') != 'ubuntu' or
            distro['config'].get('release') != lock['podvm']['release']):
        raise ValueError('unexpected upstream distro manifest')
    packages = {package['name']:package['version'] for package in distro['packages']}
    if packages.get('systemd-boot-efi') != lock['podvm']['systemd_stub_package_version']:
        raise ValueError('systemd-stub package differs from supported version')
    for name in ('python3', 'systemd-timesyncd', 'cryptsetup', 'e2fsprogs', 'linux-image-generic'):
        if name not in packages:
            raise ValueError('guest distro package is missing: ' + name)
    # Check the complete local overlay in the verity-protected final root.
    overlay = source/'deployment/guest/files'
    for path in overlay.rglob('*'):
        if (not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc'):
            continue
        installed = rootfs/path.relative_to(overlay)
        if installed.is_symlink() or digest(installed) != digest(path):
            raise ValueError('guest overlay differs from frozen source: '+str(path.relative_to(overlay)))
    binaries = {}
    expected = {name: item['binary_sha256'] for name, item in lock['guest_components']['binaries'].items()}
    expected['kata-agent'] = lock['kata_agent']['binary_sha256']
    # Compare actual APF/PUD to this build's payload, not an earlier image.
    with tarfile.open(source/'artifacts/guest-payload.tar') as payload:
        for name in ('agent-protocol-forwarder', 'process-user-data'):
            member = payload.getmember('./usr/local/bin/'+name)
            expected[name] = hashlib.sha256(payload.extractfile(member).read()).hexdigest()
    for name, wanted in expected.items():
        path = rootfs/'usr/local/bin'/name
        if digest(path) != wanted:
            raise ValueError('guest binary differs from pinned release or current payload: '+name)
        binaries[name] = wanted
    if digest(rootfs/'pause_bundle/rootfs/pause') != lock['pause_image']['binary_sha256']:
        raise ValueError('guest pause binary differs from locked image')
    copied_sections = rootfs/'tmp/openshell-uki-sections'
    copied_sections.mkdir()
    for name, content in sections.items():
        (copied_sections/name[1:]).write_bytes(content)
    argv = ['chroot', str(rootfs), '/usr/lib/systemd/systemd-measure', 'calculate',
            '--bank=sha384', '--phase=:', '--json=short']
    argv += ['--'+name[1:]+'=/tmp/openshell-uki-sections/'+name[1:]
             for name in SECTION_ORDER if name in sections]
    measured = json.loads(run(*argv))
    if measured['sha384'][0]['hash'] != seed:
        raise ValueError('UKI section seed disagrees with guest systemd-measure')
    receipt = {'schema':1, 'verity_verified':True, 'roothash':roothash,
               'uki_sha256':digest(uki), 'uki_authenticode_sha384':refs['measurement.uki.sha384'][0],
               'uki_section_seed_sha384':seed, 'systemd_measure_matches':True,
               'expected_rtmr2_sha384':rtmr2.hex(), 'linux_events':linux_events,
               'systemd_stub':sections['.sdmagic'].decode().strip('\0'),
               'expected_rtmr1_sha384':refs['measurement.ecs.rtmr_1.sha384'][0],
               'distro_packages':packages, 'distro_manifest_sha256':digest(evidence/'distro-manifest.json'),
               'section_events':events, 'binaries':binaries,
               'public_input_modes':public_modes,
               'kernel':sections.get('.uname', b'').rstrip(b'\0').decode(),
               'kernel_cmdline':cmdline,
               'reference_scope':'independent UKI sections, Linux EFI events and single-UKI RTMR1; cloud MRTD/RTMR0 require separately approved platform references',
               'guest_boot':'not_run; real TDX acceptance required'}
    (evidence/'verification.json').write_text(json.dumps(receipt, indent=2)+'\n')
    (evidence/'references.json').write_text(json.dumps(refs, indent=2, sort_keys=True)+'\n')
    (evidence/'partitions.json').write_text(json.dumps(table, indent=2)+'\n')
    print(json.dumps({'verity_verified':True,'uki_sha256':receipt['uki_sha256'],
                      'uki_section_seed_sha384':seed,'kernel':receipt['kernel']}))


if __name__ == '__main__':
    main()
