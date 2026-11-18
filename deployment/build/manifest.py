#!/usr/bin/env python3
"""Inventory pinned sources and explicitly selected public outputs (not build attestation)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
LAYOUTS = {
    'attestation-observer': r'openshell-attestation-observer',
    'driver': r'openshell-driver-confidential-kubernetes',
    'guest-payload': r'guest-payload.tar',
    'guest-image': r'guest/openshell-guest-[0-9a-f]{12}\.qcow2',
    'guest-references': r'guest/openshell-guest-[0-9a-f]{12}\.references\.json',
    'caa-image-archive': r'images/caa.tar',
    'peerpod-controller-image-archive': r'images/peerpod-controller.tar',
    'csi-image-archive': r'images/csi.tar',
    'csi-chart': r'charts/caa-csi-block-driver\.tgz',
}

def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def artifact_path(name, raw):
    """Validate before opening: only fixed public layouts, no traversal or symlinks."""
    supplied = Path(raw)
    if '..' in supplied.parts or name not in LAYOUTS:
        raise ValueError('invalid public artifact path')
    path = supplied if supplied.is_absolute() else ROOT / supplied
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError('artifact path contains a symlink')
    resolved = path.resolve(strict=True)
    relative = resolved.relative_to(ROOT / 'artifacts')
    if not re.fullmatch(LAYOUTS[name], relative.as_posix()):
        raise ValueError('artifact is outside its approved public layout')
    if not resolved.is_file() or resolved.stat().st_nlink != 1:
        raise ValueError('artifact must be a regular non-hardlinked file')
    return resolved

def inventory(sources):
    observed = {}
    for name, entry in sources.items():
        if name == 'schema':
            continue
        repository = entry.get('source', name)
        if not isinstance(repository, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]*', repository):
            raise ValueError('invalid source repository alias')
        item = {'source_repository': repository, 'source_upstream_commit': entry['base'], 'upstream_checkout': 'not_present'}
        upstream = ROOT / 'repos' / repository
        if (upstream / '.git').exists():
            item['observed_upstream_commit'] = git(upstream, 'rev-parse', 'HEAD')
            item['upstream_checkout'] = ('verified' if item['observed_upstream_commit'] == entry['base']
                                        and not git(upstream, 'status', '--porcelain') else 'mismatch')
        if 'result_tree' in entry:
            item.update(expected_patched_result_tree=entry['result_tree'], patch_check='not_present')
            patched = ROOT / '.local/build-sources' / name
            if (patched / '.git').exists():
                item['observed_patch_base_commit'] = git(patched, 'rev-parse', 'HEAD')
                item['observed_patched_result_tree'] = git(patched, 'write-tree')
                item['patch_check'] = ('verified' if item['observed_patch_base_commit'] == entry['base']
                    and item['observed_patched_result_tree'] == entry['result_tree']
                    and not git(patched, 'diff', '--name-only')
                    and not git(patched, 'ls-files', '--others', '--exclude-standard') else 'mismatch')
        observed[name] = item
    return observed

def csi_chart_provenance(path, observed):
    entry = observed['caa-csi-block-driver']
    if entry.get('upstream_checkout') != 'verified' or entry.get('patch_check') != 'verified':
        raise ValueError('CSI chart requires verified upstream and patched inputs')
    source = ROOT / '.local/build-sources/caa-csi-block-driver'
    tree = entry['observed_patched_result_tree']
    expected = {
        'schema': 1, 'component': 'caa-csi-block-driver',
        'source_upstream_commit': entry['source_upstream_commit'],
        'patched_result_tree': tree, 'chart_path': 'charts/caa-csi-block-driver',
        'chart_tree': git(source, 'rev-parse', f'{tree}:charts/caa-csi-block-driver'),
    }
    # Compare actual members to Git objects, not merely a self-reported label.
    # ls-tree includes directories so extra, duplicate and noncanonical members
    # cannot hide behind an otherwise valid set of chart files.
    members = {}
    listing = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-rzt', expected['chart_tree']])
    for record in listing.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, object_id = metadata.decode().split()
        if (kind, mode) not in {('tree', '040000'), ('blob', '100644'), ('blob', '100755')}:
            raise ValueError('CSI chart source contains unsupported member type')
        members['caa-csi-block-driver/' + name.decode()] = (mode, kind, object_id)
    provenance_name = 'caa-csi-block-driver/source-provenance.json'
    if provenance_name in members:
        raise ValueError('CSI chart source uses reserved provenance path')
    seen = set()
    actual = None
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            name = member.name
            relative = Path(name)
            if (relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name
                    or name in seen or not (member.isfile() or member.isdir()) or member.mode & 0o7000):
                raise ValueError('unsafe or duplicate CSI chart member')
            seen.add(name)
            if name == provenance_name:
                if not member.isfile() or member.size > 16384 or member.mode & 0o111:
                    raise ValueError('invalid CSI chart provenance member')
                actual = json.load(archive.extractfile(member))
                continue
            if name not in members:
                raise ValueError('unexpected CSI chart member: ' + name)
            mode, kind, object_id = members[name]
            if member.isdir() != (kind == 'tree'):
                raise ValueError('CSI chart member type mismatch: ' + name)
            if kind == 'blob':
                data = subprocess.check_output(['git', '-C', str(source), 'cat-file', 'blob', object_id])
                if member.mode & 0o111 != int(mode, 8) & 0o111 or archive.extractfile(member).read() != data:
                    raise ValueError('CSI chart content/mode mismatch: ' + name)
    if seen != set(members) | {provenance_name}:
        raise ValueError('missing CSI chart members')
    if actual != expected:
        raise ValueError('CSI chart provenance does not match the verified patched source')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['source-only', 'release'], default='source-only')
    parser.add_argument('--check-test-sources', action='store_true',
                        help='require pinned upstream checkouts and verified CAA/controller/CSI patch trees')
    parser.add_argument('--artifact', action='append', default=[], metavar='NAME=PATH')
    parser.add_argument('--image', action='append', default=[], metavar='NAME=REFERENCE@sha256:DIGEST')
    args = parser.parse_args()
    if args.profile == 'source-only' and (args.artifact or args.image):
        parser.error('source-only cannot claim build outputs; select release')
    # Validate every selected path before reading any artifact bytes.
    artifacts = {}
    try:
        for pair in args.artifact:
            name, raw = pair.split('=', 1)
            if name in artifacts:
                raise ValueError('duplicate artifact')
            artifacts[name] = artifact_path(name, raw)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    sources = json.loads((ROOT / 'deployment/build/sources.lock.json').read_text())
    observed = inventory(sources)
    if args.check_test_sources:
        for name in ['openshell', 'cloud-api-adaptor', 'peerpod-ctrl', 'caa-csi-block-driver']:
            if observed.get(name, {}).get('upstream_checkout') != 'verified':
                parser.error(f'test source check failed: upstream checkout {name}')
        for name in ['cloud-api-adaptor', 'peerpod-ctrl', 'caa-csi-block-driver']:
            if observed.get(name, {}).get('patch_check') != 'verified':
                parser.error(f'test source check failed: patched input {name}')
    dirty = bool(git(ROOT, 'status', '--porcelain', '--untracked-files=normal'))
    if args.profile != 'source-only':
        if dirty or not (artifacts or args.image):
            parser.error('output inventory requires clean integration source and selected outputs')
        for name in ['openshell', 'cloud-api-adaptor', 'caa-csi-block-driver']:
            if observed[name]['upstream_checkout'] != 'verified':
                parser.error(f'missing or mismatched upstream checkout: {name}')
        required = set()
        for name in artifacts:
            if name.startswith('guest-') or name == 'caa-image-archive':
                required.add('cloud-api-adaptor')
            if name == 'peerpod-controller-image-archive':
                required.add('peerpod-ctrl')
            if name in {'csi-image-archive', 'csi-chart'}:
                required.add('caa-csi-block-driver')
        for pair in args.image:
            if pair.startswith('caa='):
                required.add('cloud-api-adaptor')
            if pair.startswith('peerpod-ctrl='):
                required.add('peerpod-ctrl')
            if pair.startswith('csi='):
                required.add('caa-csi-block-driver')
        for name in required:
            if observed[name]['patch_check'] != 'verified':
                parser.error(f'missing or mismatched patched input: {name}')
    report = {'schema': 2, 'integration_commit': git(ROOT, 'rev-parse', 'HEAD'),
              'build_profile': args.profile, 'integration_dirty': dirty,
              'scope': 'source inventory' if args.profile == 'source-only' else 'caller-selected output inventory; not proof of build execution',
              'sources': observed, 'artifacts': {}, 'images': {}, 'input_sha256': {}}
    report['source_inventory_complete'] = all(
        e['upstream_checkout'] == 'verified'
        and e.get('patch_check', 'verified') == 'verified' for name, e in observed.items())
    for relative in ['deployment/artifacts.lock.json', 'deployment/runtime/artifacts.lock.json', 'deployment/build/sources.lock.json']:
        report['input_sha256'][relative] = digest(ROOT / relative)
    for series in sorted((ROOT / 'patches').glob('*/series')):
        for name in ['series', 'SHA256SUMS', *series.read_text().splitlines()]:
            if name and not name.startswith('#'):
                path = (series.parent / name).resolve()
                report['input_sha256'][str(path.relative_to(ROOT))] = digest(path)
    for name, path in artifacts.items():
        report['artifacts'][name] = {'path': str(path.relative_to(ROOT)), 'sha256': digest(path), 'bytes': path.stat().st_size}
        if name == 'csi-chart':
            try:
                report['artifacts'][name]['source'] = csi_chart_provenance(path, observed)
            except (KeyError, ValueError, OSError, tarfile.TarError) as error:
                parser.error(str(error))
    for pair in args.image:
        name, separator, reference = pair.partition('=')
        if not separator or name not in {'caa', 'peerpod-ctrl', 'csi', 'kata-deploy', 'supervisor', 'sandbox', 'workload', 'pause', 'trustee-as', 'trustee-kbs'} or name in report['images']:
            parser.error('invalid image identity')
        if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', reference):
            parser.error('image reference must be digest pinned')
        report['images'][name] = reference
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
