#!/usr/bin/env python3.11
"""Package only the CSI chart from the verified patched Git tree, without Helm/network."""
import gzip
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

import manifest

COMPONENT = 'caa-csi-block-driver'
CHART_PATH = 'charts/caa-csi-block-driver'
OUTPUT = 'artifacts/charts/caa-csi-block-driver.tgz'


def package():
    root = manifest.ROOT
    sources = json.loads((root / 'deployment/build/sources.lock.json').read_text())
    observed = manifest.inventory(sources).get(COMPONENT, {})
    if observed.get('upstream_checkout') != 'verified' or observed.get('patch_check') != 'verified':
        raise ValueError('CSI packaging requires the pinned clean upstream and exact patched base/tree without unstaged or untracked files')
    source = root / '.local/build-sources' / COMPONENT
    tree = observed['observed_patched_result_tree']
    chart_tree = manifest.git(source, 'rev-parse', f'{tree}:{CHART_PATH}')
    provenance = {
        'schema': 1, 'component': COMPONENT,
        'source_upstream_commit': observed['source_upstream_commit'],
        'patched_result_tree': tree, 'chart_path': CHART_PATH, 'chart_tree': chart_tree,
    }
    # Archive the verified tree object, never the possibly changing worktree.
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', '--format=tar', f'{tree}:{CHART_PATH}'])
    output = root / OUTPUT
    if any(p.is_symlink() for p in [output, *output.parents]):
        raise ValueError('chart artifact path contains a symlink')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.csi-chart-', delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with gzip.GzipFile(filename='', mode='wb', fileobj=temporary, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as packed:
                    with tarfile.open(fileobj=io.BytesIO(archive)) as original:
                        for member in sorted(original.getmembers(), key=lambda item: item.name):
                            path = Path(member.name)
                            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                                raise ValueError('CSI chart contains a non-regular or unsafe archive member')
                            data = original.extractfile(member) if member.isfile() else None
                            entry = tarfile.TarInfo(f'{COMPONENT}/{member.name}')
                            entry.mode = member.mode
                            entry.type = tarfile.REGTYPE if member.isfile() else tarfile.DIRTYPE
                            entry.size = member.size if member.isfile() else 0
                            packed.addfile(entry, data)
                    payload = (json.dumps(provenance, indent=2, sort_keys=True) + '\n').encode()
                    entry = tarfile.TarInfo(f'{COMPONENT}/source-provenance.json')
                    entry.mode = 0o644
                    entry.size = len(payload)
                    packed.addfile(entry, io.BytesIO(payload))
            temporary.flush()
            manifest.csi_chart_provenance(temporary_path, {COMPONENT: observed})
            temporary_path.replace(output)
        finally:
            temporary_path.unlink(missing_ok=True)
    print(json.dumps({'path': OUTPUT, 'sha256': manifest.digest(output), 'source': provenance}, indent=2))


if __name__ == '__main__':
    try:
        package()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
