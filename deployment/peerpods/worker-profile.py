#!/usr/bin/env python3
"""Runs on an ACK worker: merge the required profile into its active Kata configuration."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def section_name(header):
    data = tomllib.loads(header + '\n__cos_section = true\n')
    path = []
    while '__cos_section' not in data:
        key, data = next(iter(data.items()))
        path.append(key)
    return tuple(path)


def set_value(text, section, key, value):
    headers = list(re.finditer(r'^[ \t]*\[(?!\[)[^\n]+\][ \t]*(?:#[^\n]*)?$', text, re.M))
    found = next((i for i, h in enumerate(headers) if section_name(h.group().strip()) == tuple(section)), None)
    assignment = key + ' = ' + json.dumps(value)
    if found is None:
        return text.rstrip() + '\n\n[' + '.'.join(json.dumps(p) for p in section) + ']\n' + assignment + '\n'
    start = headers[found].end()
    end = headers[found + 1].start() if found + 1 < len(headers) else len(text)
    body = text[start:end]
    key_re = r'(?m)^[ \t]*(?:' + re.escape(key) + '|"' + re.escape(key) + '"|\'' + re.escape(key) + r"')[ \t]*=.*$"
    updated, count = re.subn(key_re, lambda _: assignment, body)
    if not count:
        updated = '\n' + assignment + '\n' + body.lstrip('\n')
    return text[:start] + updated + text[end:]


def merge(text, changes):
    expected = deepcopy(tomllib.loads(text))
    for section, key, value in changes:
        nested = expected
        for part in section:
            nested = nested.setdefault(part, {})
        nested[key] = value
        text = set_value(text, section, key, value)
    if tomllib.loads(text) != expected:
        raise SystemExit('Configuration merge changed unrelated settings; nothing was written.')
    return text


def replace(path, text):
    if path.read_text() == text:
        return False
    backup = path.with_name(path.name + '.before-openshell')
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
        backup.chmod(path.stat().st_mode & 0o777)
    temp = path.with_name(path.name + '.openshell.tmp')
    temp.write_text(text)
    os.chown(temp, path.stat().st_uid, path.stat().st_gid)
    temp.chmod(path.stat().st_mode & 0o777)
    temp.replace(path)
    return True


def main():
    pause, shim_sha = sys.argv[1:]
    observed = hashlib.sha256(Path('/opt/kata/bin/containerd-shim-kata-v2').read_bytes()).hexdigest()
    if observed != shim_sha:
        raise SystemExit('Worker shim differs from the published handoff. Check the kata-deploy rollout.')
    pid = subprocess.check_output(['systemctl', 'show', 'containerd.service', '-p', 'MainPID', '--value'], text=True).strip()
    args = [p.decode() for p in Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0') if p]
    config = '/etc/containerd/config.toml'
    for index, arg in enumerate(args):
        if arg in ('--config', '-c'):
            config = args[index + 1]
        elif arg.startswith('--config='):
            config = arg.split('=', 1)[1]
    path = Path(config)
    command = [args[0], '--config', config, 'config', 'dump']
    effective = tomllib.loads(subprocess.check_output(command, text=True))
    runtime = effective['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
    kata_path = Path(runtime['options']['ConfigPath'])
    if not str(kata_path).startswith('/opt/kata/') or '..' in kata_path.parts:
        raise SystemExit('Unexpected active Kata profile path: ' + str(kata_path))
    kata_changed = replace(kata_path, merge(kata_path.read_text(), [
        (('hypervisor', 'remote'), 'shared_fs', 'none'),
        (('runtime',), 'experimental_force_guest_pull', True),
        (('runtime',), 'create_container_timeout', 600),
    ]))
    containerd_changed = replace(path, merge(path.read_text(), [
        (('plugins', 'io.containerd.cri.v1.images', 'pinned_images'), 'sandbox', pause),
    ]))
    if containerd_changed or kata_changed:
        subprocess.run(['systemctl', 'restart', 'containerd.service'], check=True)
    subprocess.run(['systemctl', 'is-active', '--quiet', 'containerd.service'], check=True)
    current = tomllib.loads(subprocess.check_output(command, text=True))
    if current['plugins']['io.containerd.cri.v1.images']['pinned_images']['sandbox'] != pause:
        raise SystemExit('An imported containerd configuration overrides the selected pause image. Check the effective config imports.')
    configured = tomllib.loads(kata_path.read_text())
    assert configured['hypervisor']['remote']['shared_fs'] == 'none'
    assert configured['runtime']['experimental_force_guest_pull'] is True
    assert configured['runtime']['create_container_timeout'] == 600
    subprocess.run(['crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock',
                    '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'pull', pause], check=True)
    print(json.dumps({'kata_profile': str(kata_path), 'shared_fs': 'none', 'guest_pull': True,
                      'create_container_timeout': 600, 'pause_image': pause, 'shim_sha256': observed,
                      'containerd_restarted': containerd_changed or kata_changed, 'passed': True}))


if __name__ == '__main__':
    main()
