#!/usr/bin/env python3
"""Runs on an ACK worker: merge the required profile into its active Kata configuration."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
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
    existed = path.exists()
    if existed and path.read_text() == text:
        return False
    backup = path.with_name(path.name + '.before-openshell')
    if existed and not backup.exists():
        backup.write_bytes(path.read_bytes())
        backup.chmod(path.stat().st_mode & 0o777)
    temp = path.with_name(path.name + '.openshell.tmp')
    temp.write_text(text)
    if existed:
        os.chown(temp, path.stat().st_uid, path.stat().st_gid)
    temp.chmod(path.stat().st_mode & 0o777 if existed else 0o600)
    temp.replace(path)
    return True


def kubelet_timeout(text):
    """Update ACK's custom arguments, retaining other options and file contents."""
    matches = list(re.finditer(r'(?m)^[ \t]*KUBELET_CUSTOMIZED_ARGS[ \t]*=([^\n]*)$', text))
    value = matches[-1].group(1).strip() if matches else ''
    try:
        if value.startswith(('"', "'")):
            quoted = shlex.split(value)
            if len(quoted) != 1:
                raise ValueError('expected one quoted assignment value')
            value = quoted[0]
        args = iter(shlex.split(value))
        retained = []
        for arg in args:
            if arg == '--runtime-request-timeout':
                if next(args, None) is None:
                    raise ValueError('missing runtime request timeout')
            elif not arg.startswith('--runtime-request-timeout='):
                retained.append(arg)
        if any('\n' in arg or '\r' in arg for arg in retained):
            raise ValueError('multiline argument')
    except ValueError as error:
        raise SystemExit('Cannot read ACK kubelet custom arguments; keep the file and resolve its quoting before retrying.') from error
    retained.append('--runtime-request-timeout=600s')
    assignment = 'KUBELET_CUSTOMIZED_ARGS=' + json.dumps(shlex.join(retained), ensure_ascii=False)
    if matches:
        match = matches[-1]
        return text[:match.start()] + assignment + text[match.end():]
    return text + ('' if not text or text.endswith('\n') else '\n') + assignment + '\n'


def main():
    pause, shim_sha, containerd_version = sys.argv[1:]
    observed = hashlib.sha256(Path('/opt/kata/bin/containerd-shim-kata-v2').read_bytes()).hexdigest()
    if observed != shim_sha:
        raise SystemExit('Worker shim differs from the published handoff. Check the kata-deploy rollout.')
    kubelet_path = Path('/etc/kubernetes/kubelet-customized-args.conf')
    environment_files = subprocess.check_output(
        ['systemctl', 'show', 'kubelet.service', '-p', 'EnvironmentFiles', '--value'], text=True)
    if str(kubelet_path) not in environment_files:
        raise SystemExit('This worker does not load the ACK kubelet custom arguments file.')
    kubelet_text = kubelet_timeout(kubelet_path.read_text() if kubelet_path.exists() else '')
    pid = subprocess.check_output(['systemctl', 'show', 'containerd.service', '-p', 'MainPID', '--value'], text=True).strip()
    args = [p.decode() for p in Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0') if p]
    config = '/etc/containerd/config.toml'
    for index, arg in enumerate(args):
        if arg in ('--config', '-c'):
            config = args[index + 1]
        elif arg.startswith('--config='):
            config = arg.split('=', 1)[1]
    version = subprocess.check_output([args[0], '--version'], text=True)
    if 'v' + containerd_version not in version.split():
        raise SystemExit(f'Worker requires containerd {containerd_version} for the measured OCI 1.3.0 profile; found {version.strip()}.')
    path = Path(config)
    command = [args[0], '--config', config, 'config', 'dump']
    effective = tomllib.loads(subprocess.check_output(command, text=True))
    if effective.get('version') != 3 or not all(key in effective.get('plugins', {}) for key in
            ('io.containerd.cri.v1.runtime', 'io.containerd.cri.v1.images')):
        raise SystemExit('Worker requires containerd config version 3 with CRI runtime and images plugins; no files changed.')
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
    kubelet_changed = replace(kubelet_path, kubelet_text)
    kubelet_pid = subprocess.check_output(
        ['systemctl', 'show', 'kubelet.service', '-p', 'MainPID', '--value'], text=True).strip()
    cmdline = Path('/proc/' + kubelet_pid + '/cmdline')
    active_args = cmdline.read_bytes().split(b'\0') if cmdline.exists() else []
    kubelet_restart = kubelet_changed or b'--runtime-request-timeout=600s' not in active_args
    if kubelet_restart:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'restart', 'kubelet.service'], check=True)
    subprocess.run(['systemctl', 'is-active', '--quiet', 'kubelet.service'], check=True)
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
                      'kubelet_restarted': kubelet_restart,
                      'containerd_restarted': containerd_changed or kata_changed, 'passed': True}))


if __name__ == '__main__':
    main()
