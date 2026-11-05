#!/usr/bin/env python3
"""Verify the installed runtime profile and configure the ACK kubelet timeout."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib


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
    pause, shim_sha = sys.argv[1:]
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
    command = [args[0], '--config', config, 'config', 'dump']
    effective = tomllib.loads(subprocess.check_output(command, text=True))
    runtime = effective['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
    kata_path = Path(runtime['options']['ConfigPath'])
    kata_path = kata_path.resolve(strict=True)
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
    dropins = kata_path.parent / 'config.d'
    for path in sorted(dropins.iterdir()) if dropins.exists() else []:
        overlay = tomllib.loads(path.read_text())
        configured['hypervisor']['remote'].update(overlay.get('hypervisor', {}).get('remote', {}))
        configured['runtime'].update(overlay.get('runtime', {}))
    assert configured['hypervisor']['remote']['shared_fs'] == 'none'
    assert configured['runtime']['experimental_force_guest_pull'] is True
    assert configured['runtime']['create_container_timeout'] == 600
    subprocess.run(['crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock',
                    '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'pull', pause], check=True)
    print(json.dumps({'kata_profile': str(kata_path), 'shared_fs': 'none', 'guest_pull': True,
                      'create_container_timeout': 600, 'pause_image': pause, 'shim_sha256': observed,
                      'kubelet_restarted': kubelet_restart,
                      'passed': True}))


if __name__ == '__main__':
    main()
