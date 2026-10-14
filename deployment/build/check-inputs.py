#!/usr/bin/env python3.11
"""Read-only offline checks for Kata source and exact Helm dependency archives."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def verify_tree(path, revision, depth=0):
    """Hash every HEAD blob as bytes; status/fsck alone cannot prove a worktree.

    Reject hidden index states, sparse checkout, nonregular files and missing or
    mismatched submodules. Never initialize/download objects or invoke filters.
    """
    if depth > 16 or path.is_symlink():
        raise ValueError('unsafe source tree')
    def git(*args):
        return subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(path), *args],
            stderr=subprocess.DEVNULL, env={**os.environ, 'GIT_NO_LAZY_FETCH': '1',
                                          'GIT_TERMINAL_PROMPT': '0'})
    if Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve() != path.resolve():
        raise ValueError('submodule worktree missing')
    if git('rev-parse', 'HEAD').decode().strip() != revision:
        raise ValueError('wrong revision')
    for setting in ('core.sparseCheckout', 'core.sparseCheckoutCone'):
        try:
            value = git('config', '--bool', '--get', setting).strip()
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise
            value = b'false'
        if value != b'false':
            raise ValueError('sparse source tree')
    if any(entry[:2] != b'H ' for entry in git('ls-files', '-v', '-z').split(b'\0') if entry):
        raise ValueError('hidden/unmerged index state')
    try:
        partial = git('config', '--get-regexp', r'^(extensions\.partialclone|remote\..*\.promisor)$')
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        partial = b''
    if partial:
        raise ValueError('partial clone cannot fetch during offline verification')
    if git('ls-files', '--others', '--exclude-standard', '-z'):
        raise ValueError('untracked source files')
    tree = git('ls-tree', '-rz', 'HEAD')
    expected_index = set()
    for entry in tree.split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            mode, kind, oid = meta.split()
            expected_index.add(mode + b' ' + oid + b' 0\t' + name)
    if set(git('ls-files', '--stage', '-z').rstrip(b'\0').split(b'\0')) != expected_index:
        raise ValueError('staged source changes')
    algorithm = git('rev-parse', '--show-object-format').decode().strip()
    if algorithm not in ('sha1', 'sha256'):
        raise ValueError('unknown Git object format')
    for entry in tree.split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t', 1)
        mode, kind, expected = meta.decode().split()
        relative = Path(os.fsdecode(name))
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe tracked path')
        target = path / relative
        for parent in relative.parents:
            if (path / parent).is_symlink():
                raise ValueError('symlink parent')
        info = target.lstat()
        if mode == '160000' and kind == 'commit':
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('submodule absent')
            verify_tree(target, expected, depth + 1)
            continue
        if kind != 'blob':
            raise ValueError('unexpected tree entry')
        if mode == '120000':
            if not stat.S_ISLNK(info.st_mode):
                raise ValueError('symlink type changed')
            data = os.fsencode(os.readlink(target))
            actual = hashlib.new(algorithm, b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        else:
            if mode not in ('100644', '100755') or not stat.S_ISREG(info.st_mode):
                raise ValueError('file type changed')
            if bool(info.st_mode & 0o111) != (mode == '100755'):
                raise ValueError('executable mode changed')
            h = hashlib.new(algorithm, b'blob ' + str(info.st_size).encode() + b'\0')
            with target.open('rb') as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(chunk)
            actual = h.hexdigest()
        if actual != expected:
            raise ValueError('tracked bytes changed')
    git('fsck', '--connectivity-only', '--no-dangling')


def check(root, kata):
    lock = json.loads((root / 'deployment/build/sources.lock.json').read_text())
    runtime = json.loads((root / 'deployment/runtime/artifacts.lock.json').read_text())
    result = {}
    for name, expected in runtime['charts'].items():
        path = root / 'artifacts/cache/helm' / name
        result[name] = 'absent'
        if path.is_file() and not path.is_symlink():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            result[name] = 'passed' if actual == expected else 'hash_mismatch'
    result['kata_full_source'] = 'absent'
    if kata.is_dir():
        try:
            verify_tree(kata, lock['kata-containers']['base'])
            required = ('src/runtime/Makefile', 'src/runtime/go.mod', 'src/agent/Cargo.toml', 'versions.yaml')
            if not all((kata / f).is_file() and not (kata / f).is_symlink() for f in required):
                raise ValueError('required source entry missing')
            result['kata_full_source'] = 'passed'
        except (subprocess.CalledProcessError, OSError, ValueError):
            result['kata_full_source'] = 'incomplete_or_wrong_revision'
    return {'schema': 1, 'checks': result, 'ready': all(v == 'passed' for v in result.values()),
            'scope': 'source_and_helm_only; compiler/dependency/guest builds not run'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kata', type=Path, default=ROOT / '.local/dependencies/kata-containers')
    args = parser.parse_args()
    result = check(ROOT, args.kata)
    print(json.dumps(result, indent=2))
    return 0 if result['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
