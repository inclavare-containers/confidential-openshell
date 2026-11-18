#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
upstream="$root/repos/openshell/crates/openshell-driver-kubernetes"
local_crate="$root/components/confidential-driver"

expected_commit="$(python3 - "$local_crate/UPSTREAM-SOURCES.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())['upstream_commit'])
PY
)"
actual_commit="$(git -C "$root/repos/openshell" rev-parse HEAD)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
    echo "OpenShell checkout changed: $actual_commit != $expected_commit" >&2
    exit 1
fi

python3 - "$local_crate/UPSTREAM-SOURCES.json" "$upstream" "$local_crate" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys
manifest=json.loads(pathlib.Path(sys.argv[1]).read_text())
source=pathlib.Path(sys.argv[2])
local=pathlib.Path(sys.argv[3])
for name, expected in manifest['files_sha256'].items():
    actual=hashlib.sha256((source/name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'upstream source changed: {name}: {actual} != {expected}')
print(f"verified {len(manifest['files_sha256'])} {manifest['upstream_tag']} upstream source hashes")
shared = set(manifest['compiled_upstream_modules'])
entrypoint = (local / 'src/lib.rs').read_text()
for module in sorted(shared):
    name = f'src/{module}.rs'
    declaration = (f'#[path = "../../../repos/openshell/crates/'
                   f'openshell-driver-kubernetes/{name}"]')
    if (name not in manifest['files_sha256'] or (local / name).exists()
            or not re.search(re.escape(declaration) + r'\s+(?:pub )?mod '
                             + re.escape(module) + ';', entrypoint)):
        raise SystemExit(f'upstream module must be compiled directly: {module}')
print(f"compiled directly from upstream: {', '.join(sorted(shared))}")
delegates = manifest.get('compiled_upstream_delegates', {})
for module, name in delegates.items():
    declaration = (f'#[path = "../../../repos/openshell/crates/'
                   f'openshell-driver-kubernetes/{name}"]')
    entry = local / 'src' / f'{module}.rs'
    if (name != f'src/{module}.rs' or name not in manifest['files_sha256']
            or not re.search(re.escape(declaration) + r'\s+mod upstream;', entry.read_text())
            or 'pub use upstream::*;' not in entry.read_text()):
        raise SystemExit(f'upstream implementation must be delegated directly: {module}')
print(f"delegated to pinned upstream: {', '.join(sorted(delegates))}")
for name in ('driver.rs', 'main.rs', 'image_update.rs', 'lifecycle_tests.rs'):
    file = source / 'src' / name
    target = local / 'src' / name
    result = subprocess.run(['git', 'diff', '--no-index', '--stat', '--',
                             str(file), str(target)])
    if result.returncode not in (0, 1):
        raise SystemExit(result.returncode)
PY
