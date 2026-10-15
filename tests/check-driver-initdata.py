#!/usr/bin/env python3
"""Pass actual Rust-rendered role fixtures through the guest validator offline."""
import base64
import gzip
from pathlib import Path
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent / 'contracts'))
from test_guest_initdata import validate

prefix = Path(sys.argv[1])
for suffix, role, persistent in [('', 'workload', True), ('.ephemeral.toml', 'workload', False), ('.supervisor.toml', 'supervisor', False)]:
    raw = Path(str(prefix) + suffix).read_bytes()
    annotation_suffix = suffix.removesuffix('.toml') + '.annotation'
    encoded = Path(str(prefix) + annotation_suffix).read_bytes()
    assert gzip.decompress(base64.b64decode(encoded, validate=True)) == raw
    data = tomllib.loads(raw.decode())['data']
    result = validate(data)
    assert result['workspace-required.env'] == ('ENCRYPTED_VOLUMES_REQUIRED=' + str(persistent).lower() + '\n').encode()
    print(f'Rust→guest validated: {role}, persistent={persistent}')
