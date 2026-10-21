#!/usr/bin/env python3
"""Print the measured base initdata used by the independent driver."""

from __future__ import annotations

import argparse
import json
from urllib.parse import urlsplit
import pathlib
import sys
import tomllib


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kbs-url", required=True)
    parser.add_argument("--kbs-ca", required=True, type=pathlib.Path)
    parser.add_argument("--registry-ca", required=True, type=pathlib.Path)
    args = parser.parse_args()
    endpoint = args.kbs_url.rstrip('/')
    address = urlsplit(endpoint)
    if (address.scheme != 'https' or not address.hostname or address.username or address.password
            or address.path or address.query or address.fragment):
        raise SystemExit("KBS URL must be a cloud-reachable HTTPS origin")
    ca_path = args.kbs_ca
    if ca_path.is_symlink() or not ca_path.is_file():
        raise SystemExit("Trustee CA must be a regular file")
    ca = ca_path.read_text().rstrip()
    if '"""' in ca or "'''" in ca:
        raise SystemExit("Trustee CA cannot be represented safely in initdata")
    registry_ca = args.registry_ca.read_text().rstrip()
    if chr(34) * 3 in registry_ca or chr(39) * 3 in registry_ca:
        raise SystemExit("Registry CA cannot be represented safely in initdata")
    aa = f'''[eventlog_config]
enable_eventlog = true
init_pcr = 17
[token_configs.kbs]
url = {json.dumps(endpoint)}
tee_key_algorithm = "ECDH-ES+A256KW-P256"
cert = """\n{ca}\n"""
'''
    cdh = f'''socket = "unix:///run/confidential-containers/cdh.sock"
credentials = []
[kbc]
name = "cc_kbc"
url = {json.dumps(endpoint)}
kbs_cert = """\n{ca}\n"""
[image]
work_dir = "/var/lib/confidential-containers/image"
extra_root_certificates = ["""\n{registry_ca}\n"""]
'''
    policy = "package agent_policy\nimport rego.v1\ndefault allow := false\n"
    values = {"aa.toml": aa, "cdh.toml": cdh, "policy.rego": policy}
    doc = 'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n' + "".join(
        f'"{name}" = \'\'\'\n{value}\'\'\'\n' for name, value in values.items())
    parsed = tomllib.loads(doc)
    if (tomllib.loads(parsed["data"]["aa.toml"])["token_configs"]["kbs"]["cert"].strip() != ca or
            tomllib.loads(parsed["data"]["cdh.toml"])["kbc"]["kbs_cert"].strip() != ca):
        raise SystemExit("Trustee CA changed while rendering initdata")
    sys.stdout.write(doc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
