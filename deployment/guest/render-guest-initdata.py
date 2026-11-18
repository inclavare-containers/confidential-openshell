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
    parser.add_argument("--registry-ca", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--attestation-policy-selector", default="openshell-tdx")
    args = parser.parse_args()
    endpoint = args.kbs_url.rstrip('/')
    address = urlsplit(endpoint)
    if (address.scheme != 'https' or not address.hostname or address.username or address.password
            or address.path or address.query or address.fragment):
        raise SystemExit("KBS URL must be a cloud-reachable HTTPS origin")
    ca = args.kbs_ca.read_text().rstrip()
    registry_cas = [path.read_text().rstrip() for path in args.registry_ca]
    aa = f'''[eventlog_config]
init_pcr = 17
[token_configs.kbs]
url = {json.dumps(endpoint)}
tee_key_algorithm = "ECDH-ES+A256KW-P256"
attestation_policy_selector = {json.dumps(args.attestation_policy_selector)}
cert = {json.dumps(ca)}
'''
    cdh = f'''socket = "unix:///run/confidential-containers/cdh.sock"
credentials = []
[kbc]
name = "cc_kbc"
url = {json.dumps(endpoint)}
kbs_cert = {json.dumps(ca)}
[image]
work_dir = "/var/lib/confidential-containers/image"
extra_root_certificates = {json.dumps(registry_cas)}
'''
    policy = "package agent_policy\nimport rego.v1\ndefault allow := false\n"
    values = {"aa.toml": aa, "cdh.toml": cdh, "policy.rego": policy}
    doc = 'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n' + "".join(
        f'{json.dumps(name)} = {json.dumps(value)}\n' for name, value in values.items())
    parsed = tomllib.loads(doc)
    if (tomllib.loads(parsed["data"]["aa.toml"])["token_configs"]["kbs"]["cert"].strip() != ca or
            tomllib.loads(parsed["data"]["cdh.toml"])["kbc"]["kbs_cert"].strip() != ca):
        raise SystemExit("Trustee CA changed while rendering initdata")
    sys.stdout.write(doc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
