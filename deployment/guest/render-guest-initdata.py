#!/usr/bin/env python3
"""Print the measured base initdata used by the independent driver."""

from __future__ import annotations

import ipaddress
import pathlib
import sys
import tomllib


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: render-guest-initdata.py HOST_PRIVATE_IPV4 TRUSTEE_CA_PEM")
    address = ipaddress.IPv4Address(sys.argv[1])
    private_ranges = tuple(ipaddress.IPv4Network(cidr) for cidr in
                           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not any(address in network for network in private_ranges):
        raise SystemExit("Trustee endpoint must be a private non-loopback IPv4 address")
    ca_path = pathlib.Path(sys.argv[2])
    if ca_path.is_symlink() or not ca_path.is_file():
        raise SystemExit("Trustee CA must be a regular file")
    ca = ca_path.read_text().rstrip()
    if '"""' in ca or "'''" in ca:
        raise SystemExit("Trustee CA cannot be represented safely in initdata")
    endpoint = f"https://{address}:8443"
    aa = f'''[eventlog_config]
enable_eventlog = true
init_pcr = 17
[token_configs.kbs]
url = "{endpoint}"
tee_key_algorithm = "ECDH-ES+A256KW-P256"
cert = """\n{ca}\n"""
'''
    cdh = f'''socket = "unix:///run/confidential-containers/cdh.sock"
credentials = []
[kbc]
name = "cc_kbc"
url = "{endpoint}"
kbs_cert = """\n{ca}\n"""
[image]
extra_root_certificates = ["""\n{ca}\n"""]
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
