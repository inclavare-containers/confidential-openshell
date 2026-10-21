#!/usr/bin/env python3
"""Register reference maps through the authenticated KBS management API."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trustee-config", type=Path, default=Path("/etc/openshell-confidential/trustee-client.json"))
    parser.add_argument("--references", required=True, action="append", type=Path)
    args = parser.parse_args()
    from admin_client import AdminClient
    client = AdminClient(args.trustee_config)
    references = {}
    inputs = []
    for path in args.references:
        raw = path.read_bytes()
        values = json.loads(raw)
        if not isinstance(values, dict) or not values:
            raise ValueError("reference map must be a nonempty object")
        for name, digests in values.items():
            if not re.fullmatch(r"measurement\.[A-Za-z0-9_.-]{1,160}", name):
                raise ValueError("only image/platform measurement references may be registered")
            if (not isinstance(digests, list) or not digests
                    or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{96}", value)
                           for value in digests) or len(set(digests)) != len(digests)):
                raise ValueError("reference values must be distinct SHA-256 or SHA-384 digests")
            if name in references:
                raise ValueError("duplicate reference identifier across input maps")
            references[name] = digests
        inputs.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()})
    provenance = json.dumps(references, sort_keys=True, separators=(",", ":")).encode()
    message = json.dumps({"version": "0.1.0", "type": "sample",
                          "payload": base64.b64encode(provenance).decode("ascii")})
    client.request("POST", "reference-value", message.encode(), json_body=True)
    for name, expected in references.items():
        if json.loads(client.request("GET", "reference-value/" + name)) != expected:
            raise ValueError("RVPS readback differs from the reviewed reference map")
    print(json.dumps({"builtin_rvps_register_and_readback": True,
                      "reference_ids": sorted(references), "inputs": inputs}, sort_keys=True))


if __name__ == "__main__":
    main()
