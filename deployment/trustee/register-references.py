#!/usr/bin/env python3
"""Register reviewed reference maps in upstream AS's loopback BuiltIn RVPS."""

import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from urllib.parse import urlparse


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def decode_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("oversized protobuf varint")


def rpc(address, method, value):
    raw = value.encode("utf-8")
    message = b"\x0a" + varint(len(raw)) + raw
    with tempfile.TemporaryDirectory(prefix="trustee-rvps-") as directory:
        area = Path(directory)
        request = area / "request.bin"
        response = area / "response.bin"
        headers = area / "headers.txt"
        request.write_bytes(b"\x00" + struct.pack(">I", len(message)) + message)
        subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--http2-prior-knowledge",
            "--max-time", "30", "--dump-header", str(headers),
            "--header", "Content-Type: application/grpc", "--header", "TE: trailers",
            "--data-binary", "@" + str(request), "--output", str(response),
            address + "/reference.ReferenceValueProviderService/" + method,
        ], check=True)
        statuses = re.findall(r"^grpc-status:\s*(\d+)\s*$", headers.read_text(), re.I | re.M)
        if statuses != ["0"]:
            raise RuntimeError("RVPS returned non-success or missing gRPC status")
        data = response.read_bytes()
        if len(data) < 5 or data[0] != 0 or struct.unpack_from(">I", data, 1)[0] != len(data) - 5:
            raise ValueError("invalid RVPS gRPC response frame")
        return data[5:]


def query(address, name):
    data = rpc(address, "QueryReferenceValue", name)
    if not data:
        raise ValueError("registered RVPS reference is missing")
    tag, offset = decode_varint(data, 0)
    length, offset = decode_varint(data, offset)
    if tag != 10 or offset + length != len(data):
        raise ValueError("invalid RVPS query response")
    return json.loads(data[offset:].decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default="http://127.0.0.1:50004")
    parser.add_argument("--references", required=True, action="append", type=Path)
    args = parser.parse_args()
    endpoint = urlparse(args.address)
    if (endpoint.scheme != "http" or endpoint.username or endpoint.password
            or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment
            or not endpoint.port or not ipaddress.ip_address(endpoint.hostname).is_loopback):
        raise ValueError("RVPS administration requires an explicit loopback HTTP endpoint")
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
    if rpc(args.address.rstrip("/"), "RegisterReferenceValue", message):
        raise ValueError("unexpected RVPS registration response")
    for name, expected in references.items():
        if query(args.address.rstrip("/"), name) != expected:
            raise ValueError("RVPS readback differs from the reviewed reference map")
    print(json.dumps({"builtin_rvps_register_and_readback": True,
                      "reference_ids": sorted(references), "inputs": inputs}, sort_keys=True))


if __name__ == "__main__":
    main()
