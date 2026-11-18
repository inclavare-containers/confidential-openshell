#!/usr/bin/env python3
"""Stress the renderer with the pinned official Trustee AS/KBS policy engines.

This runs loopback AS/KBS with synthetic sample evidence/tokens and a fixture
resource. It does not contact production or prove hardware attestation.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import socket
import struct
from pathlib import Path
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent
CHECKER = HERE / "check-policy-denials.py"
spec = importlib.util.spec_from_file_location("check_policy_denials", CHECKER)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def assignment_json(policy, name):
    tail = policy.split(name + " := ", 1)[1]
    _, end = json.JSONDecoder().raw_decode(tail)
    return tail[:end]


def fixture_binding(directory, index):
    role = "supervisor" if index % 2 else "workload"
    generation = "g{:016x}".format(index + 1)
    sandbox = "sandbox-{}".format(index)
    attempt = "a" * 64
    key = "FILE_{}".format(index)
    identity = sha256(b"openshell-bootstrap-identity-v1\0" + role.encode() + b"\0"
                      + generation.encode() + b"\0" + sandbox.encode() + b"\0" + attempt.encode())
    opaque = sha256(b"openshell-bootstrap-file-v1\0" + identity.encode() + b"\0" + key.encode())
    measured = "6" * 96 if index == 0 else "{:096x}".format(index)
    record = {"resource_path": "resource/default/bootstrap/" + opaque,
              "initdata_sha384": measured, "role": role, "generation": generation,
              "sandbox_id": sandbox, "sandbox_cr_uid": "123e4567-e89b-12d3-a456-426614174000",
              "attempt_id": attempt, "key": key,
              "resource_sha256": "e" * 64, "identity_sha256": identity}
    path = directory / (opaque + ".json")
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    return path


def run(binary, kbs_rootfs, as_binary, as_rootfs):
    with tempfile.TemporaryDirectory(prefix="trustee-renderer-release-") as temporary:
        area = Path(temporary)
        bindings = area / "bindings"
        workspace = area / "workspace-bindings"
        bindings.mkdir()
        workspace.mkdir()
        first = None
        for index in range(14):
            path = fixture_binding(bindings, index)
            if index == 0:
                first = path
        namespace = "openshell"
        uid = "123e4567-e89b-12d3-a456-426614174000"
        identity = sha256(b"openshell-workspace-v1\0" + namespace.encode() + b"\0" + uid.encode())
        workspace_record = {"resource_path": "resource/default/workspace/" + identity,
                            "initdata_sha384": "{:096x}".format(14),
                            "namespace": namespace, "sandbox_cr_uid": uid,
                            "resource_sha256": "e" * 64, "identity_sha256": identity}
        path = workspace / (identity + ".json")
        path.write_text(json.dumps(workspace_record))
        path.chmod(0o600)
        records = [json.loads(item.read_text()) for directory in (bindings, workspace)
                   for item in directory.glob("*.json")]
        distinct_digests = {record["initdata_sha384"] for record in records}
        if len(records) != 15 or len(distinct_digests) < 12:
            raise RuntimeError("stress fixture lacks required binding or digest diversity")
        kbs = area / "kbs.rego"
        attestation = area / "as.rego"
        subprocess.run(["python3", str(HERE.parents[1] / "deployment/trustee/render-kbs-policy.py"),
                        "--bindings-dir", str(bindings), "--workspace-bindings-dir", str(workspace),
                        "--as-policy-output", str(attestation), "--output", str(kbs)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        line_lengths = [max(map(len, path.read_text().splitlines())) for path in (kbs, attestation)]
        if any(length >= 1024 for length in line_lengths):
            raise RuntimeError("rendered policy exceeds Trustee 0.22 line limit")
        kbs_result = checker.check(binary, kbs, first, kbs_rootfs)
        if not kbs_result["passed"]:
            raise RuntimeError("released KBS failed positive or exact PolicyDeny resource policy case")
        as_result = check_released_as(as_binary, as_rootfs, attestation, area)
        return {"passed": True, "binding_count": len(records),
                "distinct_initdata_count": len(distinct_digests),
                "kbs_policy_sha256": sha256(kbs.read_bytes()),
                "as_policy_sha256": sha256(attestation.read_bytes()),
                "kbs_max_line_length": line_lengths[0],
                "as_max_line_length": line_lengths[1],
                "released_kbs_cases": {name: case["http_status"] for name, case in kbs_result["cases"].items()},
                "released_kbs_policy_denials": {name: case["policy_deny"] for name, case in kbs_result["cases"].items() if name != "approved_out_of_date"},
                "released_as": as_result,
                "evidence_level": "isolated_official_release_policy_engines_no_hardware_tee"}


def protobuf_string(number, value):
    raw = value if isinstance(value, bytes) else value.encode()
    length = len(raw)
    result = bytearray([number * 8 + 2])
    while length > 127:
        result.append((length & 127) | 128)
        length >>= 7
    result.append(length)
    return bytes(result) + raw


def grpc_call(address, method, payload, area, service="attestation.AttestationService"):
    frame = b"\x00" + struct.pack(">I", len(payload)) + payload
    headers, response = area / "grpc.private.headers", area / "grpc.private.response"
    subprocess.run(["curl", "--silent", "--show-error", "--fail", "--http2-prior-knowledge",
                    "--max-time", "30", "--dump-header", str(headers), "--output", str(response),
                    "--header", "Content-Type: application/grpc", "--header", "TE: trailers",
                    "--data-binary", "@-", address + "/" + service + "/" + method],
                   input=frame, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if re.findall(r"^grpc-status:\s*(\d+)\s*$", headers.read_text(), re.I | re.M) != ["0"]:
        raise RuntimeError("isolated released AS returned non-success gRPC status")
    data = response.read_bytes()
    if len(data) < 5 or data[0] != 0 or struct.unpack_from(">I", data, 1)[0] != len(data) - 5:
        raise RuntimeError("isolated released AS returned invalid gRPC frame")
    return data[5:]


def check_released_as(binary, rootfs, policy, area):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    address = "http://127.0.0.1:" + str(port)
    config = area / "as.json"
    storage = area / "as-storage"
    config.write_text(json.dumps({"storage_backend": {"storage_type": "LocalFs", "backends": {
        "local_fs": {"dir_path": str(storage)}}}, "rvps_config": {"type": "BuiltIn"}}))
    environment = os.environ.copy()
    environment["RUST_LOG"] = "error"
    log_handle = (area / "as.private.log").open("wb")
    process = subprocess.Popen(checker.release_command(binary, rootfs) + ["--socket", "127.0.0.1:" + str(port),
                               "--config-file", str(config)], stdout=log_handle, stderr=log_handle, env=environment)
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError("isolated released AS did not start")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("isolated released AS did not bind loopback")
        # This isolated AS exposes only loopback gRPC. Deployed registration
        # continues to use the authenticated KBS management API.
        reference_id = "measurement.fixture.sha384"
        reference_values = ["a" * 96]
        message = json.dumps({"version": "0.1.0", "type": "sample", "payload":
            base64.b64encode(json.dumps({reference_id: reference_values}).encode()).decode()})
        reference_service = "reference.ReferenceValueProviderService"
        grpc_call(address, "RegisterReferenceValue", protobuf_string(1, message), area, reference_service)
        response = grpc_call(address, "QueryReferenceValue", protobuf_string(1, reference_id), area, reference_service)
        if response != protobuf_string(1, json.dumps(reference_values, separators=(",", ":"))):
            raise RuntimeError("released AS reference readback differs from registered values")
        raw_policy = policy.read_bytes()
        encoded_policy = base64.urlsafe_b64encode(raw_policy).rstrip(b"=")
        grpc_call(address, "SetAttestationPolicy", protobuf_string(1, "fixture_cpu") + protobuf_string(2, encoded_policy), area)
        stored = storage / "attestation_service_policy/fixture_cpu.rego"
        if stored.read_bytes() != raw_policy:
            raise RuntimeError("released AS stored different rendered policy bytes")
        evidence = base64.urlsafe_b64encode(json.dumps({"svn": "1"}).encode()).rstrip(b"=")
        individual = protobuf_string(1, "sample") + protobuf_string(3, evidence)
        response = grpc_call(address, "AttestationEvaluate", protobuf_string(1, individual) + protobuf_string(2, "fixture"), area)
        if not response or response[0] != 10:
            raise RuntimeError("AS returned no sample appraisal token")
        offset, length, shift = 1, 0, 0
        while True:
            byte = response[offset]
            offset += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
            shift += 7
            if shift >= 64:
                raise ValueError("oversized AS protobuf token")
        if offset + length != len(response):
            raise ValueError("unexpected AS token response")
        token = response[offset:].decode()
        header, claims, signature = token.split(".")
        decoded_header = json.loads(checker.unb64url(header))
        if decoded_header["alg"] != "ES256":
            raise ValueError("released AS did not use ES256")
        public = decoded_header["jwk"]
        key = checker.ec.EllipticCurvePublicNumbers(
            int.from_bytes(checker.unb64url(public["x"]), "big"),
            int.from_bytes(checker.unb64url(public["y"]), "big"), checker.ec.SECP256R1()).public_key()
        raw_signature = checker.unb64url(signature)
        if len(raw_signature) != 64:
            raise ValueError("malformed AS signature")
        der = checker.utils.encode_dss_signature(int.from_bytes(raw_signature[:32], "big"), int.from_bytes(raw_signature[32:], "big"))
        key.verify(der, (header + "." + claims).encode(), checker.ec.ECDSA(checker.hashes.SHA256()))
        appraisal = json.loads(checker.unb64url(claims))["submods"]["cpu0"]
        vector = appraisal["ear_trustworthiness_vector"]
        expected = {"hardware": 97, "executables": 33, "configuration": 36, "file-system": 35}
        if any(vector[name] != value for name, value in expected.items()) or appraisal["ear_status"] == "affirming":
            raise RuntimeError("TDX-only policy affirmed synthetic sample evidence")
        return {"binary_sha256": checker.sha256_file(binary), "set_policy_and_exact_storage": True,
                "builtin_rvps_registration_and_readback": True, "sample_ES256_verified": True,
                "sample_rejected_by_TDX_policy": True, "sample_vector": expected}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log_handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kbs-binary", type=Path)
    parser.add_argument("--kbs-rootfs", type=Path)
    parser.add_argument("--grpc-as-binary", type=Path)
    parser.add_argument("--grpc-as-rootfs", type=Path)
    args = parser.parse_args()
    binary = args.kbs_binary or (args.kbs_rootfs / "usr/local/bin/kbs" if args.kbs_rootfs else None)
    as_binary = args.grpc_as_binary or (args.grpc_as_rootfs / "usr/local/bin/grpc-as" if args.grpc_as_rootfs else None)
    if binary is None or as_binary is None:
        parser.error("supply a released binary or extracted official rootfs for both KBS and gRPC AS")
    print(json.dumps(run(binary.resolve(), args.kbs_rootfs.resolve() if args.kbs_rootfs else None,
                         as_binary.resolve(), args.grpc_as_rootfs.resolve() if args.grpc_as_rootfs else None), sort_keys=True))


if __name__ == "__main__":
    main()
