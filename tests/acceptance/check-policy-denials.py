#!/usr/bin/env python3
"""Exercise a copy of the active KBS policy with the released KBS binary.

This is synthetic policy-engine evidence. Live TDX quote verification and EAR
signature validation remain separate deployment gates.
"""

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signed_token(issuer, issuer_jwk, tee_pubkey, digest, tcb="OutOfDate", attributes="0000001000000000",
                 event_digest_override=None, index=4, digest_matches_event=True):
    header = {"alg": "ES256", "jwk": issuer_jwk}
    text = ('github.com/confidential-containers InitData '
            f'{{"digest":"sha384:{digest}"}}').encode("ascii")
    event_digest = hashlib.sha384(struct.pack("<II", 0x4141454c, len(text)) + text).hexdigest()
    event = {"index": index, "type_name": "EV_EVENT_TAG", "digest_matches_event": digest_matches_event,
             "digests": [{"alg": "SHA-384", "digest": event_digest_override or event_digest}],
             "details": {"unicode_name": "AAEL", "data": {
        "domain": "github.com/confidential-containers", "operation": "InitData", "content": {"digest": "sha384:" + digest},
    }}}
    claims = {
        "exp": int(time.time()) + 120, "nbf": int(time.time()) - 10,
        "submods": {"cpu0": {
            "ear.appraisal-policy-id": "openshell-tdx", "ear.status": "affirming",
            "ear.trustworthiness-vector": {
                "hardware": 2, "configuration": 2, "executables": 3, "file-system": 2,
            },
            "ear.veraison.annotated-evidence": {"runtime_data_claims": {"tee-pubkey": tee_pubkey}, "tdx": {
                "tcb_status": tcb,
                "quote": {"body": {"td_attributes": attributes}},
                "uefi_event_logs": [event],
            }},
        }},
    }
    message = ".".join(b64url(json.dumps(value, separators=(",", ":")).encode()) for value in (header, claims))
    der = issuer.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return message + "." + b64url(signature)


def request(url, token=None):
    headers = {} if token is None else {"Authorization": "Bearer " + token}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def release_command(binary, rootfs=None):
    if rootfs is None:
        return [str(binary)]
    libraries = [rootfs / path for path in (
        "usr/lib/x86_64-linux-gnu", "lib/x86_64-linux-gnu",
        "usr/local/lib/x86_64-linux-gnu", "usr/local/lib")]
    loader = next((path / "ld-linux-x86-64.so.2" for path in libraries
                   if (path / "ld-linux-x86-64.so.2").is_file()), None)
    if loader is None:
        raise ValueError("released image rootfs has no amd64 dynamic loader")
    return [str(loader), "--library-path", os.pathsep.join(map(str, libraries)), str(binary)]


def error_witness(body, logs):
    try:
        information = json.loads(body)
        error_type = information.get("type", "")
    except (ValueError, AttributeError):
        error_type = ""
    plain_logs = re.sub(r"\x1b\[[0-9;]*m", "", logs)
    policy_deny = error_type.endswith("/PolicyDeny") or any(
        re.search(r"(?:^|\s)PolicyDeny\s*$", line) for line in plain_logs.splitlines())
    policy_load_error = "PolicyLoadError" in logs
    return {"policy_deny": policy_deny, "policy_load_error": policy_load_error,
            "error_type": error_type if error_type.startswith("https://github.com/confidential-containers/kbs/errors/") else None}


def check(binary, policy_path, binding_path, rootfs=None):
    original_policy = policy_path.read_bytes()
    original_binding = binding_path.read_bytes()
    binding = json.loads(original_binding)
    resource_path = binding["resource_path"]
    digest = binding["initdata_sha384"]
    if not resource_path.startswith("resource/default/bootstrap/") or len(resource_path.split("/")[-1]) != 64:
        raise ValueError("binding is not a per-key bootstrap resource")
    if len(digest) != 96 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("binding has invalid initdata SHA-384")
    policy_hash = sha256(original_policy)
    binding_hash = sha256(original_binding)
    binary_hash = sha256_file(binary)
    fixture = b"isolated-policy-check-fixture"
    with tempfile.TemporaryDirectory(prefix="kbs-policy-check-") as root:
        area = Path(root)
        storage = area / "storage"
        (storage / "kbs").mkdir(parents=True)
        (storage / "kbs/resource-policy.rego").write_bytes(original_policy)
        (storage / "repository").mkdir()
        resource = storage / "repository" / resource_path.removeprefix("resource/").replace("/", "\\x2F")
        resource.write_bytes(fixture)
        issuer = ec.generate_private_key(ec.SECP256R1())
        numbers = issuer.public_key().public_numbers()
        issuer_jwk = {"kty": "EC", "crv": "P-256", "alg": "ES256",
                      "x": b64url(numbers.x.to_bytes(32, "big")),
                      "y": b64url(numbers.y.to_bytes(32, "big"))}
        recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = recipient.public_key().public_numbers()
        tee_pubkey = {"kty": "RSA", "alg": "RSA-OAEP-256",
                      "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                      "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))}
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        config = area / "kbs.toml"
        config.write_text(
            '[http_server]\nsockets=["127.0.0.1:{}"]\ninsecure_http=true\n'
            '[attestation_token]\ninsecure_header_jwk=true\n'
            '[attestation_service]\ntype="coco_as_grpc"\nas_addr="http://127.0.0.1:9"\n'
            '[admin]\nauthorization_mode="DenyAll"\n'
            '[[plugins]]\nname="resource"\nstorage_backend_type="kvstorage"\n'
            '[storage_backend]\nstorage_type="LocalFs"\n'
            '[storage_backend.backends.local_fs]\ndir_path="{}"\n'.format(port, storage))
        logs = area / "kbs.private.log"
        log_handle = logs.open("wb")
        environment = os.environ.copy()
        environment["RUST_LOG"] = "kbs=error,policy_engine=error"
        process = subprocess.Popen(release_command(binary, rootfs) + ["--config-file", str(config)],
                                   stdout=log_handle, stderr=log_handle, env=environment)
        url = "http://127.0.0.1:{}/kbs/v0/{}".format(port, resource_path)
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("isolated KBS failed to start; inspect isolated release/config compatibility")
                try:
                    request(url)
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("isolated KBS did not bind loopback")
            cases = {}
            for name, value, tcb, attributes, event_digest, index, protected, approved in (
                ("approved_out_of_date", digest, "OutOfDate", "0000001000000000", None, 4, True, True),
                ("wrong_initdata_digest", "9" * 96 if digest != "9" * 96 else "8" * 96,
                 "OutOfDate", "0000001000000000", None, 4, True, False),
                ("revoked_tcb", digest, "Revoked", "0000001000000000", None, 4, True, False),
                ("debug_td", digest, "OutOfDate", "0100001000000000", None, 4, True, False),
                ("approved_text_with_unrelated_event_digest", digest,
                 "OutOfDate", "0000001000000000", "0" * 96, 4, True, False),
                ("wrong_measurement_register", digest, "OutOfDate", "0000001000000000", None, 3, True, False),
                ("unprotected_event_description", digest, "OutOfDate", "0000001000000000", None, 4, False, False),
            ):
                offset = logs.stat().st_size
                token = signed_token(issuer, issuer_jwk, tee_pubkey, value, tcb, attributes, event_digest, index, protected)
                status, body = request(url, token)
                log_handle.flush()
                delta = logs.read_bytes()[offset:].decode("utf-8", errors="replace")
                witness = error_witness(body, delta)
                case = {"http_status": status, "expected_result": "release" if approved else "PolicyDeny",
                        **witness, "passed": status == 200 if approved else status in (401, 403, 500) and witness["policy_deny"] and not witness["policy_load_error"]}
                if name == "approved_out_of_date" and status == 200:
                    jwe = json.loads(body)
                    cek = recipient.decrypt(unb64url(jwe["encrypted_key"]), padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                    plaintext = AESGCM(cek).decrypt(unb64url(jwe["iv"]),
                                                     unb64url(jwe["ciphertext"]) + unb64url(jwe["tag"]),
                                                     jwe["protected"].encode())
                    case["jwe_matches_fixture"] = plaintext == fixture and fixture not in body
                    case["passed"] = case["passed"] and case["jwe_matches_fixture"]
                cases[name] = case
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log_handle.close()
    unchanged = sha256(policy_path.read_bytes()) == policy_hash and sha256(binding_path.read_bytes()) == binding_hash
    return {
        "schema_version": 1,
        "evidence_level": "isolated_release_kbs_synthetic_token_no_hardware_tee",
        "policy_path": str(policy_path), "policy_sha256": policy_hash,
        "binding_path": str(binding_path), "binding_sha256": binding_hash,
        "kbs_binary_path": str(binary), "kbs_binary_sha256": binary_hash,
        "resource_path": resource_path, "cases": cases,
        "production_inputs_unchanged": unchanged,
        "passed": unchanged and all(case["passed"] for case in cases.values()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kbs-binary", type=Path)
    parser.add_argument("--kbs-rootfs", type=Path, help="Optional extracted official amd64 image rootfs for its matching loader")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.kbs_binary or ((args.kbs_rootfs / "usr/local/bin/kbs") if args.kbs_rootfs else Path("/usr/local/bin/kbs"))
    result = check(binary.resolve(), args.policy, args.binding, args.kbs_rootfs.resolve() if args.kbs_rootfs else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".policy-denials.", dir=args.output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(result, target, sort_keys=True, indent=2)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp, args.output)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(json.dumps({"passed": result["passed"], "policy_sha256": result["policy_sha256"],
                      "cases": {name: case["http_status"] for name, case in result["cases"].items()}}))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
