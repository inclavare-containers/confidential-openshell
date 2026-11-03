#!/usr/bin/env python3
"""Atomically render Trustee's per-request resource policy from binding records."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
from typing import Dict, Tuple


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX96 = re.compile(r"[0-9a-f]{96}\Z")
GENERATION = re.compile(r"[a-z0-9-]{1,64}\Z")
KEY = re.compile(r"[A-Za-z0-9_.-]+\Z")
TEMPLATE = Path(__file__).resolve().parent.parent / "policy" / "kbs-sealed.rego"
MARKER = "bindings := {}"
AS_TEMPLATE = Path(__file__).resolve().parent.parent / "policy" / "tdx-podvm.rego"
AS_MARKER = "approved_initdata := []"
AS_EVENT_MARKER = "approved_initdata_events := {}"
KBS_EVENT_MARKER = "approved_initdata_events := {}"
REGORUS_MAX_COLUMN = 1024


def initdata_event_sha384(digest: str) -> str:
    """Hash the AA's complete TCG2 tagged event, including its LE header."""
    if not HEX96.fullmatch(digest):
        raise ValueError("invalid measured initdata digest")
    text = ('github.com/confidential-containers InitData '
            f'{{"digest":"sha384:{digest}"}}').encode("ascii")
    event = struct.pack("<II", 0x4141454C, len(text)) + text
    return hashlib.sha384(event).hexdigest()


def read_binding(path: Path) -> Tuple[str, Dict[str, str]]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"binding is not a regular private file: {path}")
    if metadata.st_mode & 0o077:
        raise ValueError(f"binding is accessible to other users: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        record = json.load(source)
    if not isinstance(record, dict):
        raise ValueError(f"binding must be an object: {path}")
    required = {
        "resource_path", "initdata_sha384", "role", "generation",
        "sandbox_id", "sandbox_cr_uid", "attempt_id", "key", "resource_sha256", "identity_sha256",
    }
    if set(record) != required or any(not isinstance(v, str) for v in record.values()):
        raise ValueError(f"binding schema mismatch: {path}")
    opaque = path.stem
    if not HEX64.fullmatch(opaque) or path.suffix != ".json":
        raise ValueError(f"invalid binding filename: {path}")
    if record["resource_path"] != f"resource/default/bootstrap/{opaque}":
        raise ValueError(f"binding path and filename disagree: {path}")
    if not HEX96.fullmatch(record["initdata_sha384"]):
        raise ValueError(f"invalid measured initdata digest: {path}")
    if record["role"] not in ("workload", "supervisor"):
        raise ValueError(f"invalid role: {path}")
    if not GENERATION.fullmatch(record["generation"]):
        raise ValueError(f"invalid generation: {path}")
    if not record["sandbox_id"] or len(record["sandbox_id"]) > 253 or any(ord(c) < 33 for c in record["sandbox_id"]):
        raise ValueError(f"invalid sandbox ID: {path}")
    if len(record["sandbox_cr_uid"]) > 253 or not KEY.fullmatch(record["sandbox_cr_uid"]):
        raise ValueError(f"invalid Sandbox CR UID: {path}")
    if not HEX64.fullmatch(record["attempt_id"]):
        raise ValueError(f"invalid attempt ID: {path}")
    if not KEY.fullmatch(record["key"]):
        raise ValueError(f"invalid Secret key: {path}")
    if not HEX64.fullmatch(record["resource_sha256"]):
        raise ValueError(f"invalid resource digest: {path}")
    identity = hashlib.sha256(
        b"openshell-bootstrap-identity-v1\0"
        + record["role"].encode() + b"\0"
        + record["generation"].encode() + b"\0"
        + record["sandbox_id"].encode() + b"\0"
        + record["attempt_id"].encode()
    ).hexdigest()
    expected_opaque = hashlib.sha256(
        b"openshell-bootstrap-file-v1\0"
        + identity.encode() + b"\0" + record["key"].encode()
    ).hexdigest()
    if record["identity_sha256"] != identity or opaque != expected_opaque:
        raise ValueError(f"binding identity or resource path does not match metadata: {path}")
    return (
        f"resource/default/bootstrap/{opaque}",
        {"kind": "bootstrap", "initdata_sha384": record["initdata_sha384"], "role": record["role"], "generation": record["generation"]},
    )


def read_workspace_binding(path: Path) -> Tuple[str, Dict[str, str]]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
        raise ValueError(f"workspace binding is not a regular private file: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        record = json.load(source)
    required = {"resource_path", "initdata_sha384", "namespace", "sandbox_cr_uid", "resource_sha256", "identity_sha256"}
    if not isinstance(record, dict) or set(record) != required or any(not isinstance(v, str) for v in record.values()):
        raise ValueError(f"workspace binding schema mismatch: {path}")
    opaque = path.stem
    if not HEX64.fullmatch(opaque) or path.suffix != ".json":
        raise ValueError(f"invalid workspace binding filename: {path}")
    if record["resource_path"] != f"resource/default/workspace/{opaque}":
        raise ValueError(f"workspace binding path and filename disagree: {path}")
    if not HEX96.fullmatch(record["initdata_sha384"]) or not HEX64.fullmatch(record["resource_sha256"]):
        raise ValueError(f"invalid workspace digest: {path}")
    if not KEY.fullmatch(record["namespace"]) or not KEY.fullmatch(record["sandbox_cr_uid"]):
        raise ValueError(f"invalid workspace identity: {path}")
    identity = hashlib.sha256(
        b"openshell-workspace-v1\0"
        + record["namespace"].encode() + b"\0"
        + record["sandbox_cr_uid"].encode()
    ).hexdigest()
    if opaque != identity or record["identity_sha256"] != identity:
        raise ValueError(f"workspace binding identity does not match metadata: {path}")
    return (record["resource_path"], {"kind": "workspace", "role": "workload", "initdata_sha384": record["initdata_sha384"]})


def write_policy(output: Path, policy: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not output.is_file():
        raise ValueError(f"policy output is not a regular file: {output}")
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(policy)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, output)
        dir_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def require_supported_line_lengths(policy: str, description: str) -> None:
    # Trustee 0.22's regorus 0.11 loader rejects a source line once its
    # column count exceeds 1024, before any resource authorization is run.
    if any(len(line) >= REGORUS_MAX_COLUMN for line in policy.splitlines()):
        raise ValueError(f"{description} exceeds Trustee's Rego line limit")


def render(bindings_dir: Path, output: Path, as_output: Path, workspace_bindings_dir: Path = None) -> None:
    directory = bindings_dir.lstat()
    if not stat.S_ISDIR(directory.st_mode):
        raise ValueError(f"bindings path is not a directory: {bindings_dir}")
    bindings = {}
    for path in sorted(bindings_dir.iterdir()):
        if path.name.startswith("."):
            continue
        resource_path, binding = read_binding(path)
        if resource_path in bindings:
            raise ValueError(f"duplicate binding: {resource_path}")
        bindings[resource_path] = binding
    if workspace_bindings_dir is not None:
        workspace_directory = workspace_bindings_dir.lstat()
        if not stat.S_ISDIR(workspace_directory.st_mode):
            raise ValueError(f"workspace bindings path is not a directory: {workspace_bindings_dir}")
        for path in sorted(workspace_bindings_dir.iterdir()):
            if path.name.startswith("."):
                continue
            resource_path, binding = read_workspace_binding(path)
            if resource_path in bindings:
                raise ValueError(f"duplicate binding: {resource_path}")
            bindings[resource_path] = binding
    template = TEMPLATE.read_text(encoding="utf-8")
    if template.count(MARKER) != 1:
        raise ValueError("KBS policy template has no unique bindings marker")
    policy = template.replace(MARKER, "bindings := " + json.dumps(bindings, sort_keys=True, indent=2))
    as_template = AS_TEMPLATE.read_text(encoding="utf-8")
    if as_template.count(AS_MARKER) != 1:
        raise ValueError("AS policy template has no unique approved initdata marker")
    active_digests = sorted({binding["initdata_sha384"] for binding in bindings.values()})
    events = json.dumps({digest: initdata_event_sha384(digest) for digest in active_digests},
                        sort_keys=True, indent=2)
    if template.count(KBS_EVENT_MARKER) != 1 or as_template.count(AS_EVENT_MARKER) != 1:
        raise ValueError("policy template has no unique initdata event marker")
    policy = policy.replace(KBS_EVENT_MARKER, "approved_initdata_events := " + events)
    as_policy = as_template.replace(AS_MARKER, "approved_initdata := " + json.dumps(active_digests, indent=2))
    as_policy = as_policy.replace(AS_EVENT_MARKER, "approved_initdata_events := " + events)
    require_supported_line_lengths(policy, "KBS policy")
    require_supported_line_lengths(as_policy, "AS policy")
    # The AS may see the new digest before KBS does. During publication the
    # resource is still absent; during revocation it is removed first.
    write_policy(as_output, as_policy)
    write_policy(output, policy)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings-dir", required=True, type=Path)
    parser.add_argument("--workspace-bindings-dir", type=Path)
    parser.add_argument("--as-policy-output", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trustee-config", type=Path)
    parser.add_argument("--resources-dir", type=Path)
    parser.add_argument("--publication-journal", type=Path)
    args = parser.parse_args()
    render(args.bindings_dir, args.output, args.as_policy_output, args.workspace_bindings_dir)
    if args.trustee_config:
        if not args.resources_dir or not args.publication_journal:
            parser.error("API publication requires resources-dir and publication-journal")
        from admin_client import AdminClient, staged_resources, synchronize
        synchronize(AdminClient(args.trustee_config), staged_resources(args.resources_dir),
                    args.output.read_bytes(), args.as_policy_output.read_bytes(), args.publication_journal)


if __name__ == "__main__":
    main()
