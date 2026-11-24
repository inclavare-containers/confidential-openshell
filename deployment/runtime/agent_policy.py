#!/usr/bin/env python3
"""Generate a Kata 4.4 policy from the trusted OpenShell launch template.

The confidential driver calls this program before it adds initdata to a Pod.
One Pod JSON document is read from stdin; only Rego is written to stdout.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKLOAD_EXTENSION = ROOT / "deployment/policy/agent-policy-workload.rego"
DEFAULT_OCI_VERSION = "1.3.0"
KATA_TOOL_HASHES = {
    "genpolicy": "3f3b65d4410a86e58955c15a10c3b324fa7d41d41205064c73e5d121fe32c1d9",
    "rules.rego": "0dd95a1d9d194e8e2ce71ba5befb40c813475457b100c35d9f26a1dc77894d10",
    "genpolicy-settings.json": "04bf91a0ec5154fd4aa16c20b23dc985bfeba4d90f041b01b2d70993bc4272d6",
}
ROLE_LABEL = "openshell.ai/boundary-role"
INITDATA_ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"
DIGEST_IMAGE = re.compile(r"^[a-z0-9._:/-]+@sha256:[a-f0-9]{64}$")


class PolicyError(Exception):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_pod() -> dict:
    raw = sys.stdin.buffer.read()
    try:
        pod = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PolicyError(f"invalid Pod JSON: {exc}") from exc
    if not isinstance(pod, dict):
        raise PolicyError("Pod JSON must be an object")
    if "expected" in pod or "admitted" in pod:
        if set(pod) != {"expected", "admitted"}:
            raise PolicyError("policy envelope requires expected and admitted Pods")
        return _trusted_policy_pod(pod["expected"], pod["admitted"])
    # Direct CLI input is an operator-supplied trusted Pod. The driver always
    # supplies the envelope above; U cannot select this operator-only path.
    return pod


def _default_pod(pod: dict) -> dict:
    result = copy.deepcopy(pod)
    spec = result["spec"]
    for key, value in {"restartPolicy": "Always", "dnsPolicy": "ClusterFirst",
                       "terminationGracePeriodSeconds": 30, "serviceAccountName": "default",
                       "hostNetwork": False, "hostPID": False, "hostIPC": False,
                       "shareProcessNamespace": False}.items():
        spec.setdefault(key, value)
    alias = spec.pop("serviceAccount", spec["serviceAccountName"])
    if alias != spec["serviceAccountName"]:
        raise PolicyError("service account aliases disagree")
    if "securityContext" in spec:
        spec["securityContext"].setdefault("supplementalGroups", [])
        spec["securityContext"].setdefault("supplementalGroupsPolicy", "Merge")
    # U controls placement, not execution. These fields are not policy inputs.
    for key in ("nodeName", "nodeSelector", "tolerations", "affinity", "schedulerName",
                "priority", "priorityClassName", "preemptionPolicy", "topologySpreadConstraints", "overhead"):
        spec.pop(key, None)
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        for key, value in {"imagePullPolicy": "IfNotPresent", "terminationMessagePath": "/dev/termination-log",
                           "terminationMessagePolicy": "File", "resources": {}}.items():
            container.setdefault(key, value)
        for port in container.get("ports", []):
            port.setdefault("protocol", "TCP")
        for mount in container.get("volumeMounts", []):
            mount.setdefault("readOnly", False)
        for entry in container.get("env", []):
            if "valueFrom" not in entry:
                entry.setdefault("value", "")
            if "fieldRef" in entry.get("valueFrom", {}):
                entry["valueFrom"]["fieldRef"].setdefault("apiVersion", "v1")
        for key in ("livenessProbe", "readinessProbe", "startupProbe"):
            if key not in container:
                continue
            probe = container[key]
            for field, value in {"failureThreshold": 3, "successThreshold": 1,
                                 "periodSeconds": 10, "timeoutSeconds": 1, "initialDelaySeconds": 0}.items():
                probe.setdefault(field, value)
            if "httpGet" in probe:
                probe["httpGet"].setdefault("scheme", "HTTP")
        security = container.get("securityContext")
        if security is not None:
            security.setdefault("privileged", False)
    for volume in spec.get("volumes", []):
        for key in ("secret", "configMap", "downwardAPI", "projected"):
            if key in volume:
                source = volume[key]
                source.setdefault("defaultMode", 420)
                for item in source.get("items", []):
                    if "fieldRef" in item:
                        item["fieldRef"].setdefault("apiVersion", "v1")
        if "persistentVolumeClaim" in volume:
            volume["persistentVolumeClaim"].setdefault("readOnly", False)
    spec["volumes"] = sorted(spec.get("volumes", []), key=lambda v: v["name"])
    if not spec.get("imagePullSecrets"):
        spec.pop("imagePullSecrets", None)
    return result


def _trusted_policy_pod(expected: dict, admitted: dict) -> dict:
    """Accept only execution-preserving defaults; generate from T's input."""
    if not all(isinstance(p, dict) and isinstance(p.get("spec"), dict)
               and isinstance(p.get("metadata"), dict) for p in (expected, admitted)):
        raise PolicyError("trusted and admitted Pods are required")
    for key in ("name", "namespace"):
        if admitted["metadata"].get(key) != expected["metadata"].get(key):
            raise PolicyError(f"admitted Pod changed trusted {key}")
    for key, value in expected["metadata"].get("labels", {}).items():
        if admitted["metadata"].get("labels", {}).get(key) != value:
            raise PolicyError("admitted Pod changed trusted labels")
    trusted = _default_pod(expected)
    actual = _default_pod(admitted)
    if trusted["spec"].get("runtimeClassName") != "kata-qemu-tdx":
        # PeerPods replaces container resource accounting with its VM resource.
        for container in trusted["spec"].get("containers", []) + trusted["spec"].get("initContainers", []):
            container["resources"] = {}
        trusted["spec"]["containers"][0]["resources"] = {
            "requests": {"kata.peerpods.io/vm": "1"}, "limits": {"kata.peerpods.io/vm": "1"}}
    if trusted["spec"] != actual["spec"]:
        # Do not print the diff: it can contain user-supplied command arguments.
        raise PolicyError("admitted Pod execution differs from trusted launch intent")
    trusted["metadata"].setdefault("annotations", {})[INITDATA_ANNOTATION] = ""
    trusted.pop("status", None)
    return trusted


def _names(containers: object, label: str) -> list[str]:
    if not isinstance(containers, list):
        raise PolicyError(f"Pod {label} must be an array")
    names: list[str] = []
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get("name"), str):
            raise PolicyError(f"Pod {label} has an unnamed container")
        image = container.get("image")
        if not isinstance(image, str) or not DIGEST_IMAGE.fullmatch(image):
            raise PolicyError(f"Pod {label} container image must be an immutable sha256 digest reference")
        names.append(container["name"])
    if len(names) != len(set(names)):
        raise PolicyError(f"Pod {label} has duplicate container names")
    return names


def _validate_pod(pod: dict, role: str, runtime_class: str) -> set[str]:
    if pod.get("apiVersion") != "v1" or pod.get("kind") != "Pod":
        raise PolicyError("policy input must be one v1 Pod")
    metadata, spec = pod.get("metadata"), pod.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise PolicyError("Pod metadata and spec are required")
    if metadata.get("labels", {}).get(ROLE_LABEL) != role:
        raise PolicyError(f"Pod boundary role must be {role}")
    if spec.get("runtimeClassName") != runtime_class:
        raise PolicyError(f"Pod must select runtime class {runtime_class}")
    if metadata.get("annotations", {}).get(INITDATA_ANNOTATION):
        raise PolicyError("Pod already has initdata; policy generation must precede initdata binding")
    gates = spec.get("schedulingGates")
    if not isinstance(gates, list) or not any(
        isinstance(gate, dict) and gate.get("name") == "openshell.ai/bootstrap" for gate in gates
    ):
        raise PolicyError("Pod must remain behind the bootstrap scheduling gate")
    names = _names(spec.get("containers"), "containers")
    init_names = _names(spec.get("initContainers", []), "initContainers")
    all_names = names + init_names
    if len(all_names) != len(set(all_names)):
        raise PolicyError("Pod has duplicate container names")
    return set(all_names)


def _checked_tools(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    result = {}
    for name, expected in KATA_TOOL_HASHES.items():
        path = directory.resolve() / name
        if not path.is_file():
            raise PolicyError(f"missing regular Kata 4.4 tool: {path}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise PolicyError(f"Kata 4.4 tool digest mismatch: {path}")
        result[name] = path
    return result


def _compact_rules(rules: str) -> str:
    return "\n".join(
        line.strip() for line in rules.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ) + "\n"


def _settings(base: dict, pause_image: str, oci_version: str = DEFAULT_OCI_VERSION) -> dict:
    if not DIGEST_IMAGE.fullmatch(pause_image):
        raise PolicyError("pause image must be an immutable sha256 digest reference")
    settings = copy.deepcopy(base)
    settings["cluster_config"]["guest_pull"] = True
    settings["cluster_config"]["pause_container_image"] = pause_image
    settings["kata_config"]["oci_version"] = oci_version
    return settings


def _genpolicy_pod(pod: dict, role: str) -> dict:
    """Translate Kubernetes fields absent from the pinned genpolicy schema."""
    result = copy.deepcopy(pod)
    metadata = result["metadata"]
    for key in ("creationTimestamp", "generateName", "generation", "managedFields",
                "ownerReferences", "resourceVersion", "uid"):
        metadata.pop(key, None)
    result.pop("status", None)
    result["spec"].pop("schedulingGates", None)
    result["spec"].pop("automountServiceAccountToken", None)
    result["spec"].pop("enableServiceLinks", None)
    result["spec"].pop("overhead", None)
    for key in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        result["spec"].pop(key, None)
    (result["spec"].get("securityContext") or {}).pop("fsGroupChangePolicy", None)
    (result["spec"].get("securityContext") or {}).pop("seccompProfile", None)
    (result["spec"].get("securityContext") or {}).pop("runAsNonRoot", None)
    (result["spec"].get("securityContext") or {}).pop("supplementalGroupsPolicy", None)
    for volume in result["spec"].get("volumes", []):
        pvc = volume.get("persistentVolumeClaim")
        if pvc is not None and pvc.get("readOnly") is False:
            # Comparison expands the Kubernetes default. Kata 4.4's PVC
            # schema omits this field; absence has the same read-write meaning.
            pvc.pop("readOnly")
        downward = volume.get("downwardAPI")
        if downward is not None:
            # Kata models this bind mount, but not the source defaultMode.
            downward.pop("defaultMode", None)
        projected = volume.get("projected")
        if projected is not None:
            # Kata models the mount, but not projected-token sources.
            projected.pop("sources", None)
    for container in result["spec"].get("containers", []) + result["spec"].get("initContainers", []):
        # Kata encodes runAsUser in OCI; this Kubernetes boolean is unsupported.
        (container.get("securityContext") or {}).pop("runAsNonRoot", None)
    return result


def _bind_policy(policy: str, names: set[str], pause_image: str, workspace_mounts: dict) -> str:
    for needle in ("package agent_policy", "default CreateContainerRequest := false",
                   "default ExecProcessRequest := false", "default SetPolicyRequest := false"):
        if needle not in policy:
            raise PolicyError(f"generated policy lacks restrictive rule: {needle}")
    marker = "policy_data := "
    if policy.count(marker) != 1:
        raise PolicyError("generated policy has no unique policy_data")
    try:
        rules, raw_data = policy.split(marker, 1)
        data = json.loads(raw_data)
    except ValueError as exc:
        raise PolicyError(f"generated policy data is invalid: {exc}") from exc
    defaults = data.get("request_defaults", {}).get("ExecProcessRequest", {})
    if defaults.get("allowed_commands") or defaults.get("regex"):
        raise PolicyError("generated policy allows broad process execution")
    cluster = data.get("cluster_config", {})
    if cluster.get("guest_pull") is not True or cluster.get("pause_container_image") != pause_image:
        raise PolicyError("generated policy does not require guest pull and the pinned pause image")
    actual_names = []
    for container in data.get("containers", []):
        name = container.get("OCI", {}).get("Annotations", {}).get("io.kubernetes.cri.container-name")
        if name is not None:
            actual_names.append(name)
        bindings = workspace_mounts.get(name, [])
        if bindings:
            mounts = {mount["destination"]: mount for mount in container["OCI"]["Mounts"]}
            approved = data.setdefault("workspace_mounts", {}).setdefault(name, {})
            for binding in bindings:
                destination, disk = binding["mount_point"], binding["disk_id"]
                mounts[destination]["source"] = "^" + re.escape("/run/cloud-volumes/" + disk) + "$"
                approved[destination] = disk
    if len(actual_names) != len(set(actual_names)) or set(actual_names) != names:
        raise PolicyError("generated container policy differs from Pod containers")
    return rules + marker + json.dumps(data, separators=(",", ":"))


def generate(pod: dict, *, role: str, tools_dir: pathlib.Path,
             pause_image: str, runtime_class: str = "kata-remote",
             registry_ca: pathlib.Path | None = None, workspace_mounts: dict | None = None,
             oci_version: str = DEFAULT_OCI_VERSION) -> str:
    names = _validate_pod(pod, role, runtime_class)
    tools = _checked_tools(tools_dir)
    with tempfile.TemporaryDirectory(prefix="openshell-agent-policy-") as temp:
        work = pathlib.Path(temp)
        pod_path = work / "pod.json"
        rules_path = work / "rules.rego"
        settings_path = work / "settings.json"
        pod_path.write_text(json.dumps(_genpolicy_pod(pod, role), separators=(",", ":")) + "\n")
        rules = tools["rules.rego"].read_text()
        if workspace_mounts:
            rules += "\n" + WORKLOAD_EXTENSION.read_text()
        rules_path.write_text(_compact_rules(rules))
        settings = _settings(json.loads(tools["genpolicy-settings.json"].read_text()), pause_image, oci_version)
        settings_path.write_text(json.dumps(settings, separators=(",", ":")))
        env = os.environ.copy()
        if registry_ca is not None:
            if not registry_ca.is_file():
                raise PolicyError(f"registry CA must be a regular file: {registry_ca}")
            cert = registry_ca.read_bytes()
            if b"-----BEGIN CERTIFICATE-----" not in cert or b"-----END CERTIFICATE-----" not in cert:
                raise PolicyError("registry CA is not a PEM certificate")
            system_path = next((path for path in (
                pathlib.Path("/etc/pki/tls/certs/ca-bundle.crt"),
                pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
                pathlib.Path(ssl.get_default_verify_paths().cafile or "/nonexistent"),
            ) if path.is_file()), None)
            if system_path is None:
                raise PolicyError("system CA bundle is unavailable")
            ca_bundle = work / "registry-ca-bundle.pem"
            ca_bundle.write_bytes(system_path.read_bytes().rstrip() + b"\n" + cert)
            ca_bundle.chmod(0o600)
            # Kata's OCI client uses reqwest/rustls. rustls-native-certs reads
            # SSL_CERT_FILE, whereas Docker certs.d is only for Docker.
            env["SSL_CERT_FILE"] = str(ca_bundle)
        command = [str(tools["genpolicy"]), "--yaml-file", str(pod_path),
                   "--rego-rules-path", str(rules_path), "--json-settings-path", str(settings_path),
                   "--runtime-class-names", runtime_class, "--raw-out"]
        # The private registry is TLS protected; normal host trust is used.
        # genpolicy's insecure-registry switch is intentionally not set.
        try:
            # Kata's registry client creates image-layer temporary files under
            # its current directory. The driver service starts in `/`, so run
            # the subprocess in this owner-only scratch directory instead.
            result = subprocess.run(
                command, capture_output=True, check=False, timeout=300, env=env, cwd=work)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError(f"Kata genpolicy could not complete: {type(exc).__name__}") from exc
        if result.returncode:
            detail = result.stderr.decode(errors="replace")[-1200:].strip()
            raise PolicyError(f"Kata genpolicy failed: {detail}")
        try:
            policy = result.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("Kata genpolicy returned non-UTF-8 policy") from exc
        return _bind_policy(policy, names, pause_image, workspace_mounts or {})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("supervisor", "workload"))
    parser.add_argument("--workspace-mounts", type=json.loads, default={})
    parser.add_argument("--tools-dir", required=True, type=pathlib.Path)
    parser.add_argument("--runtime-class", default="kata-remote")
    parser.add_argument("--pause-image", required=True)
    parser.add_argument("--registry-ca", type=pathlib.Path)
    parser.add_argument("--oci-version", default=os.environ.get("OPENSHELL_KATA_OCI_VERSION", DEFAULT_OCI_VERSION))
    args = parser.parse_args()
    try:
        policy = generate(_read_pod(), role=args.role, tools_dir=args.tools_dir,
                          runtime_class=args.runtime_class,
                          pause_image=args.pause_image, registry_ca=args.registry_ca, workspace_mounts=args.workspace_mounts,
                          oci_version=args.oci_version)
    except (PolicyError, KeyError, TypeError) as exc:
        print(f"agent policy: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
