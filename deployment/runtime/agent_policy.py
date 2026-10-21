#!/usr/bin/env python3
"""Generate a Kata 4.2 policy from the trusted OpenShell launch template.

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
GUEST_PULL_EXTENSION = ROOT / "deployment/policy/agent-policy-guest-pull.rego"
# ACK's pinned containerd 2.3.4 produced OCI 1.3.0 in the observed infra
# CreateContainer request. The measured Kata policy compares this field for
# exact equality; a different runtime requires a separately validated profile.
ACK_OCI_VERSION = "1.3.0"
KATA_TOOL_HASHES = {
    "genpolicy": "48b12625bd47bb9279b444ed0d52233bf30ffab86e7af69f0ebbf7b8bcd4c9dd",
    "rules.rego": "e30ecf1a3ded94d7b1d3228a46fffcea1652fb91cdc1d09026e91255c34abdfd",
    "genpolicy-settings.json": "46bf9ac5460393f626ff2ed6fa2501ec5a82893da57c06e5c53a8f8e50e9dfa0",
}
MAX_POD_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
ROLE_LABEL = "openshell.ai/boundary-role"
INITDATA_ANNOTATION = "io.katacontainers.config.hypervisor.cc_init_data"
DIGEST_IMAGE = re.compile(r"^[a-z0-9._:/-]+@sha256:[a-f0-9]{64}$")
SEALED_MOUNT = {
    "workload": ("openshell-sandbox-bootstrap", "/.openshell/bootstrap-input"),
    "supervisor": ("supervisor", "/.openshell/supervisor"),
}
PRIVATE_SEALED_SOURCE = "^/run/peerpod/verified-secrets/$(bundle-id)$"


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
    raw = sys.stdin.buffer.read(MAX_POD_BYTES + 1)
    if len(raw) > MAX_POD_BYTES:
        raise PolicyError("Pod JSON exceeds 2 MiB")
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
    # U controls placement, not execution. These fields are not policy inputs.
    for key in ("nodeName", "nodeSelector", "tolerations", "affinity", "schedulerName",
                "priority", "priorityClassName", "preemptionPolicy", "topologySpreadConstraints"):
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
    # Exactly the mutation performed by the pinned PeerPods resource webhook.
    trusted["spec"]["overhead"] = {"cpu": "250m", "memory": "120Mi"}
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
    namespace = metadata.get("namespace")
    if (not isinstance(namespace, str) or len(namespace) > 63
            or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace)):
        raise PolicyError("Pod namespace must be a valid explicit Kubernetes namespace")
    if metadata.get("labels", {}).get(ROLE_LABEL) != role:
        raise PolicyError(f"Pod boundary role must be {role}")
    if spec.get("runtimeClassName") != runtime_class:
        raise PolicyError(f"Pod must select runtime class {runtime_class}")
    if metadata.get("annotations", {}).get(INITDATA_ANNOTATION):
        raise PolicyError("Pod already has initdata; policy generation must precede initdata binding")
    if any(spec.get(key) for key in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace")):
        raise PolicyError("host namespace access is forbidden")
    if spec.get("automountServiceAccountToken") is not False:
        raise PolicyError("automatic Kubernetes service account token mount is forbidden")
    if spec.get("enableServiceLinks") is not False:
        raise PolicyError("Pod must disable service environment injection")
    # The pinned ACK kata-remote RuntimeClass adds only this scheduling
    # accounting overhead. Kata 4.2 genpolicy has no PodSpec.overhead field;
    # reject any drift before removing it from the tool-only Pod view.
    if spec.get("overhead") != {"cpu": "250m", "memory": "120Mi"}:
        raise PolicyError("Pod RuntimeClass overhead differs from the pinned ACK profile")
    pod_security = spec.get("securityContext") or {}
    if pod_security.get("fsGroupChangePolicy") not in (None, "OnRootMismatch"):
        raise PolicyError("unexpected fsGroupChangePolicy")
    if pod_security.get("seccompProfile") not in (None, {"type": "RuntimeDefault"}):
        raise PolicyError("unexpected Pod seccomp profile")
    if pod_security.get("runAsNonRoot"):
        uid = pod_security.get("runAsUser")
        if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
            raise PolicyError("Pod runAsNonRoot requires a fixed positive UID")
    if pod_security.get("supplementalGroupsPolicy") not in (None, "Strict"):
        raise PolicyError("unexpected supplemental groups policy")
    if any(isinstance(v, dict) and "hostPath" in v for v in spec.get("volumes", [])):
        raise PolicyError("hostPath is forbidden")
    for volume in spec.get("volumes", []):
        if not isinstance(volume, dict):
            raise PolicyError("Pod volume must be an object")
        downward = volume.get("downwardAPI")
        if downward is not None:
            if (role != "workload" or volume.get("name") != "openshell-pod-identity"
                    or downward != {"defaultMode": 420, "items": [{
                        "path": "uid", "fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}]}):
                raise PolicyError("unexpected Downward API identity volume")
        projected = volume.get("projected")
        if projected is None:
            continue
        sources = projected.get("sources") if isinstance(projected, dict) else None
        if not isinstance(sources, list) or not sources:
            raise PolicyError("projected volume lacks trusted sources")
        for source in sources:
            token = source.get("serviceAccountToken") if isinstance(source, dict) else None
            if (not isinstance(token, dict) or token.get("audience") != "openshell-gateway"
                    or token.get("path") != "token" or not isinstance(token.get("expirationSeconds"), int)):
                raise PolicyError("unexpected projected volume source")
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
    if role == "supervisor":
        if names != ["supervisor"] or init_names:
            raise PolicyError("supervisor Pod must contain only the supervisor container")
        if (pod_security.get("supplementalGroupsPolicy") != "Strict"
                or pod_security.get("supplementalGroups", []) != []):
            raise PolicyError("supervisor Pod requires Strict with empty supplemental groups")
    elif (names != ["agent"] or "openshell-sandbox-bootstrap" not in init_names
          or not set(init_names) <= {"openshell-sandbox-bootstrap", "workspace-init"}):
        raise PolicyError("workload Pod contains an unexpected container")
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        security = container.get("securityContext") or {}
        if not isinstance(security, dict) or security.get("privileged") or security.get("allowPrivilegeEscalation"):
            raise PolicyError("privileged or escalating container is forbidden")
        if security.get("runAsNonRoot") and (
            not isinstance(security.get("runAsUser"), int) or security["runAsUser"] <= 0
        ):
            raise PolicyError("runAsNonRoot requires a fixed positive runAsUser")
    return set(all_names)


def _checked_tools(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    result = {}
    for name, expected in KATA_TOOL_HASHES.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise PolicyError(f"missing regular Kata 4.2 tool: {path}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise PolicyError(f"Kata 4.2 tool digest mismatch: {path}")
        result[name] = path
    return result


def _compact_rules(rules: str) -> str:
    # Upstream's debug prints and comments inflate Alibaba UserData without
    # affecting authorization. Keep each actual Rego statement unchanged.
    return "\n".join(
        line.strip() for line in rules.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "print("))
    ) + "\n"


def _settings(base: dict, pause_image: str) -> dict:
    if not DIGEST_IMAGE.fullmatch(pause_image):
        raise PolicyError("pause image must be an immutable sha256 digest reference")
    settings = copy.deepcopy(base)
    settings["cluster_config"]["guest_pull"] = True
    settings["cluster_config"]["pause_container_image"] = pause_image
    settings["kata_config"]["oci_version"] = ACK_OCI_VERSION
    # Kata 4.2 derives fsgid from the Pod itself. Adding it to the defaults
    # duplicates the option in generated storages and makes runtime matching
    # brittle. Older 4.1 policy scripts needed an explicit setting here.
    exec_defaults = settings["request_defaults"]["ExecProcessRequest"]
    if exec_defaults.get("allowed_commands") or exec_defaults.get("regex"):
        raise PolicyError("Kata settings allow broad process execution")
    return settings


def _genpolicy_pod(pod: dict, role: str) -> dict:
    """Remove Kubernetes bookkeeping that Kata does not consume in the guest.

    Every removed field is either apiserver bookkeeping or the scheduling gate
    that we already required on the input Pod. Security relevant spec fields
    remain visible to genpolicy, which fails on unknown fields.
    """
    result = copy.deepcopy(pod)
    metadata = result["metadata"]
    for key in ("creationTimestamp", "generateName", "generation", "managedFields",
                "ownerReferences", "resourceVersion", "uid"):
        metadata.pop(key, None)
    result.pop("status", None)
    result["spec"].pop("schedulingGates", None)
    result["spec"].pop("automountServiceAccountToken", None)
    # Kata 4.2 has no PodSpec.enableServiceLinks field. The admitted Pod was
    # required above to set it false, disabling namespace Service environment
    # injection. Kubelet can still add default/kubernetes variables; the
    # pinned Kata policy's existing Service-env patterns remain unchanged.
    result["spec"].pop("enableServiceLinks", None)
    result["spec"].pop("overhead", None)
    for key in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        result["spec"].pop(key, None)
    (result["spec"].get("securityContext") or {}).pop("fsGroupChangePolicy", None)
    (result["spec"].get("securityContext") or {}).pop("seccompProfile", None)
    (result["spec"].get("securityContext") or {}).pop("runAsNonRoot", None)
    (result["spec"].get("securityContext") or {}).pop("supplementalGroupsPolicy", None)
    if role == "supervisor":
        # Kata 4.2 genpolicy sees group 0 in the pinned image's /etc/group and
        # refuses guest pull unless it appears explicitly. The *actual* Pod
        # uses Strict and no supplemental groups. Add 0 only to this temporary
        # tool input; _bind_sealed_volume removes it from the measured policy.
        result["spec"]["securityContext"]["supplementalGroups"] = [0]
    for volume in result["spec"].get("volumes", []):
        downward = volume.get("downwardAPI")
        if downward is not None:
            # The admitted volume above is a public Pod UID file with the
            # Kubernetes default 0644 mode. Kata models its bind mount but
            # cannot parse the source's defaultMode field.
            downward.pop("defaultMode")
        projected = volume.get("projected")
        if projected is not None:
            # The audience/path were validated above. Kata models the guest
            # mount, but not Kubernetes's projected-token source descriptor.
            projected.pop("sources", None)
    for container in result["spec"].get("containers", []) + result["spec"].get("initContainers", []):
        # A fixed positive runAsUser was checked above. Kata encodes that UID
        # in the OCI policy, while the Kubernetes-only boolean is unsupported.
        (container.get("securityContext") or {}).pop("runAsNonRoot", None)
    return result


def _bind_sealed_volume(policy: str, role: str, pod: dict | None = None) -> str:
    marker = "policy_data := "
    if policy.count(marker) != 1:
        raise PolicyError("generated policy has no unique policy_data")
    start = policy.index(marker) + len(marker)
    try:
        data, used = json.JSONDecoder().raw_decode(policy[start:])
    except ValueError as exc:
        raise PolicyError(f"generated policy data is invalid: {exc}") from exc
    expected_name, destination = SEALED_MOUNT[role]
    found = 0
    for container in data.get("containers", []):
        name = container.get("OCI", {}).get("Annotations", {}).get("io.kubernetes.cri.container-name")
        for mount in container.get("OCI", {}).get("Mounts", []):
            if mount.get("destination") != destination:
                continue
            if (name != expected_name or mount.get("type_") != "bind"
                    or mount.get("options") != ["rbind", "rprivate", "ro"]
                    or not isinstance(mount.get("source"), str)
                    or not mount["source"].startswith("$(sfprefix)")):
                raise PolicyError("generated sealed-volume mount differs from expected read-only Secret")
            mount["source"] = PRIVATE_SEALED_SOURCE
            found += 1
    if found != 1:
        raise PolicyError("generated policy must contain one sealed-volume mount")
    if role == "supervisor":
        if pod is None:
            raise PolicyError("supervisor policy requires the actual Pod for group normalization")
        security = pod["spec"]["containers"][0].get("securityContext") or {}
        group = security.get("runAsGroup")
        user = security.get("runAsUser")
        fs_group = pod["spec"].get("securityContext", {}).get("fsGroup")
        if any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in (group, user, fs_group)):
            raise PolicyError("supervisor Pod needs fixed positive user, group and fsGroup")
        matched = [c for c in data["containers"] if
                   c.get("OCI", {}).get("Annotations", {}).get("io.kubernetes.cri.container-name") == "supervisor"]
        if len(matched) != 1:
            raise PolicyError("generated supervisor policy has no unique container")
        policy_user = matched[0]["OCI"]["Process"]["User"]
        expected = sorted({group, fs_group})
        if (policy_user.get("UID") != user or policy_user.get("GID") != group
                or policy_user.get("AdditionalGids") != sorted({0, *expected})):
            raise PolicyError("Kata 4.2 supervisor image groups differ from audited normalization")
        policy_user["AdditionalGids"] = expected
    return policy[:start] + json.dumps(data, separators=(",", ":")) + policy[start + used:]


def _validate_policy(policy: str, names: set[str], pause_image: str, role: str) -> None:
    if len(policy.encode()) > MAX_POLICY_BYTES:
        raise PolicyError("generated policy exceeds 256 KiB")
    for needle in ("package agent_policy", "default CreateContainerRequest := false",
                   "default ExecProcessRequest := false", "default SetPolicyRequest := false",
                   "openshell_guest_pull(p_oci, i_storages)"):
        if needle not in policy:
            raise PolicyError(f"generated policy lacks restrictive rule: {needle}")
    marker = "policy_data := "
    if policy.count(marker) != 1:
        raise PolicyError("generated policy has no unique policy_data")
    try:
        data, _ = json.JSONDecoder().raw_decode(policy.split(marker, 1)[1])
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
    if len(actual_names) != len(set(actual_names)) or set(actual_names) != names:
        raise PolicyError("generated container policy differs from Pod containers")
    expected_name, destination = SEALED_MOUNT[role]
    mounts = [mount for container in data.get("containers", [])
              if container.get("OCI", {}).get("Annotations", {}).get("io.kubernetes.cri.container-name") == expected_name
              for mount in container.get("OCI", {}).get("Mounts", [])
              if mount.get("destination") == destination]
    if len(mounts) != 1 or mounts[0].get("source") != PRIVATE_SEALED_SOURCE:
        raise PolicyError("verified Secret source is not bound to the private guest directory")
    if role == "supervisor":
        supervisor = next(c for c in data["containers"] if
                          c.get("OCI", {}).get("Annotations", {}).get("io.kubernetes.cri.container-name") == "supervisor")
        if 0 in supervisor["OCI"]["Process"]["User"]["AdditionalGids"]:
            raise PolicyError("supervisor policy unexpectedly grants supplemental group 0")


def generate(pod: dict, *, role: str, tools_dir: pathlib.Path, registry: str,
             pause_image: str, runtime_class: str = "kata-remote",
             registry_ca: pathlib.Path | None = None) -> str:
    names = _validate_pod(pod, role, runtime_class)
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", registry):
        raise PolicyError("registry must be a host with optional port")
    tools = _checked_tools(tools_dir)
    with tempfile.TemporaryDirectory(prefix="openshell-agent-policy-") as temp:
        work = pathlib.Path(temp)
        pod_path = work / "pod.json"
        rules_path = work / "rules.rego"
        settings_path = work / "settings.json"
        pod_path.write_text(json.dumps(_genpolicy_pod(pod, role), separators=(",", ":")) + "\n")
        rules = tools["rules.rego"].read_text()
        insertion = "    allow_by_anno(p_oci, i_oci, p_storages, i_storages)\n"
        if rules.count(insertion) != 1:
            raise PolicyError("Kata rules changed; guest image binding insertion is unsafe")
        rules = rules.replace(insertion, insertion + "    openshell_guest_pull(p_oci, i_storages)\n")
        rules += "\n" + GUEST_PULL_EXTENSION.read_text()
        if role == "workload":
            fs_group = pod["spec"].get("securityContext", {}).get("fsGroup")
            if not isinstance(fs_group, int) or isinstance(fs_group, bool) or fs_group <= 0:
                raise PolicyError("workload Pod requires a fixed positive fsGroup")
            rules += "\n" + WORKLOAD_EXTENSION.read_text().replace("__WORKLOAD_FSGROUP__", str(fs_group))
        rules_path.write_text(_compact_rules(rules))
        settings = _settings(json.loads(tools["genpolicy-settings.json"].read_text()), pause_image)
        settings_path.write_text(json.dumps(settings, separators=(",", ":")))
        env = os.environ.copy()
        if registry_ca is not None:
            if registry_ca.is_symlink() or not registry_ca.is_file():
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
        policy = _bind_sealed_volume(policy, role, pod)
        _validate_policy(policy, names, pause_image, role)
        return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("supervisor", "workload"))
    parser.add_argument("--tools-dir", required=True, type=pathlib.Path)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--runtime-class", default="kata-remote")
    parser.add_argument("--pause-image", required=True)
    parser.add_argument("--registry-ca", type=pathlib.Path)
    args = parser.parse_args()
    try:
        policy = generate(_read_pod(), role=args.role, tools_dir=args.tools_dir,
                          registry=args.registry, runtime_class=args.runtime_class,
                          pause_image=args.pause_image, registry_ca=args.registry_ca)
    except (PolicyError, KeyError, TypeError) as exc:
        print(f"agent policy: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
