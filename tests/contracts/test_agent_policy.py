"""Focused tests for measured Kata policy Secret and group bindings."""

import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import agent_policy as policy


IMAGE = "ghcr.io/example/supervisor@sha256:" + "a" * 64


def supervisor_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"namespace": "sandbox", "labels": {policy.ROLE_LABEL: "supervisor"}},
        "spec": {
            "runtimeClassName": "kata-remote", "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "overhead": {"cpu": "250m", "memory": "120Mi"},
            "schedulingGates": [{"name": "openshell.ai/bootstrap"}],
            "securityContext": {"fsGroup": 1000, "supplementalGroups": [],
                                "supplementalGroupsPolicy": "Strict"},
            "containers": [{"name": "supervisor", "image": IMAGE,
                            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000,
                                                "runAsNonRoot": True,
                                                "allowPrivilegeEscalation": False},
                            "volumeMounts": [{"name": "bootstrap", "mountPath": "/.openshell/supervisor",
                                              "readOnly": True}]}],
            "volumes": [{"name": "bootstrap", "secret": {"secretName": "measured"}}],
        },
    }


def generated_policy():
    data = {"containers": [{"OCI": {
        "Annotations": {"io.kubernetes.cri.container-name": "supervisor"},
        "Process": {"User": {"UID": 1000, "GID": 1000, "AdditionalGids": [0, 1000]}},
        "Mounts": [{"destination": "/.openshell/supervisor",
                    "source": "$(sfprefix)supervisor$", "type_": "bind",
                    "options": ["rbind", "rprivate", "ro"]}],
    }}]}
    return "package agent_policy\npolicy_data := " + json.dumps(data)


class MeasuredPolicyBindingTest(unittest.TestCase):
    def test_ack_oci_version_is_pinned_for_exact_policy_matching(self):
        settings = policy._settings({
            "cluster_config": {},
            "kata_config": {"oci_version": "1.2.1"},
            "request_defaults": {"ExecProcessRequest": {
                "allowed_commands": [], "regex": []}},
        }, "registry.k8s.io/pause@sha256:" + "a" * 64)
        self.assertEqual(settings["kata_config"]["oci_version"], "1.3.0")
        self.assertEqual(policy.ACK_OCI_VERSION, "1.3.0")

    def test_genpolicy_uses_owner_only_scratch_as_working_directory(self):
        with tempfile.TemporaryDirectory() as fixture_dir:
            fixture = pathlib.Path(fixture_dir)
            (fixture / "genpolicy").write_text("")
            (fixture / "rules.rego").write_text(
                "    allow_by_anno(p_oci, i_oci, p_storages, i_storages)\n")
            (fixture / "genpolicy-settings.json").write_text(json.dumps({
                "cluster_config": {}, "kata_config": {},
                "request_defaults": {"ExecProcessRequest": {
                    "allowed_commands": [], "regex": []}}}))
            tools = {name: fixture / name for name in policy.KATA_TOOL_HASHES}
            observed = []

            def inspect_cwd(_command, **kwargs):
                work = pathlib.Path(kwargs["cwd"])
                self.assertTrue(work.is_dir())
                self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                self.assertTrue((work / "pod.json").is_file())
                observed.append(work)
                raise OSError("stop after checking scratch directory")

            with mock.patch.object(policy, "_checked_tools", return_value=tools), \
                    mock.patch.object(policy.subprocess, "run", side_effect=inspect_cwd):
                with self.assertRaises(policy.PolicyError):
                    policy.generate(supervisor_pod(), role="supervisor", tools_dir=fixture,
                                    registry="ghcr.io", pause_image=(
                                        "registry.k8s.io/pause@sha256:" + "a" * 64))
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists(), "scratch directory must be removed")

    def test_actual_supervisor_pod_is_unchanged_by_tool_normalization(self):
        actual = supervisor_pod()
        saved = copy.deepcopy(actual)
        policy._validate_pod(actual, "supervisor", "kata-remote")
        tool_input = policy._genpolicy_pod(actual, "supervisor")
        self.assertEqual(actual, saved)
        self.assertEqual(actual["spec"]["securityContext"]["supplementalGroups"], [])
        self.assertEqual(actual["spec"]["securityContext"]["supplementalGroupsPolicy"], "Strict")
        self.assertEqual(tool_input["spec"]["securityContext"]["supplementalGroups"], [0])
        self.assertNotIn("supplementalGroupsPolicy", tool_input["spec"]["securityContext"])

    def test_api_omits_empty_supplemental_groups_without_changing_strict_policy(self):
        actual = supervisor_pod()
        del actual["spec"]["securityContext"]["supplementalGroups"]
        policy._validate_pod(actual, "supervisor", "kata-remote")
        tool_input = policy._genpolicy_pod(actual, "supervisor")
        self.assertEqual(tool_input["spec"]["securityContext"]["supplementalGroups"], [0])
        self.assertNotIn("supplementalGroups", actual["spec"]["securityContext"])
        actual["spec"]["securityContext"]["supplementalGroups"] = [0]
        with self.assertRaises(policy.PolicyError):
            policy._validate_pod(actual, "supervisor", "kata-remote")
        del actual["spec"]["securityContext"]["supplementalGroupsPolicy"]
        with self.assertRaises(policy.PolicyError):
            policy._validate_pod(actual, "supervisor", "kata-remote")

    def test_service_environment_injection_must_be_disabled_before_tool_normalization(self):
        actual = supervisor_pod()
        policy._validate_pod(actual, "supervisor", "kata-remote")
        self.assertNotIn("enableServiceLinks", policy._genpolicy_pod(actual, "supervisor")["spec"])
        for value in (True, None):
            with self.subTest(value=value):
                drifted = supervisor_pod()
                if value is None:
                    drifted["spec"].pop("enableServiceLinks")
                else:
                    drifted["spec"]["enableServiceLinks"] = value
                with self.assertRaises(policy.PolicyError):
                    policy._validate_pod(drifted, "supervisor", "kata-remote")

    def test_pinned_runtime_class_overhead_is_tool_only(self):
        actual = supervisor_pod()
        saved = copy.deepcopy(actual)
        policy._validate_pod(actual, "supervisor", "kata-remote")
        self.assertNotIn("overhead", policy._genpolicy_pod(actual, "supervisor")["spec"])
        self.assertEqual(actual, saved)
        for overhead in ({"cpu": "500m", "memory": "120Mi"}, None):
            with self.subTest(overhead=overhead):
                drifted = supervisor_pod()
                if overhead is None:
                    drifted["spec"].pop("overhead")
                else:
                    drifted["spec"]["overhead"] = overhead
                with self.assertRaises(policy.PolicyError):
                    policy._validate_pod(drifted, "supervisor", "kata-remote")

    def test_defaulted_downward_identity_mode_is_checked_before_tool_normalization(self):
        actual = supervisor_pod()
        actual["metadata"]["labels"][policy.ROLE_LABEL] = "workload"
        actual["spec"]["containers"][0]["name"] = "agent"
        actual["spec"]["initContainers"] = [{
            "name": "openshell-sandbox-bootstrap", "image": IMAGE,
            "securityContext": {"runAsUser": 1000, "runAsNonRoot": True,
                                "allowPrivilegeEscalation": False}}]
        actual["spec"]["volumes"].append({
            "name": "openshell-pod-identity", "downwardAPI": {
                "defaultMode": 420, "items": [{"path": "uid", "fieldRef": {
                    "apiVersion": "v1", "fieldPath": "metadata.uid"}}]}})
        policy._validate_pod(actual, "workload", "kata-remote")
        normalized = policy._genpolicy_pod(actual, "workload")
        self.assertEqual(normalized["spec"]["volumes"][-1]["downwardAPI"], {
            "items": [{"path": "uid", "fieldRef": {
                "apiVersion": "v1", "fieldPath": "metadata.uid"}}]})
        actual["spec"]["volumes"][-1]["downwardAPI"]["defaultMode"] = 384
        with self.assertRaises(policy.PolicyError):
            policy._validate_pod(actual, "workload", "kata-remote")

    def test_measured_policy_removes_group_zero_and_shared_source(self):
        result = policy._bind_sealed_volume(generated_policy(), "supervisor", supervisor_pod())
        data = json.JSONDecoder().raw_decode(result.split("policy_data := ", 1)[1])[0]
        container = data["containers"][0]["OCI"]
        self.assertEqual(container["Process"]["User"]["AdditionalGids"], [1000])
        self.assertEqual(container["Mounts"][0]["source"], policy.PRIVATE_SEALED_SOURCE)
        self.assertNotIn("$(sfprefix)", result)

    def test_group_drift_and_non_strict_pods_fail_closed(self):
        actual = supervisor_pod()
        actual["spec"]["securityContext"]["supplementalGroupsPolicy"] = "Merge"
        with self.assertRaises(policy.PolicyError):
            policy._validate_pod(actual, "supervisor", "kata-remote")
        drifted = generated_policy().replace("[0, 1000]", "[0, 1000, 2000]")
        with self.assertRaises(policy.PolicyError):
            policy._bind_sealed_volume(drifted, "supervisor", supervisor_pod())


if __name__ == "__main__":
    unittest.main()
