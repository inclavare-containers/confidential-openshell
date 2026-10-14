#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate upstream exec rules with a synthetic approved probe and fixed state."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kata-source", type=Path, required=True)
parser.add_argument("--opa", required=True)
args = parser.parse_args()
source = args.kata_source / "src/tools/genpolicy/rules.rego"
rules = source.read_text()
digest = hashlib.sha256(source.read_bytes()).hexdigest()
profiles = {
    "e30ecf1a3ded94d7b1d3228a46fffcea1652fb91cdc1d09026e91255c34abdfd":
        {"namespace": "default", "test-container": 0},
    "6161dfd2aace48f621c03afcfdf51c7b19b07a43a7e941f648e80bfddb933645":
        {"namespace": "default", "p_container_0": "test-container"},
}
if digest not in profiles:
    parser.error("rules.rego differs from the reviewed 4.2.0/main sources")
process = {
    "Terminal": False,
    "User": {"UID": 1000, "GID": 1000, "AdditionalGids": [1000], "Username": ""},
    "Args": ["/bin/true"], "Env": [], "Cwd": "/", "Capabilities": None,
    "NoNewPrivileges": True, "ApparmorProfile": "", "SelinuxLabel": "",
}
fixture = {
    "containers": [{
        "OCI": {"Annotations": {"io.kubernetes.cri.sandbox-name": "demo"},
                "Process": process},
        "exec_commands": [["/bin/true"]],
    }],
    "request_defaults": {"ExecProcessRequest": {"allowed_commands": [], "regex": []}},
}
request = {"container_id": "test-container", "exec_id": "probe",
           "string_user": None, "process": process}
cases = [
    ("requested true", lambda p: None, True),
    ("runtime dropped to false", lambda p: p.update(NoNewPrivileges=False), False),
    ("wrong command", lambda p: p.update(Args=["/bin/sh"]), False),
    ("wrong user", lambda p: p["User"].update(UID=0), False),
    ("extra capability", lambda p: p.update(Capabilities={"Bounding": ["CAP_SYS_ADMIN"]}), False),
]
results = []
with tempfile.TemporaryDirectory(prefix="kata-exec-policy-") as temporary:
    root = Path(temporary)
    policy, state, input_file = [root / name for name in ("policy.rego", "state.json", "input.json")]
    # Keep every upstream rule unchanged. Supply synthetic policy_data through
    # external data and model the state after an approved container creation.
    policy.write_text(rules + "\npolicy_data := data.fixture\n")
    state.write_text(json.dumps({"pstate": profiles[digest], "fixture": fixture}))
    for name, change, expected in cases:
        value = copy.deepcopy(request)
        change(value["process"])
        input_file.write_text(json.dumps(value))
        run = subprocess.run(
            [args.opa, "eval", "--format=json", "--data", str(policy),
             "--data", str(state), "--input", str(input_file),
             "data.agent_policy.ExecProcessRequest"],
            text=True, capture_output=True, check=True, timeout=30)
        decision = json.loads(run.stdout)["result"][0]["expressions"][0]["value"]
        if decision is not expected:
            raise RuntimeError(f"{name}: expected {expected}, got {decision}")
        results.append({"case": name, "allowed": decision})
print(json.dumps({"rules_sha256": digest, "scope": "offline synthetic post-create state",
                  "results": results}, indent=2))
