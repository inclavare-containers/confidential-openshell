# Live exec/policy validation — 2026-10-12

The fix was exercised through real containerd CRI `ExecSync` and task exec,
using an unmodified released kata-agent in QEMU/KVM VMs. This test uses no
OpenShell, CAA, Trustee, Alibaba Cloud, or custom guest image. The generated
agent policy is enforced inside the guest by Regorus.

Both source baselines were tested independently:

| Shim source base | Go toolchain | Sequence |
| --- | --- | --- |
| 4.2.0 `c7351e797efff8bfc6bd73da0eb1909be12e2cfe` | 1.26.7 | Original → patched → original |
| PR base `46c507fe445370f0728aeefbfd16c49cead0493d` | 1.26.8 | Original → patched → original |

For each baseline, both shims were built from the same checkout with the same
command, before and after applying the two-file patch:

```sh
make PREFIX=/opt/kata QEMUCMD=qemu-system-x86_64 STATIC=yes containerd-shim-v2
```

“Original” means rebuilt unmodified source, rather than the release-distributed
shim. The only functional source change is the `NoNewPrivileges` assignment.
The additional test assertions do not compile into the shim.

## Fixed environment

- Official Kata 4.2.0 Go static and tools release archives; their downloaded
  SHA-256 values match GitHub's release asset digests.
- QEMU 11.0.1, kernel `6.18.35-202`, standard `kata-ubuntu-resolute.image`, and
  its released kata-agent. The guest agent hash was read in all six VMs and
  remained `212844dcbed2975b753a1cd3461a8511e631f408be08e798acd02de28ba4f9cb`.
- Official containerd **static** 2.3.4 and crictl 1.35.0, with a private
  containerd root, state directory, socket, and runtime handler.
- The [Pod fixture](live/pod.json): pinned BusyBox image, UID/GID 10001,
  dropped capabilities, `allowPrivilegeEscalation=false`, and two exec probes.
- Official 4.2.0 genpolicy, its complete unchanged rules and settings, and
  the shipped `10-non-coco-drop-in.json` / `20-oci-1.3.0-drop-in.json`.
  The only additional settings replace the bundle-path annotation prefix to
  match the private containerd state directory. No exec rule is relaxed.
- The policy emitted once by genpolicy is transported in its normal
  `io.katacontainers.config.hypervisor.cc_init_data` annotation. Its exact text
  SHA-256 is `7f5cc655a294807ada5edf4aa31949d33b61ee62986772ce2e7ded4a582e7026`.

The Pod configuration, CRI inputs, guest image/kernel, generated policy,
containerd configuration, and Kata configuration were frozen for all six
phases. The selected shim binary changed. Each phase used a fresh sandbox and
container; their generated IDs differ and are matched by the same expressions
in the unchanged policy. Each container was successfully started before exec.

## Observed results

The same results occurred on both source baselines:

| Request | Original | Patched | Reverted to original |
| --- | --- | --- | --- |
| Approved probes: three CRI ExecSync calls | Agent policy denial, client exit 1 | All exit 0 | Agent policy denial, client exit 1 |
| Approved probe: one containerd task exec | Agent policy denial, client exit 1 | Exit 0 | Agent policy denial, client exit 1 |
| Unapproved `/bin/echo not-approved` | Deny | Deny | Deny |
| Approved command with UID/GID changed to 0 | Deny | Deny | Deny |

The original/reverted error text returned through CRI includes
`ExecProcessRequest is blocked by policy`, the expected process with
`NoNewPrivileges: true`, and the received process with `NoNewPrivileges: false`.
This is an agent refusal observed during real execution, rather than an OPA
replay of a fabricated request.

The agent's built-in `/tmp/policy.jsonl` log records the request it deserializes
and passes to its policy engine. The approved `/bin/true` process objects are
retained as [before](live/process-before.json) and [after](live/process-after.json).
Comparing **every one of the six corresponding exec Process objects** in each
baseline showed exactly one changed property: `NoNewPrivileges`, false → true.
The reverted Process objects equal the original ones. User/groups, argv,
environment, cwd, and the remaining process fields were unchanged.

The [generated-policy excerpt](live/policy-process-excerpt.json) records the
approved commands and required process settings. It is an excerpt for review;
the guest enforced the complete generated policy. The [evidence receipt](live-evidence.json)
contains hashes and the individual results for all 36 exec requests.

## Reproduction through the same APIs

Use the shipped QEMU configuration and a private containerd handler pointing
`runtime_path` to a replaceable shim path and `options.ConfigPath` to the test
Kata configuration. Enable propagation of `io.katacontainers.*` Pod annotations.
Relocate asset paths if the release is unpacked outside `/opt/kata`; QEMU also
needs its released BIOS directory supplied with `-L` when relocated.

Generate the policy from `live/pod.json` with the official rules/settings and
both shipped drop-ins listed above. Adapt only the two
`io.katacontainers.pkg.oci.bundle_path` settings to the chosen containerd state
prefix. Copy the generated Pod's annotations into [sandbox.json](live/sandbox.json).
Use [container.json](live/container.json) as the CRI container input; its PID
namespace, supplementary groups, and masked/read-only paths supply the fields
normally prepared by the kubelet. This avoids mistaking an unrelated
container-creation policy mismatch for the exec defect.

With `crictl.yaml` pointing at that private socket, run:

```sh
sandbox=$(crictl --config crictl.yaml runp --runtime kata-nnp sandbox.json)
container=$(crictl --config crictl.yaml create "$sandbox" container.json sandbox.json)
crictl --config crictl.yaml start "$container"
crictl --config crictl.yaml inspect "$container"
# Confirm info.runtimeSpec.process.noNewPrivileges is true.
crictl --config crictl.yaml exec --sync --timeout 10 "$container" /bin/true
crictl --config crictl.yaml exec --sync --timeout 10 "$container" /bin/echo not-approved

# Use ctr with the same private socket and k8s.io namespace for a user-change negative:
ctr --address "$socket" --namespace k8s.io tasks exec \
  --exec-id root-negative --user 0:0 "$container" \
  /bin/sh -c "grep '^NoNewPrivs:' /proc/self/status"

crictl --config crictl.yaml stop "$container"
crictl --config crictl.yaml rm "$container"
crictl --config crictl.yaml stopp "$sandbox"
crictl --config crictl.yaml rmp "$sandbox"
```

After cleanup, atomically replace the selected shim with the patched build,
then repeat with the **same input files and generated annotation**. After that,
restore the original shim and repeat again. Replacing a binary while an existing
sandbox's shim is still running does not replace that running process.

For evidence collection, the standard guest debug console was enabled
identically in these isolated VMs, solely to read the existing agent policy log
and hash the agent. All probes and negative requests went through CRI/containerd
with policy enforcement active. No agent patch or policy bypass was used to
execute a probe. The ordinary CLI results reproduce the failure without
collecting the debug log.

## Scope and retained artifacts

This establishes the live runtime → agent → generated-policy behavior. No
kubelet was run, so Kubernetes Ready/liveness transitions were **not** measured.
It is not a new Aliyun PeerPods/TDX or complete OpenShell lifecycle test.
Probe stdout was empty in the captured CLI results; the report relies on the
agent input, denial text, and exit status and makes no `/proc` flag observation.

Full request logs, denial responses, CLI receipts, build logs, exact configuration,
`kata-runtime env`, and official `kata-collect-data.sh` output are retained locally
under `.local/kata-exec-live-20261012/`. Collector output describes some host-wide
services as well; the environment above identifies the private instance actually
used. Raw host collector output has not been published to the community.

The current collector comment is the unedited stdout of the official release
script, invoked directly. It is retained under
`.local/kata-community-review-20261012/compliance/`. Default-configuration lookup
errors remain in that output because the test used an explicit private
`ConfigPath`. A separate unedited `kata-runtime --config ... env` capture and
copies of the actual test configurations provide that configuration context.
An earlier processed comment that substituted paths and inadvertently changed
some package versions has been withdrawn.

All test containers, sandboxes, and VMs were removed, the private containerd
was stopped, and no shared cluster or deployment configuration was changed.
The upstream PR remains the same two-file runtime fix. Full upstream CI and
other hypervisor/runtime implementations remain outside this validation.
