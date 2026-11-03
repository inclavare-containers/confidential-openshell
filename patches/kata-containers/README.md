# Kata exec `NoNewPrivileges` fix

The [patch](0001-fix-runtime-preserve-exec-no-new-privileges.patch) fixes field
conversion in the Kata 4.2.0 host Go runtime: `cmdToKataProcess` must copy
`types.Cmd.NoNewPrivileges` to `grpc.Process.NoNewPrivileges`.
It changes only the conversion function and its existing unit test. The guest
agent, protocol and policy require no changes.

## Why it is needed

When a Pod sets `allowPrivilegeEscalation: false`, the Kata agent policy generated
by the official `genpolicy` requires `Process.NoNewPrivileges=true`. The containerd
exec request already carries this value, but the Go runtime drops it, so the guest
agent receives false. The policy then rejects an otherwise permitted exec
readiness probe.

```text
containerd OCI process → types.Cmd → grpc.Process → guest kata-agent policy
                                      ^ Copy NoNewPrivileges here
```

This is the **Kata guest agent's Rego policy**, which constrains host RPCs.
OpenShell supervisor application/network policies and Trustee attestation/key
release policies run at separate layers. The defect drops a request field; it
does not corrupt the generated agent policy.

The patch preserves the caller's true or false value.
The affected path is independent of Alibaba, TDX, PeerPods and OpenShell. The
Rust runtime uses a separate implementation.

## Baseline and checks

The deployment baseline is Kata 4.2.0 at
`c7351e797efff8bfc6bd73da0eb1909be12e2cfe`. See the
[source lock](../../deployment/build/sources.lock.json) for the base and patched
result tree. Run these commands from the root of a clean Kata checkout:

```bash
PATCH=/path/to/0001-fix-runtime-preserve-exec-no-new-privileges.patch
git apply --check "$PATCH"

# With only the test change, the true assertion must fail.
git apply --include=src/runtime/virtcontainers/kata_agent_test.go "$PATCH"
(cd src/runtime && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)

# After applying the field assignment, the same test must pass.
git apply --include=src/runtime/virtcontainers/kata_agent.go "$PATCH"
(cd src/runtime && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)
git diff --check
gofmt -l src/runtime/virtcontainers/kata_agent.go \
  src/runtime/virtcontainers/kata_agent_test.go
```

The unit test covers field conversion. See the
[upstream review materials](upstream/README.md) for independent runtime → agent →
policy reproduction and contribution records for
[Issue #14024](https://github.com/kata-containers/kata-containers/issues/14024) and
[PR #14025](https://github.com/kata-containers/kata-containers/pull/14025).
Deployments continue to apply the local patch according to the source lock.
