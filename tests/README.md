# Tests

Run `./cos build test` from the repository root with the pinned toolchain and
cached dependencies and the released Kata policy rules. Cargo uses offline/locked mode; Go disables proxy/sumdb.
The runner prepares missing CAA/CSI/controller build copies, checks their source
identities and leaves the pinned `repos/` checkouts unchanged.

## Cache dependencies and run

First complete the [Ubuntu host tools](../docs/build.md#prepare-an-ubuntu-2404-host)
and [fixed source inputs](../docs/build.md#obtain-complete-fixed-sources).
Populate dependency caches while network access is available, then run the suite:

```bash
./cos build test-cache
./cos build test
```

| Suite | Coverage |
| --- | --- |
| Driver Rust and imported upstream tests | Admission, sealed resources, UID/attempt bindings, workspace identity, lifecycle and recovery |
| `tests/policy` | TDX/AAEL appraisal, exact KBS resources and guest mount/pull denials |
| `tests/contracts` | Build provenance, initdata, permissions; cloud creation/resume with mocked APIs; step failure logs, worker selection/profile preservation and atomic release extraction |
| CAA/CSI Go tests | The maintained adapter and storage patches |
| PeerPod provider tests | Deletion succeeds only after exact typed absence; present instances and read errors preserve failure |
| PeerPod controller | Compile packages and tests; envtest's API server/etcd suite is not run |
| Helm and CSI handoff | Source-bound chart package, RRSA, controller/PVC/node/StorageClass settings and corrupt-input rejection |
| `tests/e2e` | Coding-task oracle and OpenCode event checks |
| `tests/check-layout.py` | Maintained links and script/configuration syntax |

Helm requires the checksum-pinned archives under `artifacts/cache/helm/` or
`PEERPODS_CHART_CACHE`, plus Helm and the Ubuntu `python3-yaml` package.
The handoff check verifies chart file contents/modes against Git and renders the
transferred package without Git or a cluster connection. Missing dependencies fail without downloading them.

The default suite uses no cloud API, deployed KBS, real quote or external model.
[Optional policy-engine tests](acceptance/README.md) use official Trustee binaries
with synthetic claims. [Agent-task checks](e2e/README.md) cover application behavior.
Real attestation, resource release, network enforcement and volume lifecycle
require the [live acceptance procedure](../docs/live-acceptance.md).
Fixture digests must never become deployed approval references.

The core CI workflow runs `bash tests/run-core.sh` after `cargo fetch --locked`.
It covers driver lifecycle and trusted launch behavior, plus deployment contracts
and Trustee API timeout/recovery using a stateful test peer. It does not allocate
cloud resources. The complete `./cos build test` suite additionally checks the
CAA/CSI patches, policy engine and chart handoff.
