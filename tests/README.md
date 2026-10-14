# Tests

Run `bash tests/run.sh` from the repository root with the pinned toolchain and
cached dependencies. Cargo uses offline/locked mode; Go disables proxy/sumdb.
The runner prepares missing CAA/CSI/controller build copies, checks their source
identities and leaves the pinned `repos/` checkouts unchanged. Missing Kata sources
are reported as `not_run`; they do not block the remaining integration checks.

| Suite | Coverage |
| --- | --- |
| Driver Rust and imported upstream tests | Admission, sealed resources, UID/attempt bindings, workspace identity, lifecycle and recovery |
| `tests/policy` | TDX/AAEL appraisal, exact KBS resources and guest mount/pull denials |
| `tests/contracts` | Build provenance, public artifact paths, initdata, operator-key exclusion, service ordering and guest permissions |
| CAA/CSI Go tests | The maintained adapter and storage patches |
| PeerPod provider tests | Deletion succeeds only after exact typed absence; present instances and read errors preserve failure |
| Controller compilation | Import graph compiled with `-run '^$'`; envtest's API server/etcd suite is not run |
| Helm and CSI handoff | Source-bound chart package, RRSA, controller/PVC/node/StorageClass settings and corrupt-input rejection |
| `tests/e2e` | Coding-task oracle and OpenCode event checks |
| `tests/check-layout.py` | Maintained links and script/configuration syntax |

Helm requires the checksum-pinned archives under `artifacts/cache/helm/` or
`PEERPODS_CHART_CACHE`, plus Helm and yq 4.35.1. The handoff check verifies chart
file contents/modes against Git and renders the transferred package without Git
or a cluster connection. Missing dependencies fail without downloading them.
The CAA sealed-volume test runs with umask 022 because it expects mode 0440.

The default suite uses no cloud API, deployed KBS, real quote or external model.
[Optional policy-engine tests](acceptance/README.md) use official Trustee binaries
with synthetic claims. [Agent-task checks](e2e/README.md) cover application behavior.
Real attestation, resource release, network enforcement and volume lifecycle
require the [deployment checks](../docs/deployment.md#10-verify-both-confidential-roles).
Fixture digests must never become deployed approval references.
