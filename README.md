# Confidential OpenShell

Run the unmodified OpenShell v0.1.3 Gateway/CLI/supervisor with an external
confidential Kubernetes ComputeDriver and separate attested supervisor/workload
guests. Main uses official CoCo 0.22 AA/CDH and Trustee with the upstream Ubuntu
UKI image flow on ACK/PeerPods/Intel TDX. The driver and required PeerPods
integration remain local changes; this repository does not fork OpenShell's
protocol or user interface.

Start with [architecture and trust boundaries](docs/architecture.md).
Developers prepare [fixed sources and build inputs](docs/build.md), then follow
one **[sequential deployment runbook](docs/deployment.md)**. An approved compatible
PodVM ImageID and matching references need no rebuild. Users of an installed
Gateway follow [the native agent walkthrough](docs/first-agent.md).
[Upgrade and retention](docs/upgrade.md) covers existing state; the
[test guide](tests/README.md) distinguishes offline checks from live acceptance.
Component READMEs are references, not additional deployment routes.

| Component | Source and integration |
| --- | --- |
| Gateway, CLI and supervisor | Unmodified official OpenShell v0.1.3 |
| AA/CDH and Trustee | Official CoCo v0.22.0 release images/binaries; TDX attester selected through upstream build inputs |
| Guest | Official CAA Ubuntu mkosi/UKI flow plus measured OpenShell bootstrap, ECS clock configuration and encrypted-volume initialization hooks |
| Confidential ComputeDriver | Derivative of the pinned Kubernetes driver; shared modules compile from upstream, local code seals and authorizes bootstrap/workspace resources |
| CAA, CSI, PeerPod controller and Kata host shim | Pinned sources with the [required patch queues](patches/README.md) |
| Coding agent | Official Python base and released OpenCode binary; local image assembly without provider credentials |

The trusted domain contains CLI, Gateway, driver, Trustee and their authorization
state. Guest attestation gates KBS release of launch credentials and workspace
keys. Native TLS/JWT then authenticates credential holders; operator client keys
remain on the trusted host. Provider credentials reach the attested supervisor
at runtime; the external inference API remains outside this confidential boundary.
Cloud orchestration is untrusted. See the architecture for revocation and retention.

| Directory | Responsibility |
| --- | --- |
| `repos/`, `patches/` | Fixed upstream gitlinks and ordered integration changes |
| `components/` | External driver and private KBS publication/recovery code |
| `deployment/` | Source/artifact locks, build recipes and service/cluster/policy templates |
| `docs/`, `tests/` | Installation, operation, trust contracts and tests |
| `artifacts/`, `.local/` (ignored) | Build outputs, disposable prepared sources and private operator evidence |

Exact source identities are in the [source lock](deployment/build/sources.lock.json),
release identities in the [guest](deployment/artifacts.lock.json) and
[runtime](deployment/runtime/artifacts.lock.json) locks. The
[driver provenance](components/confidential-driver/UPSTREAM.md) records its local delta.
Run `bash tests/run.sh` with cached dependencies for offline verification.
Keep credentials, deployed authorization state and private evidence out of source
and release packages.
