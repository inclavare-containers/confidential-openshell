# Confidential OpenShell

Run OpenShell coding agents in Alibaba Cloud Intel TDX guests, with attestation-gated
credentials and encrypted persistent workspaces.

The main profile uses native OpenShell v0.1.3, official CoCo 0.22 AA/CDH and Trustee,
and the upstream Ubuntu UKI image flow on ACK/PeerPods. A local confidential
Kubernetes driver connects these components; OpenShell keeps its native protocol
and user commands.

Deployment instructions target a fresh development environment with the pinned components.

To install, follow these guides in order:

1. [Build](docs/build.md): prepare Ubuntu, build each component and package the outputs.
2. [Deploy](docs/deployment.md): configure ACK, Trustee, PeerPods and the native Gateway.
3. [Coding harnesses](docs/first-agent.md): start OpenCode, Codex or Claude Code, reconnect and check persistent Stop/Start.

Each installation step has its own command and expected result. The build and
service roles can share one machine. An approved compatible PodVM ImageID and
matching references can be reused without rebuilding the guest.

See [architecture](docs/architecture.md) for trust boundaries and [tests](tests/README.md)
for verification coverage. Component READMEs describe internals.

| Component | Source and integration |
| --- | --- |
| Gateway, CLI and supervisor | Unmodified official OpenShell v0.1.3 |
| AA/CDH and Trustee | Official CoCo v0.22.0 release images/binaries; TDX attester selected through upstream build inputs |
| Guest | Official CAA Ubuntu mkosi/UKI flow plus measured OpenShell bootstrap, ECS clock configuration and encrypted-volume initialization hooks |
| Confidential ComputeDriver | Derivative of the pinned Kubernetes driver; shared modules compile from upstream, local code seals and authorizes bootstrap/workspace resources |
| CAA, CSI, PeerPod controller and Kata host shim | Pinned sources with the [required patch queues](patches/README.md) |
| Coding harnesses | Unmodified, digest-pinned OpenShell Community base image with OpenCode, Codex and Claude Code |

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
