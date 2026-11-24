# Confidential OpenShell

Run OpenShell coding agents in Intel TDX guests with attestation-gated
credentials and encrypted persistent workspaces. Each deployment selects one
Kubernetes backend for its supervisor and workload guests.

<table>
<thead>
<tr>
<th>Backend</th>
<th>Guest launch</th>
<th>Workspace</th>
</tr>
</thead>
<tbody>
<tr>
<td><a href="docs/deployment.md">ACK Peer Pods</a></td>
<td>CAA starts a separate ECS TDX VM for each role.</td>
<td>CSI attaches an ESSD; APF and CDH open it in the workload guest.</td>
</tr>
<tr>
<td><a href="deployment/baremetal/README.md">Native Kata on bare metal</a></td>
<td>The worker's Go Kata shim starts local QEMU TDX VMs.</td>
<td>A restartable sidecar holds a raw Block PVC; a guest service opens it
through CDH.</td>
</tr>
</tbody>
</table>

Both use the same verified UKI and root filesystem, official OpenShell v0.1.9
CLI/Gateway, confidential driver and Trustee. Run the control plane on a
trusted system reachable from the guests. Treat the Kubernetes workers,
including the bare-metal host, as untrusted.

Follow the [build guide](docs/build.md), the deployment guide for your chosen
backend above, then [run your first agent](docs/first-agent.md).

Use `./cos --help` for the build/deployment commands. Each command runs one
step, streams progress and reports success/failure, a private log and the next
command. New ACK cluster deployment creates its VPC and vSwitches;
existing-cluster attachment has a separate path. The build and service roles can
share one machine. An existing compatible PodVM image and references can be
reused without rebuilding.

Optional [attestation records](docs/attestation-records.md) expose dated Trustee
appraisals through native sandbox conditions.

See [architecture](docs/architecture.md) for trust boundaries and
[tests](tests/README.md) for verification coverage. Component READMEs describe
internals.

<table>
<thead>
<tr>
<th>Component</th>
<th>Source and integration</th>
</tr>
</thead>
<tbody>
<tr>
<td>Gateway, CLI and supervisor</td>
<td>Unmodified official OpenShell v0.1.9</td>
</tr>
<tr>
<td>AA/CDH and Trustee</td>
<td>Official guest-components v0.23.1 and Trustee v0.23.0 artifacts; TDX
attester selected through upstream build inputs</td>
</tr>
<tr>
<td>Guest</td>
<td>Official CAA Ubuntu mkosi/UKI flow plus measured OpenShell bootstrap,
ECS clock configuration and encrypted-volume initialization</td>
</tr>
<tr>
<td>Confidential ComputeDriver</td>
<td>Derivative of the pinned Kubernetes driver; shared modules compile
from upstream, local code seals and authorizes bootstrap/workspace
resources</td>
</tr>
<tr>
<td>CAA, CSI and PeerPod controller</td>
<td>Pinned sources with the <a href="patches/README.md">required patch
queues</a></td>
</tr>
<tr>
<td>Coding harnesses</td>
<td>Unmodified, digest-pinned OpenShell Community base image with
OpenCode, Codex and Claude Code</td>
</tr>
</tbody>
</table>

The trusted domain contains CLI, Gateway, driver, Trustee and their
authorization state. Guest attestation gates KBS release of launch credentials
and workspace keys. Native TLS/JWT then authenticates credential holders;
operator client keys remain on the trusted host. Provider credentials reach the
attested supervisor at runtime; the external inference API remains outside this
confidential boundary. Cloud orchestration is untrusted. See the architecture
for revocation and retention.

<table>
<thead>
<tr>
<th>Directory</th>
<th>Responsibility</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>repos/</code>, <code>patches/</code></td>
<td>Fixed upstream gitlinks and ordered integration changes</td>
</tr>
<tr>
<td><code>components/</code></td>
<td>External driver and private KBS publication/recovery code</td>
</tr>
<tr>
<td><code>deployment/</code></td>
<td>Source/artifact locks, build recipes and service/cluster/policy
templates</td>
</tr>
<tr>
<td><code>docs/</code>, <code>tests/</code></td>
<td>Installation, operation, trust contracts and tests</td>
</tr>
<tr>
<td><code>artifacts/</code>, <code>.local/</code> (ignored)</td>
<td>Build outputs, disposable prepared sources and private operator
evidence</td>
</tr>
</tbody>
</table>

Exact source identities are in the
[source lock](deployment/build/sources.lock.json), release identities in the
[guest](deployment/artifacts.lock.json) and
[runtime](deployment/runtime/artifacts.lock.json) locks. The
[driver provenance](components/confidential-driver/UPSTREAM.md) records its
local delta. Run `./cos build test` with cached dependencies for offline
verification. Cloud deployment and live TDX acceptance are separate workflows
described in [deployment](docs/deployment.md) and
[live acceptance](docs/live-acceptance.md). Keep credentials, deployed
authorization state and private evidence out of source and release packages.
