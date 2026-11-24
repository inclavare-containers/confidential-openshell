# Build

Start on Ubuntu 24.04 amd64 with root access, 8 CPUs, 32 GiB RAM and at least
150 GiB free disk. The build machine can also host the trusted services.
Builds use Docker and the host kernel; nested virtualization is not needed.

Run these commands from the supplied Git checkout. `./cos` runs one step,
prints its purpose and streams progress, then reports `OK` or `FAILED`,
elapsed time, a private log path and the next command. On failure, correct the
reported problem and repeat that step. Build logs stay under `.local/logs/`
and are excluded from the release.

## Prepare an Ubuntu 24.04 host

### Host packages

```bash
./cos host packages
```

Installs Ubuntu packages, including Python 3.12, Docker and compiler
dependencies, then starts Docker. Success prints Python and Docker server
versions.

### Build toolchains

```bash
./cos host toolchains
```

Installs the pinned Rust 1.95.0 and Go 1.26.11 toolchains. These sources need
newer compiler versions than Ubuntu 24.04 supplies. Matching versions are
reused.

### Release tools

```bash
./cos host tools
```

Installs checksum-pinned Helm, kubectl, crane, GitHub CLI, ORAS and yq v4 and
prints their versions. Ubuntu supplies the other tools and the Python YAML
parser.

Downloads need access to GitHub, GHCR, Docker registries and Go/Rust release
servers.

## Obtain complete fixed sources

```bash
./cos build sources
```

Initializes the pinned submodules, fetches the released Kata chart, prepares the
patch queues and packages charts. Expect passed input checks and
`Source trees and charts ready`. Prepared copies live under
`.local/build-sources/`; `repos/` remains unchanged. A supplied checkout with
initialized submodules needs no GitHub authentication for the remaining public
inputs.

## Build integration outputs

### Driver

```bash
./cos build driver
```

Produces `artifacts/openshell-driver-confidential-kubernetes`.

### Cloud API adaptor

```bash
./cos build caa
```

Builds the Alibaba adaptor with upstream Make and packages it over the pinned
runtime. Success prints the local image tag.

### Workspace CSI

```bash
./cos build csi
```

Builds the CSI image and `artifacts/charts/caa-csi-block-driver.tgz`.

### PeerPod controller

```bash
./cos build controller
```

Builds the Alibaba controller and writes
`artifacts/images/peerpod-controller.tar`. Only its executable replaces the one
in the pinned runtime image.

OpenCode, Codex and Claude Code use the unchanged OpenShell Community image.
There is no coding-agent image to build.

### Offline checks

```bash
./cos build test-cache
```

Downloads the locked test dependencies. Then run:

```bash
./cos build test
```

Runs the [offline suites](../tests/README.md). These checks do not exercise
cloud deployment or real TDX attestation.

## Select the guest image

### Build the Ubuntu guest

```bash
./cos build guest --region cn-beijing
```

The ACK example selects a TDX-capable instance family in Beijing Zone I. Choose
a supported region and zone for your deployment. Region and zone are
configurable; ECS validates the actual TDX launch parameters. This step builds
the upstream Ubuntu UKI/verity image, verifies it, records its measurements and
selects that exact build for the release. It prints the QCOW2, reference JSON
and receipt paths; there is no receipt path to copy into another command. See
[guest internals](../deployment/guest/README.md).

### Use an existing image instead

Skip the guest build only when a publisher supplies a compatible image and
matching references. Run:

```bash
./cos build guest-existing --region cn-beijing
```

This option is for Peer Pods. Native Kata requires the verified QCOW2 as well as
the matching references to prepare the UKI and raw system disk. The command asks
for the ECS ImageID, local reference JSON path and reference checksum obtained
from the publisher, then verifies and records the selection. The image must
support TDX AA/CDH, sealed bootstrap and encrypted workspaces.

## Build and transfer

### Package the release

Use a clean committed checkout after completing the builds and guest selection:

```bash
./cos build package
```

Produces `artifacts/handoff/` with public sources, binaries, images, charts,
guest references and a build manifest. Saves `artifacts/handoff.sha256` for the
installation step. Credentials and deployment state are not packaged.
An existing handoff directory is refused to prevent mixing releases.

### Install on the same machine

```bash
./cos release install
cd /opt/confidential-openshell
```

Uses the saved build checksum, verifies the handoff, copies it into
`/var/lib/openshell-confidential/operator/handoff` and installs deployment
sources under `/opt/confidential-openshell`. The Git build checkout is retained.
Continue with [deployment](deployment.md).

### Install on a separate trusted service host

Copy the source checkout, `artifacts/handoff/` and `artifacts/handoff.sha256`
over your normal administrator SSH connection, keeping their relative paths.
On the Ubuntu 24.04 service host, from the copied source:

```bash
./cos host service-packages
./cos host tools
./cos release install
cd /opt/confidential-openshell
```

If the handoff is elsewhere, run `./cos release install --handoff` with its
local directory as the argument; it asks for the checksum retained on the build
host. This host needs no compiler toolchains or build caches and can be outside
the cloud.

The [source](../deployment/build/sources.lock.json),
[runtime](../deployment/runtime/artifacts.lock.json) and
[guest](../deployment/artifacts.lock.json) locks define inputs. Real attestation
and workspace checks follow
[deployment](deployment.md#10-verify-both-confidential-roles).
