# Build

Use an Ubuntu 24.04 amd64 machine with root access, 8 CPUs, 32 GiB RAM and
at least 150 GiB free disk. Docker runs native builds; nested virtualization is
not needed. Commands below run from this repository checkout.

Builds produce public artifacts under `artifacts/`. Patched upstream copies live
under `.local/build-sources/`; the original `repos/` checkouts remain unchanged.
Keep credentials and deployment state outside the build package.

## Prepare an Ubuntu 24.04 host

Run these three steps separately. Each prints the installed versions or a success
message. If a download fails, fix connectivity and repeat that step; verified
cached downloads are reused.

### Host packages

```bash
bash deployment/build/install-host-packages.sh build
```

This installs Ubuntu packages, including Python 3, Docker, compiler dependencies
and Rustup, then starts Docker. A service-only host can use `service` instead of
`build`. Python must be at least 3.11; Ubuntu 24.04 supplies 3.12.

### Build toolchains

```bash
bash deployment/build/install-toolchains.sh
```

Expect Rust 1.95.0 and Go 1.26.7. The script reads the repository toolchain/locks,
installs Go under `/usr/local/go`, and configures its PATH for future login shells.
It reuses matching installations and refuses to replace a different Go installation.

These compiler downloads are necessary: the pinned upstream sources require
newer versions than Ubuntu 24.04 supplies. Rustup itself comes from apt.

### Release command-line tools

```bash
bash deployment/build/install-release-tools.sh
```

This installs checksum-pinned Helm, kubectl, crane, GitHub CLI, ORAS and yq v4.
CAA's upstream Makefiles require yq v4; Ubuntu's `yq` is a different implementation.
The test suite uses Ubuntu's Python YAML parser.

All downloads need outbound access to the URLs and registries in the locks,
including GitHub, GHCR, Go and Rust release servers. The scripts honor standard
proxy variables. A retry cannot fix blocked outbound access.

If `docker pull` times out, configure outbound access for the **Docker daemon**
using the [Docker proxy guide](https://docs.docker.com/engine/daemon/proxy/).
Setting `HTTPS_PROXY` only in your shell does not configure the daemon. Verify
`docker pull` works before starting the image builds below.

## Obtain complete fixed sources

```bash
bash deployment/build/fetch-inputs.sh
```

This initializes the pinned submodules, fetches the complete Kata source revision,
prepares the patch queues and packages the required charts. Expect all
`check-inputs.py` checks to report `passed`, followed by `Source trees and charts
ready`. Existing prepared trees are reused only when their base, patched tree
and working files match.

A supplied checkout with initialized submodules needs no GitHub authentication.
Kata and the remaining release inputs are public downloads.

## Build integration outputs

Run one component at a time. A failure leaves the other components available;
repeat the failed build after correcting its error.

### Driver and Kata host shim

```bash
bash deployment/build/build-driver.sh
```

Output: `artifacts/openshell-driver-confidential-kubernetes`.

```bash
bash deployment/build/build-kata-shim.sh
```

Output: `artifacts/containerd-shim-kata-v2` and `artifacts/shim.sha256`.
The shim build also runs the exec-process conversion test. Its patch is merged
upstream, but the pinned Kata 4.2.0 release still needs the backport. The guest
agent and policy generator use unmodified release binaries.

### CAA and CSI images

```bash
bash deployment/build/build-caa.sh
```

Builds the Alibaba adapter using upstream Make, then packages it over the pinned
CAA runtime. Prints the local image tag.

```bash
bash deployment/build/build-csi.sh
```

Builds the CSI image and `artifacts/charts/caa-csi-block-driver.tgz` from the verified
patched source. Prints the local image tag.

### PeerPod controller

```bash
bash deployment/build/build-controller.sh
```

Builds the Alibaba controller and writes `artifacts/images/peerpod-controller.tar`.
Only the controller executable is added to the pinned runtime image.

### Coding agent image

```bash
bash deployment/build/build-agent.sh
```

Builds the pinned OpenCode/Python image without provider credentials and checks
both executable versions.

### Check the builds

```bash
bash deployment/build/cache-test-dependencies.sh
bash tests/run.sh
```

The first command fetches locked dependencies. The second runs the offline suite.
See [test coverage](../tests/README.md). Neither command proves real TDX attestation.

## Select the guest image

Choose one of the following routes. Both save the selection for packaging, so
later commands do not depend on shell variables from earlier build steps.

### Use an existing image

Use an approved compatible image and its authenticated reference file. A generic
Ubuntu image cannot replace the measured UKI/verity image with TDX AA/CDH, sealed
bootstrap and encrypted workspace support.

```bash
bash deployment/build/select-guest.sh existing \
  cn-beijing IMAGE_ID /path/to/image.references.json APPROVED_REFERENCE_SHA256
```

Replace the region, ECS ImageID and reference inputs with your release values.
The script checks the reference checksum and copies it into `artifacts/guest/`.

### Build a new image (optional)

```bash
bash deployment/guest/build-image.sh
```

The builder prints the path to its `build.json` receipt. Select that exact result:

```bash
bash deployment/build/select-guest.sh built cn-beijing /path/printed/by/build/build.json
```

The receipt binds the source commit, payload, final QCOW2 and independently derived
measurements. See [guest internals](../deployment/guest/README.md). A new image
still needs the [real deployment checks](deployment.md#10-verify-both-confidential-roles).

## Build and transfer

### Create the public handoff on B

Use a clean committed checkout with all builds above complete:

```bash
bash deployment/build/package-release.sh
```

Output: `artifacts/handoff/`, containing public source snapshots, binaries, image
archives, charts, the selected guest references and a build manifest. The script
prints the SHA-256 of `SHA256SUMS`; keep it with the release record. The directory
must be absent before packaging to avoid mixing releases.

For a build and service host on the same machine:

```bash
install -d -m 0700 /var/lib/openshell-confidential/operator/handoff
cp -a artifacts/handoff/. /var/lib/openshell-confidential/operator/handoff/
```

For separate hosts, transfer that directory over your administrator SSH connection:

```bash
ssh TRUSTED_HOST 'install -d -m 0700 /var/lib/openshell-confidential/operator/handoff'
scp -r artifacts/handoff/. TRUSTED_HOST:/var/lib/openshell-confidential/operator/handoff/
```

### Verify and extract on T

On the service host, use the checksum saved during packaging:

```bash
bash deployment/build/unpack-release.sh \
  /var/lib/openshell-confidential/operator/handoff APPROVED_SHA256SUMS_HASH
cd /opt/confidential-openshell
```

This verifies the package and installs public source into a new
`/opt/confidential-openshell`. For a separate service host, copy this checkout's
`deployment/` scripts there first, then install the `service` host packages and
release tools. The extracted snapshot is for deployment; build from the Git checkout.

Continue with [deployment](deployment.md).

## Package the Kata host shim

Run this on the service host after the deployment guide's
[registry step](deployment.md#6-configure-registry-and-transfer-digest-pinned-images):

```bash
bash deployment/build/package-kata-shim.sh
```

Uses exported `HOST_IP` and the verified handoff shim. It replaces the executable
inside kata-deploy's component archive and publishes one additional OCI layer.
It checks that the archive layout and inherited layers remain intact, then writes
`$OPERATOR_DIR/kata-deploy-image.txt`. Use that digest in the PeerPods values.

The [source](../deployment/build/sources.lock.json),
[runtime](../deployment/runtime/artifacts.lock.json),
[guest](../deployment/artifacts.lock.json) and
[agent](../deployment/agent/agent.lock.json) locks define the inputs. A build
manifest inventories outputs; it does not replace build logs or live acceptance.
