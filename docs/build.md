# Build and public handoff

Build on a trusted Linux/amd64 host (**B**); deploy on the trusted service host
(**T**) using the [ordered runbook](deployment.md). They may be the same machine.
An approved compatible PodVM ImageID with its exact references can be reused.
A new image needs a real TDX acceptance run, even when its offline build passes.

Run Bash from the integration checkout with `set -euo pipefail; umask 077`.
Use a clean approved commit and initialized gitlinks. The authoritative inputs are:

| Lock | Contents |
| --- | --- |
| [Source lock](../deployment/build/sources.lock.json) | Upstream commits, independent patch queues and required result trees |
| [Runtime lock](../deployment/runtime/artifacts.lock.json) | OpenShell 0.1.3 releases, OCI inputs, tools, charts and recorded build outputs |
| [Guest lock](../deployment/artifacts.lock.json) | Official Ubuntu/mkosi, released CoCo 0.22 TDX components, Kata agent and pause |
| [Agent lock](../deployment/agent/agent.lock.json) | OpenCode archive and minimal work-image input |

Build outputs go under `artifacts/`, patched copies under `.local/build-sources/`,
original dependencies under `.local/dependencies/`. Do not patch `repos/` or
package operator credentials, private keys, live state, `.git` or `.local`.
Prior output digests identify a released build; record the actual hashes of a new
build rather than assuming byte-identical binaries, OCI archives or disk images.

## Prepare an Ubuntu 24.04 host

Start here on a fresh Linux/amd64 machine, as root, from the repository checkout.
Complete this section before checking inputs or running any build. B and T may
share this installation. These commands use the standard Ubuntu repositories and
upstream release tools; cloud credentials are configured later during deployment.

Use **apt for the host environment**. Only tools that the configured Ubuntu
repositories cannot supply at the required version use upstream downloads:

| Tools | Installation and constraint |
| --- | --- |
| Python, cryptography, YAML parser, Docker, Git, jq, compiler packages | Ubuntu apt packages below |
| Rustup manager | Ubuntu `rustup` package; the compiler is installed through Rustup |
| Rust compiler | OpenShell requires Rust ≥1.94; this checkout selects 1.95.0. Noble's `rustc` candidate is 1.75 |
| Go compiler | Pinned CAA declares Go 1.26.7; Noble's `golang-go` defaults to 1.22 |
| GitHub CLI | The guest provenance verifier needs `gh attestation verify`, absent from Noble's 2.45 package |
| Helm, kubectl, crane, ORAS | This profile's release tools are not supplied at the required versions by the configured Noble repositories |

Ubuntu's [Go package matrix](https://ubuntu.com/developers/docs/reference/availability/go/)
and the local `apt-cache policy` output identify available versions. The Rust and
Go requirements come from the pinned upstream sources, not extra integration
requirements. Apt's `rustup` avoids downloading an installer script, but Rustup
still downloads compiler components. The release downloads below retry connection
failures and reuse checksum-verified cache entries before installation.

### Host packages

Ubuntu 24.04 provides [Python 3.12](https://ubuntu.com/developers/docs/reference/availability/python/).
The maintained scripts require **Python 3.11 or newer**, invoked as `python3`;
do not install a separate `python3.11` package or replace the system interpreter.
Use Ubuntu's `python3-cryptography` package for the trusted service helpers.

```bash
set -euo pipefail
umask 077
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git git-lfs jq openssl python3 python3-cryptography python3-yaml \
  tar gzip xz-utils zstd file binutils ripgrep rsync \
  docker.io docker-buildx runc cryptsetup-bin util-linux
systemctl enable --now docker
python3 -c 'import sys, tomllib, hashlib, cryptography, yaml; assert sys.version_info >= (3, 11); print(sys.version)'
docker version
```

### Build toolchains

On B, install the native compiler dependencies, the Rust toolchain from
`rust-toolchain.toml`, and the Go version recorded in the runtime lock:

```bash
apt-get install -y --no-install-recommends \
  build-essential cmake pkg-config clang libclang-dev libssl-dev rustup
TOOL_CACHE="$PWD/artifacts/cache/host-tools"
mkdir -p "$TOOL_CACHE"
GO_VERSION=$(jq -er .build_outputs.caa.go_version deployment/runtime/artifacts.lock.json)
curl -fL --retry 3 'https://go.dev/dl/?mode=json&include=all' -o "$TOOL_CACHE/go-releases.json"
GO_SHA256=$(jq -er --arg version "go$GO_VERSION" \
  '.[] | select(.version == $version) | .files[] |
   select(.os == "linux" and .arch == "amd64" and .kind == "archive") | .sha256' \
  "$TOOL_CACHE/go-releases.json")
if ! printf '%s  %s\n' "$GO_SHA256" "$TOOL_CACHE/go.tgz" | sha256sum -c - >/dev/null 2>&1; then
  curl -fL --connect-timeout 15 --retry 5 --retry-all-errors \
    "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$TOOL_CACHE/go.tgz"
fi
printf '%s  %s\n' "$GO_SHA256" "$TOOL_CACHE/go.tgz" | sha256sum -c -
test ! -e /usr/local/go
tar -xzf "$TOOL_CACHE/go.tgz" -C /usr/local
printf '\nexport PATH=/usr/local/go/bin:$PATH\n' >> "$HOME/.profile"
export PATH="/usr/local/go/bin:$PATH"
rustup toolchain install 1.95.0 --profile minimal
rustup default 1.95.0
rustup component add --toolchain 1.95.0 rustfmt rust-src rust-analyzer clippy
rustc --version
go version
```

Cargo and Go fetch the dependencies selected by `Cargo.lock` and the pinned
modules during builds. Before the offline test suite, also populate its module
caches as described in [the test guide](../tests/README.md).

### Release command-line tools

Install the lock-pinned Helm, kubectl, crane, GitHub CLI and ORAS releases.
The lock's tool hashes identify **extracted executables**, not their tarballs.
The YAML parser comes from `python3-yaml`; no separate `yq` is required.
GitHub CLI must provide `gh attestation verify`; ORAS/GitHub CLI are used when
fetching the guest release binaries. Already verified cached guest binaries can be reused.

```bash
LOCK=deployment/runtime/artifacts.lock.json
TOOL_CACHE="$PWD/artifacts/cache/host-tools"
mkdir -p "$TOOL_CACHE"
for tool in helm kubectl crane gh oras; do
  version=$(jq -er --arg tool "$tool" '.tools[$tool].version' "$LOCK")
  member=
  case "$tool" in
    helm) url="https://get.helm.sh/helm-v${version}-linux-amd64.tar.gz"; member=linux-amd64/helm ;;
    kubectl) url="https://dl.k8s.io/release/v${version}/bin/linux/amd64/kubectl" ;;
    crane) url="https://github.com/google/go-containerregistry/releases/download/v${version}/go-containerregistry_Linux_x86_64.tar.gz"; member=crane ;;
    gh) url="https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_amd64.tar.gz"; member="gh_${version}_linux_amd64/bin/gh" ;;
    oras) url="https://github.com/oras-project/oras/releases/download/v${version}/oras_${version}_linux_amd64.tar.gz"; member=oras ;;
  esac
  expected=$(jq -er --arg tool "$tool" '.tools[$tool].sha256' "$LOCK")
  if ! printf '%s  %s\n' "$expected" "$TOOL_CACHE/$tool" | sha256sum -c - >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --retry 5 --retry-all-errors \
      "$url" -o "$TOOL_CACHE/$tool.download"
    if [[ -n "$member" ]]; then
      tar -xzOf "$TOOL_CACHE/$tool.download" "$member" > "$TOOL_CACHE/$tool"
    else
      cp "$TOOL_CACHE/$tool.download" "$TOOL_CACHE/$tool"
    fi
  fi
  printf '%s  %s\n' "$expected" "$TOOL_CACHE/$tool" | sha256sum -c -
  install -m 0755 "$TOOL_CACHE/$tool" /usr/local/bin/
done
helm version --short
kubectl version --client
gh attestation verify --help >/dev/null
oras version
```

## Capacity before any build

Check free disk/inodes, Docker cache and competing compiler jobs; reserve room
for compiler output, uncompressed guest images and handoff copies:

```bash
df -h .
df -i .
docker system df
ps -eo pid,comm | rg '(cargo|rustc|docker|buildkit|qemu|make|go)$' || true
```

Reuse verified public release/package caches. Coordinate CPU/memory with other
builds and remove only your own outputs. No nested virtualization is needed.

## Obtain complete fixed sources

Use Rust 1.95.0, Go 1.26.7, make, Git and the lock-resolved Cargo/Go dependencies.
Obtain the complete pinned Kata tree, not a sparse checkout:

```bash
BUILD_ROOT="$PWD"
git submodule update --init repos/openshell repos/cloud-api-adaptor repos/caa-csi-block-driver
mkdir -p .local/dependencies artifacts
KATA_COMMIT=$(jq -er '.["kata-containers"].base' deployment/build/sources.lock.json)
test ! -e .local/dependencies/kata-containers
git clone --no-checkout https://github.com/kata-containers/kata-containers.git .local/dependencies/kata-containers
git -C .local/dependencies/kata-containers checkout --detach "$KATA_COMMIT"
git -C .local/dependencies/kata-containers fsck --connectivity-only
```

A verified Git bundle containing the exact commit can replace the network clone.
Check its checksum and `git bundle verify` before cloning. A supplied checkout
with initialized submodules can be used directly; neither requires GitHub login.
The remaining public downloads need outbound access to GitHub, GHCR, the distro
repositories and the OCI registries named in the locks.

Fetch the published Kata chart. Generate the two unpublished local dependency
charts from their unchanged, pinned CAA Git trees, using the commit timestamp
and fixed file modes. These commands are reproducible and do not require a previously supplied cache:

```bash
CHART_CACHE="$BUILD_ROOT/artifacts/cache/helm"
mkdir -p "$CHART_CACHE"
helm pull oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
  --version 4.2.0 --destination "$CHART_CACHE"
CAA_BASE=$(jq -er '.["cloud-api-adaptor"].base' deployment/build/sources.lock.json)
CAA_MTIME=$(git -C repos/cloud-api-adaptor show -s --format=%cI "$CAA_BASE")
git -c tar.umask=0022 -C repos/cloud-api-adaptor archive --format=tar --mtime="$CAA_MTIME" --prefix=peerpodctrl/ \
  "$CAA_BASE:src/peerpod-ctrl/chart" | gzip -n > "$CHART_CACHE/peerpodctrl-0.5.0.tgz"
git -c tar.umask=0022 -C repos/cloud-api-adaptor archive --format=tar --mtime="$CAA_MTIME" --prefix=peerpods-webhook/ \
  "$CAA_BASE:src/webhook/chart" | gzip -n > "$CHART_CACHE/peerpods-webhook-0.5.0.tgz"
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "$CHART_CACHE/$name" | sha256sum -c -
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
```

Now verify the inputs, then prepare the patched build copies:

```bash
python3 deployment/build/check-inputs.py
bash deployment/build/prepare-sources.sh cloud-api-adaptor
bash deployment/build/prepare-sources.sh caa-csi-block-driver
bash deployment/build/prepare-sources.sh kata-containers .local/dependencies/kata-containers
python3 deployment/build/package-csi-chart.py
```

The checker requires complete source bytes/modes and chart checksums. The helper
applies the checksummed series to separate copies and verifies each result tree;
existing destinations are refused. The CSI chart is packaged from that verified
Git tree with embedded source provenance. Missing inputs block the dependent
build; the driver alone does not require the Kata/chart subset.

## Build integration outputs

### Driver and Kata host shim

The confidential driver is compiled locally. The released Kata guest agent and
genpolicy remain unchanged. The pinned host shim needs the exec `NoNewPrivileges`
backport; [upstream PR #14025](https://github.com/kata-containers/kata-containers/pull/14025)
is merged on main, but that does not add the fix to the pinned 4.2.0 release.

```bash
cargo build --release --locked -p openshell-driver-confidential-kubernetes
install -m 0755 target/release/openshell-driver-confidential-kubernetes artifacts/
```

```bash
set -euo pipefail
KATA_SRC="$PWD/.local/build-sources/kata-containers"
make -C "$KATA_SRC/src/runtime" clean-generated-files
make -C "$KATA_SRC/src/runtime" PREFIX=/opt/kata \
  QEMUCMD=qemu-system-x86_64 STATIC=yes containerd-shim-v2
(cd "$KATA_SRC/src/runtime" && go test ./virtcontainers -run '^TestCmdToKataProcess$' -count=1)
KATA_STAGE="$PWD/.local/kata-shim-install"
make -C "$KATA_SRC/src/runtime" PREFIX=/opt/kata DESTDIR="$KATA_STAGE" \
  STATIC=yes install-containerd-shim-v2
file "$KATA_STAGE/opt/kata/bin/containerd-shim-kata-v2"
SHIM_TRANSFER="$PWD/artifacts"
install -d -m 0700 "$SHIM_TRANSFER"
install -m 0755 "$KATA_STAGE/opt/kata/bin/containerd-shim-kata-v2" \
  "$SHIM_TRANSFER/containerd-shim-kata-v2"
(cd "$SHIM_TRANSFER" && sha256sum containerd-shim-kata-v2 > shim.sha256)
```

### CAA and CSI images

Use the prepared sources. CAA's official Make target selects the Alibaba backend;
[Dockerfile.caa](../deployment/build/Dockerfile.caa) copies only the adapter binary
onto the pinned runtime. CSI uses its prepared Dockerfile.

```bash
set -euo pipefail
CAA_SOURCE="$PWD/.local/build-sources/cloud-api-adaptor"
CAA_TREE=$(git -C "$CAA_SOURCE" write-tree)
CSI_TREE=$(git -C .local/build-sources/caa-csi-block-driver write-tree)
CAA_UPSTREAM_COMMIT=$(git -C "$CAA_SOURCE" rev-parse HEAD)
CSI_UPSTREAM_COMMIT=$(git -C .local/build-sources/caa-csi-block-driver rev-parse HEAD)
CAA_VERSION=$(jq -er .build_outputs.caa.build_args.VERSION deployment/runtime/artifacts.lock.json)
CAA_RUNTIME=$(jq -er .images.caa deployment/runtime/artifacts.lock.json)
CAA_TAG="caa-$(printf '%s' "$CAA_TREE" | cut -c1-8)"
CSI_TAG="csi-$(printf '%s' "$CSI_TREE" | cut -c1-8)"
printf 'CAA_TAG=%s\nCSI_TAG=%s\n' "$CAA_TAG" "$CSI_TAG"
env -u GOFLAGS make -C "$CAA_SOURCE/src/cloud-api-adaptor" \
  RELEASE_BUILD=true BUILTIN_CLOUD_PROVIDERS=alibabacloud \
  GOOPTIONS='GOOS=linux GOARCH=amd64 CGO_ENABLED=0' \
  VERSION="$CAA_VERSION" COMMIT="$CAA_UPSTREAM_COMMIT" cloud-api-adaptor
CAA_CONTEXT="$PWD/artifacts/caa-context"
test ! -e "$CAA_CONTEXT"
install -d -m 0700 "$CAA_CONTEXT"
install -m 0755 "$CAA_SOURCE/src/cloud-api-adaptor/cloud-api-adaptor" "$CAA_CONTEXT/cloud-api-adaptor"
sha256sum "$CAA_CONTEXT/cloud-api-adaptor"
docker build --platform linux/amd64 --build-arg "RUNTIME_IMAGE=$CAA_RUNTIME" \
  -f deployment/build/Dockerfile.caa \
  -t "openshell/cloud-api-adaptor:$CAA_TAG" "$CAA_CONTEXT"

make -C .local/build-sources/caa-csi-block-driver GOOS=linux GOARCH=amd64 \
  VERSION="tree-$CSI_TREE" build
docker build --platform linux/amd64 \
  --label "org.opencontainers.image.revision=$CSI_UPSTREAM_COMMIT" \
  --label "org.confidential-openshell.patched-tree=$CSI_TREE" \
  -f .local/build-sources/caa-csi-block-driver/Dockerfile \
  -t "openshell/caa-csi-block-driver:$CSI_TAG" .local/build-sources/caa-csi-block-driver
```

### PeerPod controller

Prepare the independent `peerpod-ctrl` queue; it includes the generic deletion
idempotency backport and is separate from CAA's adapter queue. The official Make
build enables Alibaba. Package only `/manager` over the pinned runtime, preserving
its configuration/layers with `crane append`:

```bash
ROOT=$(git rev-parse --show-toplevel)
CONTROLLER_BUILD="$ROOT/.local/peerpod-controller"
test ! -e "$CONTROLLER_BUILD"
mkdir -p "$CONTROLLER_BUILD/context"
bash "$ROOT/deployment/build/prepare-sources.sh" peerpod-ctrl
CONTROLLER_SOURCE="$ROOT/.local/build-sources/peerpod-ctrl"
test "$(git -C "$CONTROLLER_SOURCE" write-tree)" = \
  "$(jq -er '.["peerpod-ctrl"].result_tree' "$ROOT/deployment/build/sources.lock.json")"
GOCACHE="$CONTROLLER_BUILD/go-cache" make -C "$CONTROLLER_SOURCE/src/peerpod-ctrl" \
  build BUILTIN_CLOUD_PROVIDERS=alibabacloud
(cd "$CONTROLLER_SOURCE/src/peerpod-ctrl" && go mod verify)
install -m 0755 "$CONTROLLER_SOURCE/src/peerpod-ctrl/bin/manager" "$CONTROLLER_BUILD/context/manager"
cp "$ROOT/deployment/peerpods/Dockerfile.controller" "$CONTROLLER_BUILD/context/Dockerfile"
go version -m "$CONTROLLER_BUILD/context/manager"
sha256sum "$CONTROLLER_BUILD/context/manager"
```

```bash
python3 - "$CONTROLLER_BUILD" <<'PY'
from pathlib import Path
import sys, tarfile
work = Path(sys.argv[1])
binary = work / 'context/manager'
with tarfile.open(work / 'manager.layer.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
    entry = tarfile.TarInfo('manager')
    entry.size, entry.mode, entry.mtime = binary.stat().st_size, 0o755, 0
    with binary.open('rb') as source:
        archive.addfile(entry, source)
PY
CONTROLLER_REPOSITORY=$(jq -er '.build_outputs.peerpod_ctrl.repository' "$ROOT/deployment/runtime/artifacts.lock.json")
PEERPOD_CTRL_TAG=$(jq -er '.build_outputs.peerpod_ctrl.tag' "$ROOT/deployment/runtime/artifacts.lock.json")
CONTROLLER_RUNTIME=$(jq -er '.images.peerpod_ctrl_runtime' "$ROOT/deployment/runtime/artifacts.lock.json")
mkdir -p "$ROOT/artifacts/images"
CONTROLLER_IMAGE_ARCHIVE="$ROOT/artifacts/images/peerpod-controller.tar"
crane append --platform=linux/amd64 --base "$CONTROLLER_RUNTIME" \
  --new_layer "$CONTROLLER_BUILD/manager.layer.tar" --new_tag "$CONTROLLER_REPOSITORY:$PEERPOD_CTRL_TAG" \
  --output "$CONTROLLER_IMAGE_ARCHIVE"
crane digest --tarball "$CONTROLLER_IMAGE_ARCHIVE"
sha256sum "$CONTROLLER_IMAGE_ARCHIVE"
```

### Coding agent image

Build the pinned OpenCode/Python work image without credentials or operator config:

```bash
mkdir -p artifacts/cache/agent artifacts/agent-context
AGENT_VERSION=$(jq -er .version deployment/agent/agent.lock.json)
AGENT_TAG="confidential-opencode:$AGENT_VERSION"
AGENT_ARCHIVE="artifacts/cache/agent/opencode-$AGENT_VERSION.tar.gz"
curl -fL --retry 3 \
  "$(jq -er .release_url deployment/agent/agent.lock.json)" -o "$AGENT_ARCHIVE"
printf '%s  %s\n' "$(jq -er .release_sha256 deployment/agent/agent.lock.json)" \
  "$AGENT_ARCHIVE" | sha256sum -c -
test "$(tar -tzf "$AGENT_ARCHIVE")" = opencode
tar --no-same-owner --no-same-permissions -xzf "$AGENT_ARCHIVE" \
  -C artifacts/agent-context opencode
test -f artifacts/agent-context/opencode && test ! -L artifacts/agent-context/opencode
chmod 0755 artifacts/agent-context/opencode
docker build --platform linux/amd64 -f deployment/agent/Dockerfile \
  -t "$AGENT_TAG" artifacts/agent-context
AGENT_IMAGE_ID=$(docker image inspect "$AGENT_TAG" --format '{{.Id}}')
docker run --rm --network=none "$AGENT_IMAGE_ID" --version
docker run --rm --network=none --entrypoint python3 "$AGENT_IMAGE_ID" --version
```

The version checks must match [the agent lock](../deployment/agent/agent.lock.json).
Run `bash tests/run.sh` with the prepared sources and pinned charts before release.

## Select the guest image

Choose one path before constructing the handoff. Keep the image's region,
ImageID, publisher/release identity, QCOW hash and authenticated reference checksum
in the release record. Compatibility requires immutable Ubuntu UKI/verity boot,
TDX AA/CDH 0.22, measured per-role initdata, sealed bootstrap and encrypted
persistent workspaces. A generic Ubuntu or CoCo image is insufficient by itself.

### Use an existing image

```bash
PODVM_MODE=existing
PODVM_REGION=REPLACE_WITH_TARGET_REGION
PODVM_IMAGE_ID=REPLACE_WITH_APPROVED_PODVM_IMAGE_ID
PODVM_REFERENCE_SOURCE=/absolute/path/to/published.references.json
PODVM_REFERENCE_SHA256=REPLACE_WITH_PUBLISHED_REFERENCE_SHA256
printf '%s  %s\n' "$PODVM_REFERENCE_SHA256" "$PODVM_REFERENCE_SOURCE" | sha256sum -c -
jq -e 'type == "object" and length > 0 and all(.[];
  type == "array" and length > 0 and all(.[]; type == "string" and length > 0))' \
  "$PODVM_REFERENCE_SOURCE" >/dev/null
mkdir -p artifacts/guest
PODVM_REFERENCE_VALUES="artifacts/guest/openshell-guest-${PODVM_REFERENCE_SHA256:0:12}.references.json"
install -m 0644 "$PODVM_REFERENCE_SOURCE" "$PODVM_REFERENCE_VALUES"
PODVM_QCOW2=
```

### Build a new image (optional)

[The guest builder](../deployment/guest/README.md) uses upstream CAA production
mkosi definitions, released AA/CDH/Kata binaries and small measured hooks. It
builds APF/PUD from the verified CAA tree. B needs privileged Docker, Python 3.11 or newer,
jq, crane, runc, curl, tar, zstd, readelf, Go/make and the release/package inputs;
fetching missing CoCo binaries also needs oras and gh for upstream provenance
verification. The maintained tools Dockerfile installs the required mkosi and
verification utilities. Verified public caches may be reused.

```bash
bash deployment/guest/build-image.sh
GUEST_BUILD_RECEIPT=/absolute/path/printed/by/the/build/build.json
test "$(jq -er .integration_commit "$GUEST_BUILD_RECEIPT")" = "$(git rev-parse HEAD)"
PODVM_QCOW2=$(jq -er .qcow2.path "$GUEST_BUILD_RECEIPT")
PODVM_REFERENCE_VALUES=$(jq -er .references.path "$GUEST_BUILD_RECEIPT")
printf '%s  %s\n' "$(jq -er .qcow2.sha256 "$GUEST_BUILD_RECEIPT")" "$PODVM_QCOW2" | sha256sum -c -
printf '%s  %s\n' "$(jq -er .references.sha256 "$GUEST_BUILD_RECEIPT")" "$PODVM_REFERENCE_VALUES" | sha256sum -c -
PODVM_MODE=import
PODVM_REGION=REPLACE_WITH_TARGET_REGION
PODVM_IMAGE_ID=
```

The receipt binds source, payload, final QCOW and references and verifies public
input modes, root verity, PE Authenticode and independently derived UKI/Linux
measurements. Never substitute a previous payload or QCOW. The image map derives
RTMR1 and full RTMR2; the separately reviewed ECS platform map supplies MRTD and
the static RTMR0 event prefix. Actual signed quotes, role appraisal and KBS
positive/negative decisions are required in [deployment step 10](deployment.md#10-verify-both-confidential-roles).

## Build and transfer

### Create the public handoff on B

Continue in the same shell with the tags and guest selection above. Archive only
committed public source and named outputs. The source-only manifest inventories
inputs; `--profile release` requires clean integration/gitlinks and the relevant
verified patch trees, but is still an output inventory, not proof that a build ran.
Keep compiler logs/build receipts privately. Do not re-save the controller archive
created by `crane append`.

```bash
cd "$BUILD_ROOT"
HANDOFF="$BUILD_ROOT/artifacts/handoff"
test ! -e "$HANDOFF" # A fresh handoff cannot include stale or private files.
mkdir -p "$HANDOFF/source" "$HANDOFF/outputs" "$HANDOFF/charts" artifacts/images
docker save -o artifacts/images/caa.tar "openshell/cloud-api-adaptor:$CAA_TAG"
docker save -o artifacts/images/csi.tar "openshell/caa-csi-block-driver:$CSI_TAG"
docker save -o artifacts/images/agent.tar "$AGENT_IMAGE_ID"
GUEST_ARTIFACTS=(--artifact "guest-references=$PODVM_REFERENCE_VALUES")
if [[ "$PODVM_MODE" == import ]]; then
  GUEST_ARTIFACTS+=(--artifact "guest-image=$PODVM_QCOW2")
fi
python3 deployment/build/manifest.py --profile release \
  --artifact driver=artifacts/openshell-driver-confidential-kubernetes \
  --artifact kata-shim=artifacts/containerd-shim-kata-v2 \
  "${GUEST_ARTIFACTS[@]}" \
  --artifact caa-image-archive=artifacts/images/caa.tar \
  --artifact csi-image-archive=artifacts/images/csi.tar \
  --artifact peerpod-controller-image-archive=artifacts/images/peerpod-controller.tar \
  --artifact agent-image-archive=artifacts/images/agent.tar \
  --artifact csi-chart=artifacts/charts/caa-csi-block-driver.tgz > artifacts/build-manifest.json
git archive --format=tar HEAD > "$HANDOFF/source/integration.tar"
for repo in openshell cloud-api-adaptor caa-csi-block-driver; do
  git -C "repos/$repo" archive --format=tar HEAD > "$HANDOFF/source/$repo.tar"
done
cp artifacts/build-manifest.json "$HANDOFF/"
cp artifacts/openshell-driver-confidential-kubernetes artifacts/containerd-shim-kata-v2 \
  "$PODVM_REFERENCE_VALUES" artifacts/images/caa.tar artifacts/images/csi.tar artifacts/images/agent.tar \
  artifacts/images/peerpod-controller.tar \
  "$HANDOFF/outputs/"
if [[ "$PODVM_MODE" == import ]]; then
  cp "$PODVM_QCOW2" "$HANDOFF/outputs/"
  cp "$(dirname "$GUEST_BUILD_RECEIPT")/source-manifest.json" "$HANDOFF/guest-manifest.json"
fi
cp artifacts/charts/caa-csi-block-driver.tgz "$HANDOFF/charts/"
# Use the exact published/reproducible archives verified above.
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "artifacts/cache/helm/$name" | sha256sum -c -
  cp "artifacts/cache/helm/$name" "$HANDOFF/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
jq -n --arg caa "$CAA_TAG" --arg csi "$CSI_TAG" --arg peerpod_ctrl "$PEERPOD_CTRL_TAG" \
  --arg agent "$AGENT_TAG" --arg agent_image_id "$AGENT_IMAGE_ID" \
  --arg mode "$PODVM_MODE" --arg region "$PODVM_REGION" --arg image_id "$PODVM_IMAGE_ID" \
  --arg guest "${PODVM_QCOW2##*/}" --arg refs "$(basename "$PODVM_REFERENCE_VALUES")" \
  '{caa_tag:$caa,csi_tag:$csi,peerpod_ctrl_tag:$peerpod_ctrl,agent_tag:$agent,agent_image_id:$agent_image_id,
    podvm_mode:$mode,podvm_region:$region,podvm_image_id:$image_id,
    guest:(if $mode == "import" then $guest else null end),references:$refs}' > "$HANDOFF/selection.json"
(cd "$HANDOFF" && sha256sum source/*.tar outputs/* charts/* \
  *.json > SHA256SUMS)
sha256sum "$HANDOFF/SHA256SUMS" # Retain through the authenticated administrative channel.
```

If **B and T are the same host**, copy the public handoff locally:

```bash
install -d -m 0700 /var/lib/openshell-confidential/operator/handoff
cp -a "$HANDOFF/". /var/lib/openshell-confidential/operator/handoff/
```

For **separate B and T hosts**, transfer over the existing administrator connection:

```bash
TRUSTED_SSH=trusted-control-host # Replace with the authenticated T host alias.
ssh "$TRUSTED_SSH" 'install -d -m 0700 /var/lib/openshell-confidential/operator/handoff'
scp -r "$HANDOFF/". "$TRUSTED_SSH":/var/lib/openshell-confidential/operator/handoff/
```

### Verify and extract on T

Verify `SHA256SUMS` against its hash received through the authenticated
administrative channel before trusting package contents. Extract into an empty destination.
On a separate fresh Ubuntu T, first run the [host package](#host-packages)
commands. The source snapshot is for deployment,
not a Git build checkout; CSI is installed from the separate patched chart.

```bash
set -euo pipefail
umask 077
HANDOFF=/var/lib/openshell-confidential/operator/handoff
EXPECTED_HANDOFF_SHA256=REPLACE_WITH_APPROVED_CHECKSUM_LIST_SHA256
printf '%s  %s\n' "$EXPECTED_HANDOFF_SHA256" "$HANDOFF/SHA256SUMS" | sha256sum -c -
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
SOURCE_ROOT=/opt/confidential-openshell
test ! -e "$SOURCE_ROOT"
install -d -m 0755 "$SOURCE_ROOT"
tar -xf "$HANDOFF/source/integration.tar" -C "$SOURCE_ROOT"
for repo in openshell cloud-api-adaptor caa-csi-block-driver; do
  mkdir -p "$SOURCE_ROOT/repos/$repo"
  tar -xf "$HANDOFF/source/$repo.tar" -C "$SOURCE_ROOT/repos/$repo"
done
OPERATOR_DIR=/var/lib/openshell-confidential/operator/cluster-config
install -d -m 0700 "$OPERATOR_DIR"
install -m 0755 "$HANDOFF/outputs/containerd-shim-kata-v2" "$OPERATOR_DIR/"
(cd "$OPERATOR_DIR" && sha256sum containerd-shim-kata-v2 > shim.sha256)
cd "$SOURCE_ROOT"
```

[Deployment](deployment.md) initializes the remaining T variables, publishes the
OCI archives and records destination digests. Private cloud values and state stay
under the operator/configuration directories, outside this public handoff.

## Package the Kata host shim

Run this on T after [registry setup](deployment.md#6-configure-registry-and-transfer-digest-pinned-images),
before installing Kata. `OPERATOR_DIR`, `REGISTRY_ADDR` and registry TLS trust
come from that runbook. The kata-deploy installer extracts a component archive;
replace the shim **inside** that archive, then append one OCI layer. A loose ELF
in the image would not replace the installed worker shim.

```bash
KATA_DEPLOY_UPSTREAM=$(jq -er .images.kata_deploy deployment/runtime/artifacts.lock.json)
KATA_DEPLOY_DIGEST=${KATA_DEPLOY_UPSTREAM##*@}
KATA_DEPLOY_MIRROR="${REGISTRY_ADDR}/openshell/mirror/kata_deploy:4.2.0"
KATA_DEPLOY_BASE="${REGISTRY_ADDR}/openshell/mirror/kata_deploy@$KATA_DEPLOY_DIGEST"
OVERLAY_DIR="$OPERATOR_DIR/kata-shim-overlay"
install -d -m 0700 "$OVERLAY_DIR/original" "$OVERLAY_DIR/modified"
(cd "$OPERATOR_DIR" && sha256sum -c shim.sha256)
KATA_SHIM_SHA256=$(cut -d ' ' -f1 "$OPERATOR_DIR/shim.sha256")
if ! crane digest "$KATA_DEPLOY_BASE" >/dev/null 2>&1; then
  crane copy --platform linux/amd64 "$KATA_DEPLOY_UPSTREAM" "$KATA_DEPLOY_MIRROR"
fi
test "$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$KATA_DEPLOY_BASE")" = "$KATA_DEPLOY_DIGEST"
docker pull "$KATA_DEPLOY_BASE"
KATA_CONTAINER=$(docker create "$KATA_DEPLOY_BASE")
docker cp "$KATA_CONTAINER:/opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst" "$OVERLAY_DIR/original.tar.zst"
docker rm "$KATA_CONTAINER"
printf '%s  %s\n' 1b8aa859195c33f0c85c8d31dd0dd1aa0ac523d8a9a102c92af248f9e42e6a0d "$OVERLAY_DIR/original.tar.zst" | sha256sum -c -
zstd -dc "$OVERLAY_DIR/original.tar.zst" | tar -xf - -C "$OVERLAY_DIR/original"
cp -a "$OVERLAY_DIR/original/." "$OVERLAY_DIR/modified/"
install -m 0755 "$OPERATOR_DIR/containerd-shim-kata-v2" \
  "$OVERLAY_DIR/modified/opt/kata/bin/containerd-shim-kata-v2"
(cd "$OVERLAY_DIR/original" && find . -printf '%P %y %m %l\n' | LC_ALL=C sort) > "$OVERLAY_DIR/original-layout"
(cd "$OVERLAY_DIR/modified" && find . -printf '%P %y %m %l\n' | LC_ALL=C sort) > "$OVERLAY_DIR/modified-layout"
cmp "$OVERLAY_DIR/original-layout" "$OVERLAY_DIR/modified-layout"
diff -qr "$OVERLAY_DIR/original" "$OVERLAY_DIR/modified" > "$OVERLAY_DIR/content.diff" || test "$?" -eq 1
test "$(wc -l < "$OVERLAY_DIR/content.diff")" -eq 1
grep -Fx "Files $OVERLAY_DIR/original/opt/kata/bin/containerd-shim-kata-v2 and $OVERLAY_DIR/modified/opt/kata/bin/containerd-shim-kata-v2 differ" "$OVERLAY_DIR/content.diff"
```

```bash
tar --sort=name --numeric-owner --owner=0 --group=0 -cf - -C "$OVERLAY_DIR/modified" . \
  | zstd -T0 -10 -o "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst"
zstd -dc "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst" \
  | tar -tf - | grep -Fx './opt/kata/bin/containerd-shim-kata-v2'
install -d -m 0700 "$OVERLAY_DIR/layer/opt/kata-artifacts/tarballs"
install -m 0644 "$OVERLAY_DIR/kata-static-shim-v2-go.tar.zst" \
  "$OVERLAY_DIR/layer/opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst"
tar -cf "$OVERLAY_DIR/kata-deploy-overlay.layer.tar" -C "$OVERLAY_DIR/layer" \
  opt/kata-artifacts/tarballs/kata-static-shim-v2-go.tar.zst
KATA_DEPLOY_PRIVATE="${REGISTRY_ADDR}/openshell/kata-deploy-shim-nnp:4.2.0"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane append --platform linux/amd64 \
  -b "$KATA_DEPLOY_BASE" -f "$OVERLAY_DIR/kata-deploy-overlay.layer.tar" \
  -t "$KATA_DEPLOY_PRIVATE"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$KATA_DEPLOY_PRIVATE"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest "$KATA_DEPLOY_BASE" \
  | jq -r '.layers[].digest' > "$OVERLAY_DIR/base-layers"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest "$KATA_DEPLOY_PRIVATE" \
  | jq -r '.layers[].digest' > "$OVERLAY_DIR/patched-layers"
test "$(wc -l < "$OVERLAY_DIR/patched-layers")" -eq "$(( $(wc -l < "$OVERLAY_DIR/base-layers") + 1 ))"
sed '$d' "$OVERLAY_DIR/patched-layers" | cmp - "$OVERLAY_DIR/base-layers"
```

Record the returned image digest and use it in `kata-deploy.image.reference`.
The checks above require exactly one executable content change, matching path,
mode and symlink layouts, and all inherited OCI layers unchanged. Guest agent,
genpolicy and other components stay at the official release. Every selected worker
must read back the installed shim hash after rollout.
