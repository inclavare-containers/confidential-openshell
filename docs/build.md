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

An authenticated Git bundle containing the exact commit can replace the network
clone. Check its checksum and `git bundle verify` before cloning. Offline suppliers
also provide module/package caches and these exact Helm archives under
`artifacts/cache/helm/`, with the hashes from the runtime lock:

- `kata-deploy-4.2.0.tgz`
- `peerpodctrl-0.5.0.tgz`
- `peerpods-webhook-0.5.0.tgz`

Keep the original archive bytes; a fresh `helm package` need not reproduce them.
The Kata chart originates at `oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy`;
the PeerPods dependency charts originate in the pinned CAA source.

```bash
python3.11 deployment/build/check-inputs.py
bash deployment/build/prepare-sources.sh cloud-api-adaptor
bash deployment/build/prepare-sources.sh caa-csi-block-driver
bash deployment/build/prepare-sources.sh kata-containers .local/dependencies/kata-containers
python3.11 deployment/build/package-csi-chart.py
```

The checker requires complete source bytes/modes and chart checksums. The helper
applies the checksummed series to separate copies and verifies each result tree;
existing destinations are refused. The CSI chart is packaged from that verified
Git tree with embedded source provenance. Missing inputs block the dependent
build; the driver alone does not require the Kata/chart subset.

## Build integration outputs

### Driver and Kata host shim

The confidential driver is compiled locally. The released Kata guest agent and
genpolicy remain unchanged; the host Go shim patch propagates the existing
`NoNewPrivileges` exec field so its request matches guest policy.

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
python3.11 - "$CONTROLLER_BUILD" <<'PY'
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
builds APF/PUD from the verified CAA tree. B needs privileged Docker, Python 3.11,
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
python3.11 deployment/build/manifest.py --profile release \
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
# Use the exact offline delivery archives verified in docs/build.md; do not repackage.
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
TRUSTED_SSH=trusted-control-host # Existing authenticated administrator alias.
ssh "$TRUSTED_SSH" 'install -d -m 0700 /var/lib/openshell-confidential/operator/handoff'
scp -r "$HANDOFF/". "$TRUSTED_SSH":/var/lib/openshell-confidential/operator/handoff/
```

### Verify and extract on T

Verify `SHA256SUMS` against its hash received through the authenticated
administrative channel before trusting package contents. Extract into an empty destination.
T needs Bash, SSH, tar, coreutils and jq. The source snapshot is for deployment,
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
