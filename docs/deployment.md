# Deploy

This guide installs native OpenShell 0.1.3 with the Ubuntu UKI / CoCo 0.22 profile
on Alibaba Cloud ACK and Intel TDX. Start with a fresh development environment.
For an already installed Gateway, use [first agent](first-agent.md).

You need:

- A trusted Ubuntu service host for Gateway, driver, Trustee and the private registry.
  It can also be the build machine.
- An ACK cluster with RRSA and enforced NetworkPolicy, plus access to its workers.
- A compatible TDX PodVM image and its approved reference file.
- Administrator access to ACK, ECS, VPC, RAM and the image registry.

Each numbered step is independent. Commands run as root on the trusted service
host unless a worker is named. Keep edited configuration and credentials under
`/var/lib/openshell-confidential/operator/`, outside the source checkout.

## 1. Pin sources and build integration binaries/images

Follow [build](build.md) in order: install tools, prepare sources, build each
component and run the offline tests. The build guide gives the command and output
for each component; there is no combined install-and-deploy command.

## 2. Select the guest image and matching references

In the build guide, [select a guest image](build.md#select-the-guest-image), then
[package and unpack the release](build.md#build-and-transfer). The verified
public source should now be at `/opt/confidential-openshell` on the service host.
A new guest image needs import in step 3; an approved ImageID can be reused.

Set the service host's private IPv4 once. Repeat these exports when opening a
new shell; scripts read the image selection from the handoff:

```bash
cd /opt/confidential-openshell
export HOST_IP=YOUR_TRUSTED_PRIVATE_IPV4
export HANDOFF=/var/lib/openshell-confidential/operator/handoff
export OPERATOR_DIR=/var/lib/openshell-confidential/operator/cluster-config
```

Use the same address for Gateway, KBS and registry throughout this guide.
The [architecture](architecture.md) explains the trusted host boundary.

## 3. Prepare cluster, select the cloud image and configure identities

### Create or select ACK

Follow the [ACK creation guide](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster)
and use Terway shared ENI, RRSA, and enforced ingress/egress NetworkPolicy.
Workers need containerd and `supplementalGroupsPolicy` support. The tested profile
uses Kubernetes 1.36 and containerd 2.3.4 with configuration version 3.

Download the administrator kubeconfig from ACK's connection page into
`$OPERATOR_DIR/administrator-kubeconfig`, then check cluster access:

```bash
export KUBECONFIG="$OPERATOR_DIR/administrator-kubeconfig"
chmod 0600 "$KUBECONFIG"
kubectl get nodes -o wide
kubectl get nodes -o json | jq -e '.items | length > 0'
kubectl get nodes -o json | jq -e 'all(.items[];
  .status.features.supplementalGroupsPolicy == true and
  (.status.nodeInfo.containerRuntimeVersion | startswith("containerd://")) and
  any(.status.conditions[]; .type == "Ready" and .status == "True"))'
```

Create a dedicated PodVM vSwitch and security group in the cluster VPC. Select a
TDX instance type, such as `ecs.g9i.xlarge`, in a zone with available capacity.
Configure worker–PodVM VXLAN connectivity using the
[Alibaba PeerPods guide](https://confidentialcontainers.org/docs/examples/alibaba-cloud-simple/).
Allow the approved private clients to reach this host on registry 5000, KBS 8443
and Gateway 9443. Restrict SSH separately.

### Confirm or import the PodVM image

Read the selected region and image from `$HANDOFF/selection.json`. For an existing
image, check its release identity and references. For a new QCOW2, upload the
verified handoff output to private OSS and follow
[ECS custom-image import](https://www.alibabacloud.com/help/en/ecs/user-guide/import-a-custom-image).

Both routes require an `Available` Linux/x86_64 image with UEFI and NVMe support.
Import QCOW2 as Ubuntu/Linux with a system disk of at least 20 GiB. The PeerPods
example requests 40 GiB. CAA enables TDX during VM creation; image import has no
TPM setting. Record the confirmed ImageID:

```bash
printf '%s\n' YOUR_CONFIRMED_IMAGE_ID > "$OPERATOR_DIR/podvm-image-id.txt"
```

Keep the region, ImageID and authenticated reference checksum together. An image
copied to another region needs its destination ImageID recorded separately.

### Configure RAM roles

Enable [RRSA](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services)
and obtain the OIDC provider ARN and issuer. Copy the four
[RAM templates](../deployment/ack/ram/) into the private operator directory.
Fill in account, region, cluster, OIDC, vSwitch and ownership tags, then create
these separate roles and attach only their corresponding permissions:

| Role | ServiceAccounts |
| --- | --- |
| CAA/controller | `cloud-api-adaptor`, `peerpodctrl-controller-manager` in `confidential-containers-system` |
| CSI | `caa-csi-block` in `caa-csi-block` |

The CAA role needs `vpc:DescribeVSwitchAttributes` on the configured vSwitch.
Use the same role ARNs, OIDC identity and ownership tags in the Helm values below.
Do not put access keys in Helm values or grant cloud creation permissions to node Pods.

## 4. Install Trustee and register the approved image references

### Create the initial certificates

```bash
bash deployment/trustee/create-certificates.sh
```

Creates the CA, private HTTPS server certificate and separate AS token signer
under `/etc/trustee/tls`, with `HOST_IP` in the server SAN. It refuses an existing
PKI directory. Keep an existing complete certificate set when repeating later
steps; never regenerate it to resolve an unrelated installation error.

### Install Trustee

```bash
bash deployment/trustee/install.sh
```

Pulls the locked official AS/KBS images, installs configuration and service units,
and initializes policies with empty bindings. It does not start the services or
replace an existing resource policy. Empty bindings deny resource release.

### Start AS, register references, then start KBS

Select the image reference filename from `$HANDOFF/selection.json`. Separately
review the [ECS platform map](../deployment/trustee/ecs-tdx-platform.references.json)
and use its approved checksum:

```bash
export PODVM_REFERENCE_VALUES="$HANDOFF/outputs/$(jq -er .references "$HANDOFF/selection.json")"
export PODVM_PLATFORM_REFERENCES="$PWD/deployment/trustee/ecs-tdx-platform.references.json"
PLATFORM_SHA256=YOUR_APPROVED_PLATFORM_REFERENCE_SHA256
printf '%s  %s\n' "$PLATFORM_SHA256" "$PODVM_PLATFORM_REFERENCES" | sha256sum -c -
systemctl enable --now as.service
python3 deployment/trustee/register-references.py \
  --address http://127.0.0.1:50004 \
  --references "$PODVM_REFERENCE_VALUES" --references "$PODVM_PLATFORM_REFERENCES"
systemctl enable --now kbs.service
systemctl is-active as.service kbs.service
```

The registrar reads the values back from BuiltIn RVPS. Confirm anonymous access
to the HTTPS resource endpoint returns **401 or 403**:

```bash
curl --noproxy '*' --cacert /etc/trustee/tls/ca.pem -sS -o /dev/null \
  -w '%{http_code}\n' "https://${HOST_IP}:8443/kbs/v0/resource/default/bootstrap/anonymous-check"
```

This checks the listener, certificate and denial; real attestation is checked in
step 10. Reference/policy details are in the [Trustee reference](../deployment/trustee/README.md).

## 5. Generate measured base initdata

```bash
bash deployment/guest/install-initdata.sh
```

Writes `/etc/openshell-confidential/guest-initdata-base.toml` using `HOST_IP` and
the Trustee public CA. This is a deny-only fallback for CAA. The driver generates
and authorizes the actual per-role, per-attempt initdata before scheduling.

## 6. Configure registry and transfer digest-pinned images

### Start the private TLS registry

```bash
bash deployment/peerpods/start-registry.sh
```

Installs the public CA in the host trust store, starts the pinned registry on
`HOST_IP:5000`, and checks HTTPS `/v2/`. Its durable data is under
`/var/lib/openshell-confidential/registry`.

### Configure each worker to trust the registry

Copy and edit the [registry hosts template](../deployment/peerpods/registry-hosts.example.toml)
with `HOST_IP:5000`. Transfer that file and `/etc/trustee/tls/ca.pem` to each worker.
Install them as:

| Worker path | File |
| --- | --- |
| `/etc/containerd/certs.d/HOST_IP:5000/hosts.toml` | Edited registry hosts template |
| `/etc/containerd/certs.d/HOST_IP:5000/ca.crt` | Trustee public CA |

Keep containerd's effective CRI registry `config_path=/etc/containerd/certs.d`.
Only the public CA goes to workers.

### Publish the images

```bash
bash deployment/peerpods/publish-images.sh
bash deployment/build/package-kata-shim.sh
```

The first command loads the authenticated handoff archives and mirrors the pinned
runtime images. The second adds the host-shim replacement to kata-deploy.
Both write destination digest references to `$OPERATOR_DIR/*-image.txt`.
Use those exact references in the next step. No insecure registry flags are needed.

## 7. Install Kata, PeerPods and CSI, then verify workers

### Install cluster dependencies

```bash
bash deployment/peerpods/fetch-prerequisites.sh
```

In `$OPERATOR_DIR/agent-sandbox-pinned.yaml`, set only the controller image to
`images.agent_sandbox_controller` from the runtime lock, or its recorded mirror.
Then install:

```bash
kubectl apply --server-side -f "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller --timeout=10m
helm upgrade --install cert-manager "$OPERATOR_DIR/cert_manager_chart" \
  --namespace cert-manager --create-namespace \
  --values deployment/peerpods/cert-manager-values.json --wait --timeout=15m
```

A compatible existing cert-manager installation can be used instead.

### Configure and install PeerPods

```bash
cp deployment/peerpods/peerpods-values.example.yaml "$OPERATOR_DIR/peerpods-values.yaml"
${EDITOR:-vi} "$OPERATOR_DIR/peerpods-values.yaml"
```

Fill in these deployment-specific values:

| Values | Source |
| --- | --- |
| CAA, controller, kata-deploy and pause images | Digest records from step 6 |
| ImageID, region, VPC, vSwitch, security group and TDX instance type | Step 3 |
| RRSA role/OIDC and ownership tags | Step 3; match RAM restrictions |
| `INITDATA` | `gzip -n -c /etc/openshell-confidential/guest-initdata-base.toml \| base64 -w0` |

Label each intended worker, then install:

```bash
kubectl label node YOUR_WORKER_NODE node.kubernetes.io/worker= --overwrite
bash deployment/peerpods/install-peerpods.sh
```

The script verifies chart dependencies, renders the release, installs it, applies
the controller RRSA token mount, and waits for rollouts. Check desired/ready counts
cover every selected worker; a zero-node DaemonSet is not a successful deployment.
After changing provider ConfigMap values, restart both CAA and the controller so
their `envFrom` settings reload.

### Configure and check each worker

After each kata-deploy rollout, inspect the containerd service command to find its
actual config file, then use `containerd --config PATH config dump` to locate the
`kata-remote` runtime's `options.ConfigPath`. Merge the
[Kata settings](../deployment/peerpods/kata-remote-settings.example.toml) into that
active file: `shared_fs=none`, guest image pull enabled, creation timeout 600.
Preserve the other settings, set the same private pause digest in CRI, and restart
containerd.

From the service host, read back and check each worker:

```bash
export WORKER_SSH=YOUR_EXISTING_WORKER_SSH_ALIAS
export CONTAINERD_CONFIG=/etc/containerd/config.toml
bash deployment/peerpods/check-worker.sh
```

This checks the merged configuration, active Kata settings and installed shim hash.
Propagate these settings through node-pool initialization. Keep confidential
scheduling stopped until every selected worker passes.

```bash
kubectl get runtimeclass kata-remote -o yaml
kubectl label runtimeclass kata-remote openshell.ai/sandbox-attachable=true --overwrite
```

The handler must be `kata-remote`, with overhead `cpu: 250m`, `memory: 120Mi`.

### Configure and install CSI

```bash
cp deployment/peerpods/csi-values.example.yaml "$OPERATOR_DIR/csi-values.yaml"
${EDITOR:-vi} "$OPERATOR_DIR/csi-values.yaml"
bash deployment/peerpods/install-csi.sh
```

Use the published CSI digest and separate RRSA role. Controller state needs a
durable PVC on the host ACK ESSD StorageClass, not the PeerPod class it provisions.
Keep one controller replica and `Recreate` strategy.

The script verifies chart provenance and waits for deployment/DaemonSet rollouts.
Confirm the controller-state PVC is Bound. Resources are in `caa-csi-block`;
the Helm release namespace is `confidential-containers-system`.
The PeerPod StorageClass uses `Delete` reclaim policy and disables expansion.
Stop/Start retains the original workspace PVC; final deletion removes its owned disk.

## 8. Install the native Gateway and confidential driver

Install the released Gateway/CLI, handoff driver and official Kata policy tools:

```bash
bash deployment/openshell/install-binaries.sh
bash deployment/openshell/create-identity.sh
```

The identity step creates native mTLS/JWT credentials with `HOST_IP` in the SAN.
An existing complete set is retained and checked. Operator client private keys
remain on this trusted host; guests receive the public CA and their own sealed
launch credentials.

Using the administrator `KUBECONFIG`, create the restricted Gateway credentials
and verify permissions:

```bash
bash deployment/openshell/install-kubeconfig.sh
```

The script applies RBAC, installs a private ServiceAccount kubeconfig, runs native
Gateway preflight and installs the namespace ingress default denial. Verify actual
network denial in step 10; NetworkPolicy objects alone do not prove enforcement.

Generate the driver image settings from step 6, review them, then start services:

```bash
bash deployment/openshell/configure-driver.sh
cat /etc/openshell-confidential/driver.env
bash deployment/openshell/start-services.sh
```

Expect the driver socket and Gateway `/readyz` to become available. The Gateway
uses native operator mTLS and sandbox-scoped JWTs; anonymous users are disabled.

Register the local CLI with its private operator identity:

```bash
install -d -m 0700 /var/lib/openshell-confidential/cli-config
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
openshell gateway add --name confidential-local --local "https://${HOST_IP}:9443"
export OPENSHELL_GATEWAY=confidential-local
openshell whoami --output json
```

## 9. Run the native coding agent and verify its lifecycle

Follow [first agent](first-agent.md), using the published agent image, a provider
and persistent workspace. It covers provider readiness, file upload/download,
model use, Stop/Start and Delete through the native CLI.

## 10. Verify both confidential roles

Before accepting a new image or deployment, verify these behaviors in the actual
environment:

| Check | Required result |
| --- | --- |
| Supervisor and workload attestation | Valid signed TDX appraisal against the selected image/platform references and current initdata |
| KBS release | Current role/attempt/CR UID bindings succeed; invalid image, quote, policy, descriptor or binding denies release |
| Access and network boundaries | Anonymous and cross-sandbox access fail; private guest mounts and network denial hold |
| Coding agent | Real model use, PTY and independent task-result checks succeed |
| Persistent Stop/Start | Same CR UID, ESSD, LUKS header UUID, workspace key and file bytes; new bootstrap attempts revoke old bindings |
| Encryption | Detached stopped workspace disk contains ciphertext; inspect using host cryptsetup/util-linux |
| Delete | Owned role VMs/disks and controller metadata disappear |

Keep sanitized hashes, owner IDs and observed decisions privately; do not commit
credentials or validation transcripts. The default policy accepts TCB `UpToDate`
and `OutOfDate` for development. Record the actual status and choose a production
TCB requirement separately. [Tests](../tests/README.md) describe automated coverage.
