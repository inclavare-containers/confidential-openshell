# Deploy

This guide installs native OpenShell 0.1.3 with the Ubuntu UKI / CoCo 0.22 profile
on Alibaba Cloud ACK and Intel TDX. Start with a fresh development environment.
For an already installed Gateway, use [first agent](first-agent.md).
Developers connect to the trusted Gateway over public TLS using the native
OpenShell CLI.

You need:

- A user-trusted Ubuntu service host for Gateway, driver, Trustee and the registry.
  It can be on-premise and can also be the build machine. Its placement is
  independent of the ACK network; see the [trust boundary](architecture.md).
- A new or existing ACK cluster, prepared in step 3. Existing clusters need RRSA,
  enforced NetworkPolicy and accessible workers.
- A compatible TDX PodVM image and its approved reference file.
- Administrator access to ACK, ECS, VPC, RAM and the image registry.

Run the numbered steps in order. Commands run as root on the trusted service
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

Set the trusted service address reachable from the cloud:

```bash
cd /opt/confidential-openshell
export HANDOFF=/var/lib/openshell-confidential/operator/handoff
export OPERATOR_DIR=/var/lib/openshell-confidential/operator/cluster-config
read -r -p 'Trusted service IPv4 reachable from cloud workers/guests: ' HOST_IP
export HOST_IP
```

`HOST_IP` is the address advertised to the cloud for Gateway 9443, KBS 8443 and
registry 5000, and included in TLS certificates. It is the only service-address
input. Services listen on `0.0.0.0` locally, so a public address mapped through NAT
does not need to appear on the host's network interfaces.

A machine with outbound NAT alone cannot receive these connections. Provision a
reachable ingress, VPN, or TCP forwarding route first; obtain its assigned IPv4
from that network's configuration. Forward the three TCP ports to the trusted host
and retain TLS termination/private keys on T. A public NAT **egress** IP alone is
not evidence that inbound connectivity exists. Permit only approved clients.
The [architecture](architecture.md) defines T independently of network placement.

## 3. Prepare cluster, select the cloud image and configure identities

### Install cloud tools and configure operator access

```bash
bash deployment/ack/install-tools.sh
aliyun configure
export REGION=$(jq -er .podvm_region "$HANDOFF/selection.json")
aliyun sts GetCallerIdentity --region "$REGION"
```

Obtain the operator identity from your Alibaba account administrator or
[RAM console](https://ram.console.aliyun.com/). This identity needs ECS, VPC, ACK,
RAM and OSS administration. Set `ALIBABA_CLOUD_PROFILE` to choose a named CLI
profile, and use the same profile for manual queries. Credentials stay in T.

### Choose an existing cluster, or prepare a new one

For an existing ACK, list clusters and use its ID:

```bash
aliyun cs DescribeClustersV1 --region "$REGION" --region_id "$REGION" \
  --page_size 100 --profile "${ALIBABA_CLOUD_PROFILE:-default}" \
  | jq -r '.clusters[] | [.cluster_id, .name, .vpc_id, .state] | @tsv'
python3 deployment/ack/configure-inputs.py --cluster-id ID_FROM_THE_LIST
```

For a new ACK, list **cloud-side** worker vSwitches, then select one:

```bash
aliyun vpc DescribeVSwitches --region "$REGION" --RegionId "$REGION" --PageSize 50 \
  | jq -r '.VSwitches.VSwitch[] | [.VSwitchId, .VSwitchName, .VpcId, .ZoneId, .CidrBlock] | @tsv'
python3 deployment/ack/configure-inputs.py --worker-vswitch-id ID_FROM_THE_LIST
```

If no suitable cloud network exists, the [network preparation commands](../deployment/ack/README.md#cloud-network-selection)
create a VPC and worker vSwitch before this step. The trusted service host is not
required to belong to that VPC. Only workers, Kubernetes Pods and PodVMs use the
selected cloud network.

The initializer writes `$OPERATOR_DIR/ack.json` and creates no cloud resources.
It discovers the ACK VPC/zone, proposes unused Pod/PodVM CIDRs and generates a
bucket name for import. The later steps create those resources. Review the file:

```bash
cat "$OPERATOR_DIR/ack.json"
${EDITOR:-vi} "$OPERATOR_DIR/ack.json"
```

The default `ack_api_access=public` obtains a public API kubeconfig; an existing
ACK must already have its public API enabled. For VPN/private routing, choose
`--ack-api-access private` instead. The default OSS endpoint is public HTTPS;
`--oss-endpoint-network internal` requires same-region OSS internal connectivity.
To reuse a private bucket, add `--oss-bucket NAME_FROM_OSS`.

The [input reference](../deployment/ack/README.md) explains every field and its
source. `--replace` regenerates an input file only before cloud setup starts.

### Prepare the selected ACK cluster

For an existing cluster:

```bash
python3 deployment/ack/prepare-cluster.py
export KUBECONFIG="$OPERATOR_DIR/administrator-kubeconfig"
```

This obtains an administrator kubeconfig for the selected API path and checks Ready Linux/amd64
workers, containerd, `supplementalGroupsPolicy` and Terway NetworkPolicy settings.
If RRSA is disabled, repeat with `--enable-rrsa` to explicitly enable it.

For a new cluster:

```bash
python3 deployment/ack/prepare-cluster.py --create
export KUBECONFIG="$OPERATOR_DIR/administrator-kubeconfig"
```

This creates a **paid ACK Pro cluster and pay-as-you-go workers**, using the
reviewed inputs. It configures API public access according to `ack_api_access`, Terway shared ENI,
NetworkPolicy and RRSA; selects ACK's Ubuntu 24.04 worker image; generates an SSH
key under `$OPERATOR_DIR/worker-key`; and waits for workers before checking them.
Cluster creation enables deletion protection. The default is one worker.

Both paths save resources in `$OPERATOR_DIR/ack-state.json`. Keep this state when
retrying. The kubeconfig lasts up to three days; repeat the cluster step
to renew it. Use a separate operator directory/name for a different deployment.
If a Kubernetes API request fails, the script prints the error and exits. Fix
connectivity or credentials, then repeat the same command to resume.

### Prepare the PodVM network

```bash
python3 deployment/ack/prepare-network.py
```

Creates or selects the dedicated PodVM vSwitch in the worker VPC/zone and creates
a dedicated security group. It permits worker–PodVM tunnel traffic between their
security groups. The cloud needs outbound routes to T's three TLS endpoints;
configure SNAT for the worker/PodVM networks if required.

Configure the trusted host's firewall/ingress in its own network, permitting the
intended clients on ports 5000/8443/9443. Arrange worker SSH access through your
chosen operator route; in ACK console, select the worker security group and allow
TCP 22 from that route's source address when needed. Cluster preparation manages
only the selected ACK and its cloud resources.

### Prepare image-import storage

```bash
python3 deployment/ack/prepare-storage.py
```

For QCOW2 import this creates the named bucket if missing, with a **private ACL**
in the selected region, or verifies an existing bucket's owner, location and ACL.
It uses the selected public or internal OSS HTTPS endpoint. The bucket holds the QCOW2
until ECS has imported it; it is not the encrypted workspace disk.

The first image import in an account also needs ECS's standard import role. If
the script reports missing authorization, explicitly create/authorize it:

```bash
python3 deployment/ack/prepare-storage.py --authorize-image-import
```

This uses the official `AliyunECSImageImportDefaultRole` and system policy
`AliyunECSImageImportRolePolicy`. Alternatively, open **ECS console → Images →
Import Image → Authorize**, then repeat the storage step. A read-only readiness
check is available with `--check`. For an approved existing ImageID, the script
skips bucket creation and import authorization.

### Confirm or import the PodVM image

```bash
python3 deployment/ack/prepare-image.py
```

Verifies the handoff checksums. For a selected ImageID it checks the ECS image; for
a new QCOW2 it uploads a private OSS object, imports the image and waits until it
is Available. Both paths require Linux/x86_64, UEFI and NVMe support. Import uses
Ubuntu/Linux and a 20 GiB system disk; PeerPods later requests 40 GiB. CAA enables
TDX when creating the VM.

Outputs: `podvm-image-id.txt` and `podvm-image.json` in `$OPERATOR_DIR`. The latter
binds region and ImageID to the approved handoff and reference checksums. Existing
image/reference provenance still needs approval in step 2; ECS metadata cannot
prove that binding. A cross-region image copy needs its destination ImageID.

### Configure RAM roles

```bash
python3 deployment/ack/configure-identities.py
```

Renders the maintained [RAM templates](../deployment/ack/ram/) with the discovered
account, OIDC identity, cluster and vSwitch. Creates separate CAA/controller and CSI
roles, attaches their scoped permissions, and records the role ARNs. It reuses an
existing role only when ownership and policies match. No access keys are passed
to Kubernetes. Step 7 generates Helm values from these saved results.

## 4. Install Trustee and register the approved image references

### Create the initial certificates

```bash
bash deployment/trustee/create-certificates.sh
```

Creates the CA, HTTPS server certificate and separate AS token signer
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

Installs the public CA in the host trust store, starts the pinned registry listening on
`0.0.0.0:5000`, advertised as `HOST_IP:5000`, and checks HTTPS `/v2/`. Its durable data is under
`/var/lib/openshell-confidential/registry`.

### Configure each worker to trust the registry

Copy and edit the [registry hosts template](../deployment/peerpods/registry-hosts.example.toml)
with `HOST_IP:5000`. Transfer that file and `/etc/trustee/tls/ca.pem` to each worker.
Install them as:

| Worker path | File |
| --- | --- |
| `/etc/containerd/certs.d/HOST_IP:5000/hosts.toml` | Edited registry hosts template |
| `/etc/containerd/certs.d/HOST_IP:5000/ca.crt` | Trustee public CA |

Keep `/etc/containerd/certs.d` in containerd's effective CRI registry `config_path`.
ACK can already include it alongside `/etc/containerd/cert.d`; preserve that list.
Only the public CA goes to workers.

### Publish the images

```bash
bash deployment/peerpods/publish-images.sh
bash deployment/build/package-kata-shim.sh
```

The first command loads the authenticated handoff archives and mirrors the pinned
runtime and cluster dependency images. Workers pull these from the private
registry, so only this host needs access to upstream registries.
The second adds the host-shim replacement to kata-deploy.
Both write destination digest references to `$OPERATOR_DIR/*-image.txt`.
Use those exact references in the next step. No insecure registry flags are needed.

## 7. Install Kata, PeerPods and CSI, then verify workers

### Install cluster dependencies

```bash
bash deployment/peerpods/fetch-prerequisites.sh
```

This prepares the Agent Sandbox manifest and cert-manager values using the
published image records. Install them:

```bash
kubectl apply --server-side -f "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller --timeout=10m
helm upgrade --install cert-manager "$OPERATOR_DIR/cert_manager_chart" \
  --namespace cert-manager --create-namespace \
  --values "$OPERATOR_DIR/cert-manager-values.json" --wait --timeout=15m
```

A compatible existing cert-manager installation can be used instead.

### Configure and install PeerPods

```bash
python3 deployment/peerpods/configure-values.py
cat "$OPERATOR_DIR/peerpods-values.yaml"
cat "$OPERATOR_DIR/csi-values.yaml"
```

This fills in the saved cloud identities and network settings, selected PodVM
ImageID, published image digests and base initdata. It generates both PeerPods and
CSI values. Review the files before installing; edit private copies if needed.
The script refuses existing values unless `--replace` is explicitly given.

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

Follow [first agent](first-agent.md). The driver defaults to the mirrored
OpenShell Community image, so users can start OpenCode, Codex or Claude Code
without building an image or passing `--from`. Configure the matching provider
and verify creation, interactive reconnect, model use and persistent Stop/Start
through the native CLI.

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
