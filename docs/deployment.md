# Deploy

Deploy native OpenShell 0.1.3 with CoCo 0.22, Trustee, ACK and Intel TDX.
Complete [build](build.md), including release installation, first. Run the commands
below as root from `/opt/confidential-openshell` on the **trusted service host**.
It hosts Gateway, driver, Trustee and the private registry. It may be your build
machine, an on-premise host or a cloud VM; ACK does not determine its location.

Each `./cos` command runs one step and prints its purpose, progress,
`OK`/`FAILED`, elapsed time, log path and next command. A failure stops the step.
Use `./cos --help` to list commands and `./cos status` to inspect saved resources
and previous command results.

## 1. Build and install the release

Complete [the build guide](build.md#build-and-transfer). Keep the Git checkout for
future builds; use the installed source for deployment.

## 2. Configure the trusted service host

```bash
./cos host cloud-tools
```

Installs the pinned Alibaba Cloud CLI. Then configure the deployment:

```bash
./cos deploy configure
```

Asks for the trusted host's **IPv4 reachable from the cloud**, checks the Alibaba
CLI identity and saves the configuration. If credentials are needed, it opens the
normal CLI credential setup. Existing valid profiles are reused.
The region comes from your guest selection. The operator needs administration of
ACK, ECS, VPC, RAM and OSS, including ECS Cloud Assistant commands on workers.
Credentials remain on the trusted host. Use `--profile` followed by a CLI profile
name when needed.

Later steps automatically load the service address, profile, handoff and
administrator kubeconfig, including in a new shell. State and private logs stay
under `/var/lib/openshell-confidential/operator/cluster-config`.

The service address needs inbound TLS on TCP **5000** (registry), **8443** (KBS)
and **9443** (Gateway). Configure ingress/firewall in the trusted host's own
network; keep TLS termination and keys on this host. Outbound NAT alone does not
provide inbound access. Cloud network preparation prints the egress IPs to permit.
Gateway clients also need access to 9443.

## 3. Create a new ACK cluster

Use this path for a new deployment. No existing VPC, vSwitch, security group or
OSS bucket is required.

```bash
./cos cluster create
```

Creates a **paid ACK Pro cluster and pay-as-you-go worker**. It checks ECS inventory
within the documented TDX zones, creates a dedicated VPC and worker/Pod vSwitches, and configures
public API access, Terway NetworkPolicy, RRSA, storage add-ons, worker egress and
Ubuntu 24.04/containerd. The default is one worker.

Success prints cluster/VPC/vSwitch/security-group IDs and Ready nodes. These IDs
are saved automatically; rerunning resumes the same deployment.

The default VPC CIDR is `10.64.0.0/16`. Pass a different private CIDR with
`--vpc-cidr` if planned network connections would overlap. Optional `--zone`
chooses a supported zone with available inventory; `--name` chooses a resource-name prefix.
The default Beijing `ecs.g9i.xlarge` profile uses **Zone I**; ordinary ECS availability
in other zones does not imply TDX support.
`--private-api` requires routed private access from this host to ACK.

Continue with [step 4](#4-prepare-cloud-resources).

## Use an existing ACK cluster instead

Skip step 3. This command lists existing clusters and asks which to use:

```bash
./cos cluster attach
```

Obtains an administrator kubeconfig and checks the region, API access, RRSA,
Ready Linux/amd64 containerd workers, `supplementalGroupsPolicy` and Terway
NetworkPolicy. It retains the existing cluster, VPC, node pools and worker OS.
Missing prerequisites fail with an explanation; it does not upgrade the cluster
or silently enable its features.

The supported profile uses one worker zone, Ubuntu 24.04 workers with ECS Cloud
Assistant running, and host StorageClass `alicloud-disk-essd` from ACK's CSI
add-ons. Public API access must already be enabled unless you pass `--private-api`
and have private routing. `--cluster-id` can provide an ID directly.

Continue with step 4. The common steps add deployment-specific PodVM resources,
identities and workloads while retaining the existing cluster network.

## 4. Prepare cloud resources

### PodVM network

```bash
./cos cloud network
```

Creates a dedicated PodVM vSwitch/security group in ACK's VPC/worker zone, permits
worker–PodVM tunnel traffic and inherits worker NAT/SNAT for guest egress.
Success prints the vSwitch, security group and public egress IPs. Permit these
cloud clients on the trusted host's ports from step 2. An existing cluster with
routed egress can retain its route instead of SNAT.

### Guest image

```bash
./cos cloud image
```

For a built guest, creates a private OSS import bucket, ensures ECS's standard
import role, uploads the QCOW2 and waits for the image to become Available.
A selected existing ImageID is checked directly, skipping bucket/import work.
Success prints the ImageID and saves its binding to the release references.
Both paths require Linux/x86_64, UEFI and NVMe support. The step also runs an ECS
TDX launch **DryRun** with the selected image, instance type and PodVM network.
It creates no VM and reports cloud-side launch errors before component installation.

### Runtime identities

```bash
./cos cloud identities
```

Creates separate scoped CAA/controller and CSI RAM roles using RRSA, prints their
ARNs and saves them for Helm values. Kubernetes receives no operator access keys.
Generated names and IDs are passed between steps automatically.

## 5. Select deployment workers

```bash
./cos workers select
```

Selects the new cluster's workers automatically. A single eligible worker is also
selected automatically. With multiple workers in an existing cluster, lists their
names and asks which numbered entries to use. It labels and saves the selection.
Later operations use ECS Cloud Assistant; no node-name placeholders, public worker
IPs or SSH aliases are required.

## 6. Install and start Trustee

### Certificates

```bash
./cos trustee certificates
```

Creates the Trustee CA, HTTPS certificate with the saved service address, and AS
signer. Success verifies the certificates and address. An existing complete
certificate set is verified and retained. An incomplete set
stops with an explanation; its CA is never regenerated automatically.

### Containers and configuration

```bash
./cos trustee install
```

Pulls the official pinned AS/KBS container images and installs configuration and
systemd units. Docker runs the containers; systemd manages their lifecycle.
Empty bindings deny resource release. Existing authorization state is not reset.

### Start and check

```bash
./cos trustee start
```

Starts AS, registers and reads back the selected image and bundled ECS platform
references, then starts KBS. Requires active services and anonymous HTTPS resource
access to return 401 or 403. This proves readiness and denial; real TDX appraisal
is checked in step 10.

## 7. Prepare bootstrap and publish images

### Base initdata

```bash
./cos deploy initdata
```

Writes the public deny-only base initdata from the saved address and CA.
The driver later creates the actual per-role, per-attempt bindings.

### Registry and images

```bash
./cos registry start
```

Starts the TLS registry and checks HTTPS. Durable registry storage is under
`/var/lib/openshell-confidential/registry`.

```bash
./cos registry publish
```

Publishes built images, mirrors all pinned upstream dependencies and the unchanged
Community harness image, then publishes kata-deploy with the verified host shim.
Success requires both stages and saves destination digests. Either stage failing
stops this command.

### Worker trust

```bash
./cos workers registry
```

Installs the public CA and `hosts.toml` on selected workers through ECS Cloud
Assistant, then performs a real CRI pull on every worker. Retains TLS verification
and containerd's registry search paths. Also verifies worker-to-KBS HTTPS access
and anonymous denial. Repeat after selecting additional workers.

## 8. Install cluster components

### Dependencies

```bash
./cos cluster dependencies
```

Generates pinned manifests, installs Agent Sandbox and cert-manager and waits for
readiness. Prints Pods/events and exits if the Agent Sandbox controller fails.

### Configuration

```bash
./cos cluster values
```

Generates private PeerPods/CSI values from saved IDs, identities, digests and
initdata, then prints their paths. Existing values are retained; `--replace`
intentionally regenerates them after reviewing changed inputs.

### Kata and PeerPods

```bash
./cos cluster peerpods
```

Installs the verified charts, applies controller RRSA and waits for worker
DaemonSets and controller/webhook deployments.

```bash
./cos workers configure
```

Finds the active Kata profile, merges required guest-pull, shared-filesystem and
timeout settings, sets the private pause image and verifies the installed shim.
Preserves unrelated settings and backs up changed files. Restarts containerd when
needed, waits for the node and verifies a CRI pull. Marks `kata-remote` attachable.
Repeat after kata-deploy upgrades or selecting new workers.

### Workspace CSI

```bash
./cos cluster csi
```

Installs the release chart and checks rollouts and a Bound controller-state PVC.
Controller state uses host ACK ESSD storage; guest workspaces use the separate
PeerPod class. Stop/Start retains a workspace; final deletion removes its owned disk.

## 9. Install and connect to OpenShell

```bash
./cos gateway install
```

Installs the native Gateway/CLI, driver and Kata policy tools, creates/checks
TLS/JWT identities, configures the driver and installs restricted Kubernetes
credentials. Success includes RBAC preflight. Operator client keys remain on T.

```bash
./cos gateway start
```

Requires the driver socket, Gateway readiness endpoint and worker-to-Gateway TCP
reachability. Anonymous access stays disabled; native TLS/operator identity is
checked by the following login step.

```bash
./cos gateway login
```

Registers the native operator CLI and checks `whoami`. Continue with
[coding harnesses](first-agent.md) for providers and native
`openshell sandbox create/connect/stop/start/delete` commands.
OpenCode, Codex and Claude Code use the default Community image.

## 10. Verify both confidential roles

Installation/readiness checks do not prove real attestation or all security
boundaries. Before accepting a new image or deployment, check:

| Check | Required result |
| --- | --- |
| Supervisor/workload attestation | Signed TDX appraisal matches selected image/platform references and current initdata |
| KBS release | Current role/attempt/CR UID succeeds; invalid image, quote, policy or binding denies release |
| Access/network boundaries | Anonymous/cross-sandbox access fails; private mounts and network denial hold |
| Coding agent | Real model use, PTY reconnect and independently checked task results |
| Stop/Start | Same CR UID, ESSD, LUKS UUID, key and files; new attempts revoke old bindings |
| Encryption | Stopped detached workspace disk contains ciphertext |
| Delete | Owned role VMs/disks and controller metadata disappear |

Keep private evidence outside source/releases. The development policy accepts TCB
`UpToDate` and `OutOfDate`; record the actual status and choose production
requirements separately. See [tests](../tests/README.md) and
[architecture](architecture.md).
