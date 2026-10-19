# ACK inputs

Start with `configure-inputs.py` as shown in [deployment step 3](../../docs/deployment.md#3-prepare-cluster-select-the-cloud-image-and-configure-identities).
It discovers the **cloud-side ACK network** and writes `$OPERATOR_DIR/ack.json`.
Region comes from the approved handoff. It creates no cloud resources.
The user-trusted service host can remain outside the cloud; it needs outbound
ACK access and reachable inbound TLS endpoints for the cloud guests. See the
[trust boundary](../../docs/architecture.md).

The optional `--service-host-instance-id` shortcut is only for ECS-based functional
development. It discovers that ECS's vSwitch/security group; it is not a
requirement for deploying the trusted services.

## What each field means

| Field | Meaning and source | If it does not exist yet |
| --- | --- | --- |
| `name` | Deployment/resource-name prefix. The initializer generates a unique name; `--name` chooses one explicitly. | Generated locally. |
| `cluster_id` | Existing ACK ID, selected from the listing below with `--cluster-id`. Empty means a new cluster. | `prepare-cluster.py --create` creates ACK. |
| `service_host_instance_id`, `service_host_ip` | Optional development ECS ID, and the advertised trusted service IPv4 from `HOST_IP`. The service address may be outside the cloud. | Leave the ECS ID empty for a user-hosted T. Configure a reachable public/VPN ingress for T. |
| `service_host_security_group_id` | Optional ingress security group, discovered only for the explicit ECS development shortcut. | Empty for user-hosted T; configure ingress/firewall in the user network. |
| `worker_vswitch_id` | Cloud worker network. Discovered from existing ACK, or selected with `--worker-vswitch-id` for new ACK. | Create a cloud VPC/vSwitch using the commands below. T does not need to join this VPC. |
| `ack_api_access` | ACK API connection: `public` by default; `private` requires VPN/VPC routing. Set with `--ack-api-access`. | New ACK configures its public endpoint accordingly. For existing ACK, enable public API access in ACK console when selecting public mode. |
| `oss_endpoint_network` | OSS transport: `public` HTTPS by default; `internal` requires same-region OSS private connectivity. | Set with `--oss-endpoint-network`. |
| `worker_ssh_source_cidr` | Optional operator network permitted to SSH to workers, for example the operator NAT egress IPv4 `/32`. The ECS development shortcut fills its private `/32`. | Empty adds no SSH ingress; configure access through the operator's chosen route. |
| `pod_vswitch_id`, `pod_vswitch_cidr` | New ACK's Kubernetes Pod network. Initializer chooses a free `/24` in the VPC; ID remains empty until creation. Existing ACK keeps its network. | Cluster preparation creates the vSwitch. `--pod-vswitch-id` reuses an existing one. |
| `podvm_vswitch_id`, `podvm_vswitch_cidr` | Dedicated network for the confidential VMs. Initializer chooses another free `/24`; this is separate from Kubernetes Pods. | Network preparation creates the vSwitch and dedicated PodVM security group. `--podvm-vswitch-id` reuses an existing dedicated vSwitch. |
| `oss_bucket` | **Bucket name**, not a URL, path or region. Stores the QCOW2 for ECS import. Initializer generates a name from the account ID and random suffix; `--oss-bucket` selects an existing name. | Storage preparation creates a private bucket in the selected region. Unused with an approved ImageID. |
| `podvm_instance_type` | ECS type for TDX guests. Default `ecs.g9i.xlarge`; confirm availability in the chosen zone below. | Choose an available TDX type; creating an instance type is not an operator task. |
| `kubernetes_version`, `containerd_version` | New ACK versions, checked against ACK metadata. Existing workers are checked, not upgraded. | Cluster preparation installs the selected versions. |
| `worker_image_id` | Optional new worker OS ImageID. Empty selects ACK's Ubuntu 24.04 amd64 image automatically. This is **not** the PodVM ImageID. | Selected from ACK metadata; no worker image build/import is needed. |
| `worker_instance_type`, `worker_count` | New ACK worker type/count. Default: one `ecs.g9i.xlarge` worker. Existing cluster ignores these fields. | Cluster preparation creates pay-as-you-go workers. |
| `service_cidr` | Kubernetes Service address range for new ACK. Initializer selects a range outside the VPC; review against any connected networks. | ACK uses this range during creation. |
| `csi_storage_class` | Host ACK ESSD StorageClass for CSI controller state; default `alicloud-disk-essd`. It is separate from encrypted guest workspace storage. | New ACK installs the standard CSI add-ons. For an existing ACK, enable `csi-plugin` and `csi-provisioner` in ACK console → Add-ons → Storage if absent. |

Discovery checks existing vSwitch CIDRs, not future allocations or connected-VPC
routes. Review the proposed networks before starting setup. Dedicated vSwitches
must be in the selected VPC and worker zone. This reference profile uses one
worker zone.

## Cloud network selection

Run cloud queries from T after `aliyun configure`; append `--profile NAME` for a
named profile. The cloud resources below belong to U and do not locate T.

```bash
export REGION=$(jq -er .podvm_region "$HANDOFF/selection.json")
aliyun cs DescribeClustersV1 --region "$REGION" --region_id "$REGION" --page_size 100 \
  | jq -r '.clusters[] | [.cluster_id, .name, .vpc_id, .state] | @tsv'
aliyun vpc DescribeVSwitches --region "$REGION" --RegionId "$REGION" --PageSize 50 \
  | jq -r '.VSwitches.VSwitch[] | [.VSwitchId, .VSwitchName, .VpcId, .ZoneId, .CidrBlock] | @tsv'
```

If a suitable cloud network exists, pass its worker vSwitch ID to the initializer.
List APIs are paginated; use later pages when needed. The initializer paginates
vSwitches itself before allocating the new Pod/PodVM CIDRs.

If no network exists, select a zone that offers the desired TDX instance type:

```bash
aliyun ecs DescribeAvailableResource --region "$REGION" --RegionId "$REGION" \
  --DestinationResource InstanceType --InstanceChargeType PostPaid --InstanceType ecs.g9i.xlarge
read -r -p 'ZoneId with available TDX capacity from the result: ' ZONE_ID
install -d -m 0700 "$OPERATOR_DIR"
NETWORK_NAME="cos-$(date -u +%Y%m%d%H%M%S)"
aliyun vpc CreateVpc --region "$REGION" --RegionId "$REGION" \
  --VpcName "$NETWORK_NAME" --CidrBlock 192.168.0.0/16 > "$OPERATOR_DIR/cloud-vpc.json"
VPC_ID=$(jq -er .VpcId "$OPERATOR_DIR/cloud-vpc.json")
aliyun vpc DescribeVpcAttribute --region "$REGION" --RegionId "$REGION" --VpcId "$VPC_ID"
```

Wait until the returned VPC `Status` is `Available`, then create its worker vSwitch:

```bash
aliyun vpc CreateVSwitch --region "$REGION" --RegionId "$REGION" --VpcId "$VPC_ID" \
  --ZoneId "$ZONE_ID" --CidrBlock 192.168.16.0/20 --VSwitchName "$NETWORK_NAME-worker" \
  > "$OPERATOR_DIR/cloud-worker-vswitch.json"
WORKER_VSWITCH_ID=$(jq -er .VSwitchId "$OPERATOR_DIR/cloud-worker-vswitch.json")
python3 deployment/ack/configure-inputs.py --worker-vswitch-id "$WORKER_VSWITCH_ID"
```

These address ranges are an example for a **new** cloud VPC. Choose ranges that do
not overlap connected networks. Retain the two JSON outputs for cleanup. Workers
and PodVMs need egress to the trusted service endpoints; arrange NAT/SNAT or routed
connectivity for the selected cloud subnets.

Other resource queries:

```bash
aliyun oss ls -e "https://oss-${REGION}.aliyuncs.com"
# After obtaining kubeconfig, inspect the host ACK disk classes:
kubectl get storageclass
```

For existing ACK, select the host ESSD class from **ACK console → cluster →
Storage → StorageClasses** before starting setup. Optional ECS development IDs
come from **ECS console → Instances**; the shortcut prints attached security-group
IDs when an explicit selection is needed.

## Storage and image-import authorization

`prepare-storage.py` creates the generated bucket with private ACL, or checks an
existing bucket's owner, region and ACL. The upload uses HTTPS over the selected
public or internal OSS endpoint. The bucket stores the image file; it does not store live
workspaces. OSS storage and image-import snapshots incur the cloud's normal fees.

For a first import, `prepare-storage.py --authorize-image-import` creates
`AliyunECSImageImportDefaultRole` with ECS service trust and attaches the official
`AliyunECSImageImportRolePolicy` system policy. It does not replace an existing
trust policy. The console alternative is **ECS → Images → Import Image → Authorize**.
This follows the [official ImportImage authorization procedure](https://help.aliyun.com/en/ecs/developer-reference/api-ecs-2014-05-26-importimage).
For an approved existing ImageID, neither bucket nor import authorization is needed.

## Saved configuration and runtime identities

Complete the private inputs before starting cloud setup. The initializer's
`--replace` option can regenerate inputs only before `ack-state.json` exists.
Keep configuration/state together on retries. Use another name and operator
directory for another deployment. Resource IDs and created identities remain in
`ack-state.json`; resources persist until the operator deletes them. Disable ACK
deletion protection before deleting a newly created cluster. An existing shared
image-import role or reused bucket is not a deployment-owned disposable resource.

The [RAM templates](ram/) are for runtime CAA/controller and CSI identities,
separate from the operator credentials and ECS import role. They restrict OIDC
trust to their ServiceAccounts and use cluster ownership tags. Helm values reuse
the same identities/tags. Existing clusters need Ready Linux/amd64 workers,
containerd, `supplementalGroupsPolicy`, and Terway shared ENI with NetworkPolicy.
Actual network denial is verified in deployment step 10.
