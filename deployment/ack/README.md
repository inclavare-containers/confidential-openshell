# ACK inputs

Start with `configure-inputs.py` as shown in [deployment step 3](../../docs/deployment.md#3-prepare-cluster-select-the-cloud-image-and-configure-identities).
It queries the service ECS and writes a private `$OPERATOR_DIR/ack.json`. Region
comes from the approved handoff. It creates no cloud resources.

The service ECS must already exist: it is the Ubuntu host used in steps 1–2.
Its existing VPC/vSwitch/security group are discovered. A pre-created ACK cluster,
PodVM network, OSS bucket and image-import role are **not** prerequisites.

## What each field means

| Field | Meaning and source | If it does not exist yet |
| --- | --- | --- |
| `name` | Deployment/resource-name prefix. The initializer generates a unique name; `--name` chooses one explicitly. | Generated locally. |
| `cluster_id` | Existing ACK ID, selected from the listing below with `--cluster-id`. Empty means a new cluster. | `prepare-cluster.py --create` creates ACK. |
| `service_host_instance_id`, `service_host_ip` | The existing Ubuntu service ECS and its private IPv4, discovered using `HOST_IP`. `--service-host-instance-id` selects it explicitly. | Provision the service ECS before following this guide. |
| `service_host_security_group_id` | A security group **attached to the service ECS**; later receives private registry/KBS/Gateway ingress rules. It is not the worker or PodVM security group. | An ECS already has at least one security group. The initializer selects it; with several groups, choose an attached ID using `--service-host-security-group-id`. |
| `worker_vswitch_id` | Existing vSwitch where new workers will run. Defaults to the service ECS vSwitch, or the selected ACK's worker vSwitch. Override with `--worker-vswitch-id`. | The service ECS already has a vSwitch. To choose another, list vSwitches in its VPC below. |
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

## Query existing resources

Run on the service host after `aliyun configure`. Commands below use the active
CLI profile; append `--profile NAME` if using a named profile.

```bash
export REGION=$(jq -er .podvm_region "$HANDOFF/selection.json")
# Find the service ECS from its private IPv4; output includes its attached groups.
aliyun ecs DescribeInstances --region "$REGION" --RegionId "$REGION" \
  --InstanceNetworkType vpc \
  --PrivateIpAddresses "$(jq -cn --arg ip "$HOST_IP" '[$ip]')" \
  > "$OPERATOR_DIR/service-ecs.json"
jq '.Instances.Instance[] | {InstanceId, InstanceName, VpcAttributes, SecurityGroupIds}' \
  "$OPERATOR_DIR/service-ecs.json"
export VPC_ID=$(jq -er '.Instances.Instance[0].VpcAttributes.VpcId' "$OPERATOR_DIR/service-ecs.json")
export ZONE_ID=$(jq -er '.Instances.Instance[0].ZoneId' "$OPERATOR_DIR/service-ecs.json")

# Existing security group IDs/names and vSwitch IDs/CIDRs in this VPC.
aliyun ecs DescribeSecurityGroups --region "$REGION" --RegionId "$REGION" --VpcId "$VPC_ID"
aliyun vpc DescribeVSwitches --region "$REGION" --RegionId "$REGION" --VpcId "$VPC_ID" --PageSize 50

# Existing ACK IDs/names. Pick an entry in the service ECS VPC.
aliyun cs DescribeClustersV1 --region "$REGION" --region_id "$REGION" --page_size 100 \
  | jq -r '.clusters[] | [.cluster_id, .name, .vpc_id, .state] | @tsv'

# Existing OSS bucket names. No result is required for the default create path.
aliyun oss ls -e "https://oss-${REGION}-internal.aliyuncs.com"

# Capacity for the default TDX type in the worker/PodVM zone.
aliyun ecs DescribeAvailableResource --region "$REGION" --RegionId "$REGION" \
  --ZoneId "$ZONE_ID" --DestinationResource InstanceType \
  --InstanceChargeType PostPaid --InstanceType ecs.g9i.xlarge
```

These are paginated list APIs: use later `--page_number`/`--PageNumber` pages when
needed. The initializer paginates the vSwitch query itself before selecting CIDRs.
For existing ACK, choose the host ESSD class in **ACK console → cluster →
Storage → StorageClasses** before starting setup and set `csi_storage_class`.
After obtaining kubeconfig, `kubectl get storageclass` confirms that choice.
When using a different worker vSwitch, use its zone in the capacity query.

## Storage and image-import authorization

`prepare-storage.py` creates the generated bucket with private ACL, or checks an
existing bucket's owner, region and ACL. The upload uses HTTPS over the same-region
OSS internal endpoint. The bucket stores the image file; it does not store live
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
