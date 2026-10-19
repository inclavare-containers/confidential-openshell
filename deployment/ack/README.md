# ACK inputs

Copy `ack.example.json` to `$OPERATOR_DIR/ack.json` and edit that private copy.
Run the separate scripts in [deployment step 3](../../docs/deployment.md#3-prepare-cluster-select-the-cloud-image-and-configure-identities).
They use the official Alibaba Cloud CLI and save resource IDs under `OPERATOR_DIR`.

| Input | Existing ACK | New ACK |
| --- | --- | --- |
| `name` | Unique deployment name; also prefixes RAM roles and owned resources | Same |
| `cluster_id` | Required | Leave empty; run `prepare-cluster.py --create` |
| `worker_vswitch_id` | Unused | Existing worker vSwitch; its VPC and zone are discovered |
| `pod_vswitch_id` / `pod_vswitch_cidr` | Existing cluster networking is retained | Supply an existing Pod vSwitch or an unused CIDR to create one |
| `podvm_vswitch_id` / `podvm_vswitch_cidr` | Supply an existing dedicated PodVM vSwitch or an unused CIDR to create one | Same |
| `service_host_security_group_id` | Security group on the trusted service host in the same VPC | Same |
| `podvm_instance_type` | TDX type available in the PodVM zone, for example `ecs.g9i.xlarge` | Same |
| `kubernetes_version`, `containerd_version` | Existing workers are checked, not upgraded | Versions must be offered together by ACK |
| `worker_image_id` | Unused | Empty selects ACK's Ubuntu 24.04 amd64 image; optionally pin an ImageID |
| `worker_instance_type`, `worker_count`, `service_cidr` | Unused | Review before creating paid resources |
| `oss_bucket` | Private bucket in the selected region for QCOW2 import; unused for an approved ImageID | Same |
| `csi_storage_class` | Existing host ACK ESSD StorageClass for CSI controller state | Same |

The reference profile uses one worker zone. Existing clusters need Ready Linux
amd64 workers, containerd, `supplementalGroupsPolicy`, and Terway shared ENI with
NetworkPolicy enabled. `prepare-cluster.py --enable-rrsa` can enable RRSA on an
existing cluster; it does not replace its network plugin or upgrade workers.
Network configuration checks do not replace the actual deny tests in step 10.

For new clusters, the script imports the generated `worker-key.pub` as an ECS key
pair. Use its matching private key only on this service host when accessing workers.
The cluster's API endpoint is private, so this host needs VPC access to it.

The image import requires ECS's standard `AliyunECSImageImportDefaultRole` and
OSS access. If import reports the service role is missing, authorize ECS image
import for the account using the [official import guide](https://www.alibabacloud.com/help/en/ecs/user-guide/import-a-custom-image),
then repeat the image step. The OSS object is private and retained for import;
its URI, imported image, cluster, node pool, network and RAM identities are recorded
in `ack-state.json`. Resources persist until the operator deletes them. Disable
ACK deletion protection before deleting a newly created cluster.

Keep `ack.json`, `ack-state.json`, kubeconfig and keys outside the checkout.
Repeat an interrupted step with the same settings and state; creating another
deployment needs a new name and operator directory. A matching resource name
alone is not permission to replace another role or expand its policies.

The [RAM templates](ram/) are shared by both paths. They restrict OIDC trust to the
CAA/controller or CSI ServiceAccounts and scope creation/deletion to the cluster's
ownership tags. `configure-values.py` uses those same identities and tags.

References: [ACK creation](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster),
[RRSA](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services),
[Terway](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/work-with-terway).
