# ACK implementation reference

Users follow [deployment](../../docs/deployment.md) using `./cos` for each step.
The Python files here implement cloud operations; users do not invoke them or
copy generated resource IDs into configuration templates.

## New cluster

`./cos cluster create` selects a configured zone or one with ECS inventory, saves inputs and creates a
dedicated VPC, worker/Pod vSwitches, ACK Pro and an Ubuntu node pool. ACK enables
RRSA, Terway NetworkPolicy, storage add-ons and worker SNAT.
`./cos cloud network` creates the PodVM vSwitch/security group and inherits egress.

Automatic zone selection uses ECS
[DescribeAvailableResource](https://help.aliyun.com/en/ecs/developer-reference/api-ecs-2014-05-26-describeavailableresource)
inventory and prefers the configured zone when available. The Beijing example
uses Zone I. Pass `--zone` to select another zone.
`./cos cloud image` then checks the actual TDX launch parameters with
[RunInstances DryRun](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-runinstances)
without creating a VM. Ordinary ECS inventory alone cannot establish TDX availability.
Network creation uses [CreateVpc](https://help.aliyun.com/en/vpc/developer-reference/api-vpc-2016-04-28-createvpc)
and [CreateVSwitch](https://help.aliyun.com/en/vpc/api-createvswitch), with saved IDs,
idempotency tokens and availability waits before dependent operations.

## Existing cluster

`./cos cluster attach` lists/selects ACK and obtains its network configuration.
It keeps existing VPC, worker vSwitches and node pools, obtains a temporary
administrator kubeconfig and reports missing requirements without changing
cluster features. Common deployment steps add PodVM resources and identities.

## Saved configuration

Under `/var/lib/openshell-confidential/operator/cluster-config`:

| File | Contents |
| --- | --- |
| `operator.json` | Trusted service address and CLI profile, loaded automatically |
| `ack.json` | Immutable inputs, generated names/CIDRs and versions |
| `ack-state.json` | Created/discovered IDs, role ARNs, egress IPs and selected workers |
| `administrator-kubeconfig` | ACK administrator credentials, valid for up to three days |
| `podvm-image.json` | ECS image binding to the release/reference checksums |
| `*-image.txt` | Published destination image digests |
| `steps.json`, `logs/` | Previous command results and private output |

Generated IDs live in state; input files stay immutable on retries. Retain both.
Use a separate `OPERATOR_DIR` for a different deployment. Repeat the same cluster
create/attach command to renew kubeconfig. The trusted host needs no ECS identity.

The new VPC defaults to `10.64.0.0/16`, with three distinct `/24` ranges for workers,
Kubernetes Pods and PodVMs. `--vpc-cidr` changes this plan. The Service CIDR is
outside the VPC. Review planned network connections for overlap before creation.
The example places PodVMs in one configured zone.

## Image storage and runtime identities

`./cos cloud image` creates/checks a private, same-region OSS bucket for import
when needed. It ensures the official `AliyunECSImageImportDefaultRole` with
`AliyunECSImageImportRolePolicy`, retaining existing trust policies. See
[ImportImage authorization](https://help.aliyun.com/en/ecs/developer-reference/api-ecs-2014-05-26-importimage).
An existing ImageID needs neither bucket creation nor import authorization.

`./cos cloud identities` uses the [RAM templates](ram/) for separate CAA/controller
and CSI roles, scoped by ServiceAccount, cluster ownership and vSwitch. Runtime
roles are separate from the operator and image-import identities.

Cloud resources remain billable until deleted. New ACK has deletion protection;
disable it before deletion. State identifies generated resources. Shared import
roles and existing-cluster resources are retained resources.

Follow [operations](../../docs/operations.md#retire-owned-resources) for the ordered
cleanup of dedicated resources and exact-ID readback. Beijing Zone I with
ecs.g9i.xlarge and containerd 2.3.4 is the validated configuration.
