# Maintain and retire a deployment

Use the installed source on T and the same `OPERATOR_DIR`, cloud profile, region
and trusted service address used during deployment. The commands below use the
default paths. A second operator directory alone does not isolate the fixed
systemd units, ports or `/etc` state; another deployment needs another service host.

## Stop and back up

Stop every sandbox with the native CLI while Gateway, driver, Trustee and CSI are
still available. Do not delete sandboxes whose workspaces must be retained.
Record their names, CR UIDs, PVC/PV handles and cloud disk IDs using the
[live acceptance procedure](live-acceptance.md). Confirm the role VMs have gone and
the retained disks are `Available` before continuing.

On T, select a new private backup directory and quiesce state writers:

```bash
export OPERATOR_DIR=/var/lib/openshell-confidential/operator/cluster-config
export HANDOFF=/var/lib/openshell-confidential/operator/handoff
export KUBECONFIG="$OPERATOR_DIR/administrator-kubeconfig"
BACKUP=/var/backups/openshell/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$BACKUP"
systemctl stop openshell-confidential-gateway.service openshell-confidential-driver.service
if systemctl cat attestation-observer.service >/dev/null 2>&1; then
  systemctl stop attestation-observer.service
fi
systemctl stop kbs.service as.service
# Run the Trustee stop/backup steps on its own host if it is separate.
docker stop openshell-registry
kubectl get pv -o yaml > "$BACKUP/pvs.yaml"
kubectl get storageclass alicloud-disk-essd-peerpod -o yaml > "$BACKUP/workspace-storageclass.yaml"
kubectl -n caa-csi-block get configmap caa-csi-block-bootstrap-params -o yaml > "$BACKUP/csi-bootstrap.yaml"
helm -n confidential-containers-system get values peerpods -a > "$BACKUP/peerpods-values.yaml"
helm -n confidential-containers-system get values caa-csi-block -a > "$BACKUP/csi-values.yaml"
EXTRA_STATE=()
for path in /etc/systemd/system/{openshell-confidential-*,as,kbs,attestation-observer}.service.d \
  /etc/systemd/system/attestation-observer.service /var/lib/openshell-attestation-observer \
  /var/lib/private/openshell-attestation-observer; do
  if [[ -e "$path" ]]; then EXTRA_STATE+=("$path"); fi
done
tar --acls --xattrs --numeric-owner -cpf "$BACKUP/trusted-state.tar" \
  /etc/openshell-confidential /var/lib/openshell-confidential \
  /etc/trustee /opt/trustee /opt/openshell \
  /etc/systemd/system/openshell-confidential-*.service \
  /etc/systemd/system/as.service /etc/systemd/system/kbs.service "${EXTRA_STATE[@]}"
sha256sum "$BACKUP/trusted-state.tar" > "$BACKUP/trusted-state.sha256"
```

The optional observer is stopped and included when installed. The extra paths
preserve its history and local service overrides. Add any custom state paths or
units used by your deployment. Include the real directory beneath `/var/lib/private`
as well as its public symlink for systemd's `DynamicUser` state. Store the backup
on protected storage outside this host. It contains private keys, provider
credentials, workspace keys, administration credentials and registry content.

Wait for outstanding volume create/delete operations to finish before taking the
inventory. CSI uses node-local records and cloud tag recovery, without a separate
state PVC. Preserve the cluster ID, bootstrap parameters and PV inventory. Take
an ACK snapshot/backup of every retained workspace ESSD and record the exact disk
and completed snapshot IDs. An application-consistent restore needs the same
stopped point across Gateway data, driver state, Trustee state and workspace
disks. A disk snapshot alone cannot recreate the workspace key or owner identity.

Keep the complete driver directory: signer, resources, workspace keys/bindings,
trusted environment records, active attempts, owner records and revocation
journals/tombstones. Keep Gateway database and TLS/JWT identity, Trustee CA/AS
signer/admin identity, reference store, policies and resource storage. Selective
copying of only apparently active files is insufficient.

## Stopped release update

This procedure supports local patch updates within the same pinned OpenShell,
Kata, guest-components, Trustee and ACK runtime versions, with unchanged private
state formats. It does not migrate upstream versions, service addresses, clusters
or storage formats. Review the release changes before proceeding. Existing
workspaces must reopen without initialization; an update must never format them.

Build and authenticate release B first, retaining release A. Complete the stopped
backup above. Set `NEW_HANDOFF` to B's transferred directory and `NEW_SHA256` to
its SHA256SUMS digest obtained from the trusted build host:

```bash
printf '%s  %s\n' "$NEW_SHA256" "$NEW_HANDOFF/SHA256SUMS" | sha256sum -c -
(cd "$NEW_HANDOFF" && sha256sum -c SHA256SUMS --quiet)
OLD_SHA256=$(sha256sum "$HANDOFF/SHA256SUMS" | cut -d ' ' -f1)
cp "$OPERATOR_DIR/ack-state.json" "$BACKUP/ack-state.before.json"
mv -T "$HANDOFF" "$BACKUP/handoff"
mv -T /opt/confidential-openshell "$BACKUP/source"
install -d -m 0700 "$BACKUP/installer"
tar -xf "$NEW_HANDOFF/source/integration.tar" -C "$BACKUP/installer"
python3 "$BACKUP/installer/deployment/build/install-release.py" \
  --handoff "$NEW_HANDOFF" --sha256 "$NEW_SHA256"
cd /opt/confidential-openshell
```

If a move or installation fails, keep services stopped. Finish the interrupted
step, or restore the two moved directories. An incomplete staging directory is
never a completed release. Do not overwrite a completed handoff or discard
`ack-state.json` to bypass its release check.

Rebind only the release fields after checking both authenticated source archives.
This retains cluster/network/role IDs and all trusted runtime state. Keep the old
image/object IDs in the backup for later cleanup:

```bash
python3 - "$BACKUP/handoff" "$HANDOFF" "$OPERATOR_DIR" "$OLD_SHA256" "$NEW_SHA256" <<'PY'
import hashlib, json, pathlib, sys, tarfile
old, new, operator = map(pathlib.Path, sys.argv[1:4])
old_sha, new_sha = sys.argv[4:]
def digest(path):
    return hashlib.sha256((path / 'SHA256SUMS').read_bytes()).hexdigest()
assert digest(old) == old_sha and digest(new) == new_sha
assert json.loads((old/'selection.json').read_text())['podvm_region'] == json.loads((new/'selection.json').read_text())['podvm_region']
def source(path, name):
    with tarfile.open(path/'source/integration.tar') as archive:
        return json.load(archive.extractfile(name))
a, b = (source(p, 'deployment/build/sources.lock.json') for p in (old, new))
assert all(a[k]['base'] == b[k]['base'] for k in ('openshell', 'cloud-api-adaptor', 'caa-csi-block-driver', 'kata-containers'))
a, b = (source(p, 'deployment/artifacts.lock.json') for p in (old, new))
assert a == b, 'guest upstream inputs changed; this is not a patch-only update'
a, b = (source(p, 'deployment/runtime/artifacts.lock.json') for p in (old, new))
assert a['openshell_version'] == b['openshell_version']
assert all(a['images'][k] == b['images'][k] for k in ('trustee_as', 'trustee_kbs', 'registry'))
assert source(old, 'deployment/ack/ack.example.json') == source(new, 'deployment/ack/ack.example.json')
path = operator/'ack-state.json'
state = json.loads(path.read_text())
assert state['handoff_sha256'] in (old_sha, new_sha), 'unexpected deployment identity'
if state['handoff_sha256'] != new_sha:
    state['handoff_sha256'] = new_sha
    for key in ('podvm_image_id', 'oss_object'):
        state.pop(key, None)
    temporary = path.with_suffix('.release.tmp')
    temporary.write_text(json.dumps(state, indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(path)
PY
```

Reapply the changed components using the normal steps:

```bash
./cos cloud image
if systemctl is-enabled --quiet attestation-observer.service; then
  ./cos trustee reports
fi
./cos trustee start
./cos deploy initdata
./cos registry start
./cos registry publish
./cos workers registry
./cos cluster values --replace
./cos cluster peerpods
./cos workers configure
./cos cluster csi
./cos gateway install
./cos gateway start
```

`gateway install` preserves `gateway.toml`. Review template changes against the
private file. Driver configuration generates `driver.env.part` and installs it as
`driver.env` automatically with `root:openshell-gateway`, mode `0640`. Back up the
previous environment before the upgrade and review the installed configuration
and published digests before starting Gateway. Do not regenerate TLS identities,
driver keys, resource records or workspace keys.
The conditional reports step installs the selected observer binary and unit when
reports were already enabled; restarting an old binary alone does not update it.
Start one retained sandbox and complete
[live acceptance](live-acceptance.md), checking stable CR UID, disk, LUKS UUID and
files with fresh role attempts. Resume the remaining sandboxes after it passes.

For rollback, stop all sandboxes and services again. Keep B's source, handoff,
`ack-state.json` and configuration separately; restore A's source/handoff paths.
In the current `ack-state.json`, restore only `handoff_sha256`, `podvm_image_id`
and `oss_object` from A's saved file, after checking that name, region, cluster ID
and `config_sha256` still match. Restore A's reviewed `driver.env` with ownership
`root:openshell-gateway` and mode `0640`, then rerun the same component installation
sequence using A. If A predates configuration preservation, its `gateway install`
overwrites `gateway.toml`: keep the reviewed configuration separately and install
it back with the same ownership/mode after that command and before `gateway start`.
**Do not restore an old trusted
state tar during a binary rollback**: doing so can revive revoked authorization
or lose changes made after the snapshot. Keep CSI state and workspace data
current. Retain both images until no VM uses them and rollback is no longer needed.

## Recovery limits

The stopped backup is a disaster-recovery input, not proof of a tested automatic
restore. Full recovery onto a lost/replaced cluster or service host is not currently
supported by an automated procedure. Before a restore exercise, isolate the old
writer, preserve the same Gateway/driver/Trustee identities, restore matching
CSI/workspace snapshots, renew kubeconfig and RRSA access, and reconcile revoked
attempts before permitting release. Do not start an old binding snapshot against
newer disks or revive a deleted sandbox. Keep this environment inaccessible until
real appraisal, denial and lifecycle checks pass. If the trusted workspace key or
owner state is lost, recreating a PVC with the same cloud disk ID is not recovery.

## Retire owned resources

Keep Gateway, driver, Trustee, CAA, PeerPod controller and CSI running while deleting
sandboxes with `openshell sandbox delete NAME`. Record each CR UID, role instance
ID, PVC/PV and cloud disk ID first. Wait for their exact-ID readbacks to show
absence. Do not remove finalizers, CSI controller state or runtime roles to force
cleanup. A retained-disk security-lock error requires investigating the instance
lock; forcing ECS deletion can destroy retained data.

Once no sandbox is retained and no owned role VM/workspace disk remains:

1. Save `ack-state.json`, Helm values and an inventory of every dedicated resource.
   On an attached cluster, this includes only resources added by this deployment.
   Preserve the CSI bootstrap configuration and workspace disk inventory.
2. Stop/disable the two OpenShell services. Uninstall `caa-csi-block` and `peerpods`
   from their Helm release namespace `confidential-containers-system`; let their
   cleanup hooks finish. Confirm all owned workspace PVs and backing disks are
   deleted or explicitly recorded as retained. If upgrading from the older split
   layout, inventory its retained controller-state PVC separately and remove it
   only after cloud recovery is verified and no old controller is using it.
3. On an attached cluster, retain the cluster, VPC, node pools, CSI add-ons,
   Terway, RRSA issuer, shared cert-manager/Agent Sandbox installations and worker
   security group. Remove only this deployment's worker labels, Kata runtime
   configuration and registry trust after confirming no other workloads use them.
   The worker files keep `.before-openshell` backups; compare current contents
   before restoring them. Retain unrelated subsequent administrator changes.
4. Remove the saved PodVM SNAT entry before its NAT gateway is removed. Check its
   `SourceVSwitchId` against `podvm_vswitch_id`. Revoke only the security-group
   rule IDs connecting this deployment's worker and PodVM groups. Then remove its
   unused PodVM security group and vSwitch. Do not remove the worker NAT/EIP or
   whole worker security group in an attached cluster.
5. For a cluster **created by this deployment** (`created_cluster: true`), verify
   its name, VPC and ownership tag, disable deletion protection and let ACK delete
   its managed workers and networking:

   ```bash
   CLUSTER=$(jq -er '.cluster_id' "$OPERATOR_DIR/ack-state.json")
   aliyun cs DescribeClusterDetail --ClusterId "$CLUSTER"
   aliyun cs ModifyCluster --ClusterId "$CLUSTER" --body '{"deletion_protection":false}'
   aliyun cs DeleteCluster --ClusterId "$CLUSTER" --retain_all_resources=false --keep_slb=false
   ```

   Use the configured CLI profile/region. Poll exact cluster ID until the API
   explicitly reports it absent. Wait for owned instances, ENIs, NAT, API EIP/SLB
   and node-pool scaling resources to disappear. Only then delete any remaining
   dedicated worker/Pod vSwitches, mutually referencing SG rules/groups and VPC.
   A timeout or permission denial is not evidence of deletion.
6. For each saved CAA/CSI RAM role, verify its description is
   `confidential-openshell:NAME:CLUSTER_ID`. List and detach its custom policy,
   delete the role, then delete the unattached custom policy (including versions).
   Remove the dedicated worker key pair after no instance uses it. Preserve
   `AliyunECSImageImportDefaultRole`, shared import policies and attached-cluster
   OIDC providers. ACK normally removes its own managed identities; check for
   leftovers belonging to the deleted cluster.
7. Only for images imported by this deployment, record backing snapshot IDs from
   `DescribeImages` before deleting the image. Confirm no instances use it, then
   delete the image, its now-unused import snapshots and the exact saved OSS
   object. Delete the bucket only when its ownership matches, it has no other
   objects/versions and no multipart uploads. Preserve publisher-provided images.
   Include old images/objects retained during release updates.
8. Stop/remove the dedicated registry container and Trustee services after no
   other deployment uses them. Retain the private backups for the agreed retention
   period. If T was a dedicated cloud VM, delete its VM, disks, EIP, key pair and
   dedicated network resources last; remove only its entries from shared ACLs.

Use the normal Alibaba CLI operations: `DescribeDisks`/`DeleteDisk`,
`DescribeSnatTableEntries`/`DeleteSnatEntry`, `DescribeSecurityGroupAttribute`/
`RevokeSecurityGroup`/`DeleteSecurityGroup`, `DescribeVSwitches`/`DeleteVSwitch`,
`DescribeVpcs`/`DeleteVpc`, and the corresponding RAM/image/OSS commands. Supply
exact IDs from the saved inventory; paginate listings when `TotalCount` exceeds
the returned page. Inspect dependencies instead of broad recursive deletion.

Close out with an exact-ID inventory for all recorded compute, disks, snapshots,
images, network and identity resources, including partial-installation resources.
Each item must be absent or explicitly retained with its owner and ongoing cost.
Do not erase operator state until that readback is complete.
