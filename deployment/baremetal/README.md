# Native Kata on a TDX worker

Run the supervisor and workload in separate TDX VMs on an untrusted Kubernetes
worker. Keep the CLI, Gateway, confidential driver and Trustee on a trusted
system. Both backends use the same verified UKI and SquashFS root filesystem.

## Limitations

- Guest access to KBS and the private registry requires IPv4 endpoints. Each
  server certificate must include its endpoint IP in the subjectAltName (SAN).
- Guest services and containers share the Pod network. Egress rules apply to
  the entire PodVM. The in-guest broker constrains agent egress.
- Persistent volumes use a transitional sidecar and guest service. Replace
  the handoff when Kata delivers policy-bound devices, and replace guest
  initialization and open when CDH supports the persistent volume lifecycle.
  See the [CoCo RFC][volume-rfc] and guest-components [#1648][cdh1648] and
  [#1715][cdh1715].
- The workspace is the only supported workload block device. With Kata 4.4
  and virtio-scsi, a second block device can fail the guest's SCSI scan during
  container creation. Use Memory emptyDirs. Disk-backed emptyDirs (CoCo's
  default `block-encrypted` mode) and additional Block PVCs are unsupported.
- A local PV supports recovery on the same worker.
- After workload Pod replacement or worker reboot, use Gateway stop/start to
  authorize the replacement VMs, as with Peer Pods. See [Recovery](#recovery).
- The platform policy accepts the VMM's TD HOB memory layout for the approved
  TDVF to process, as it does for dynamic ACPI data. CCEL replay authenticates
  the recorded digests. Individual memory ranges are outside this appraisal.
- Only the Go `kata-qemu-tdx` shim has been validated with this boot profile.
- Use `--memory 16Gi` for the pinned OpenShell Community image. Its layers
  unpack in guest memory. With the current Kata overhead the VM gets 18 GiB.
  Size other images for their unpacked layers and workload.

## Prerequisites

- A TDX-capable amd64 worker, a Kubernetes cluster with containerd, and a CNI
  that enforces NetworkPolicy. The cluster administrator needs Helm and kubectl.
- An [installed release][release] on the trusted system, its verified guest
  QCOW2 (`GUEST_QCOW2`), and the matching image references (`IMAGE_REFERENCES`).
  The worker and the trusted system need qemu-img, sfdisk, mtools and GNU
  objcopy to prepare the image.
- A trusted host IPv4 address reachable from the guests. The bundled services
  use TCP 8443 for KBS, 5000 for the registry and 9443 for the Gateway.
- Reserve about 150 GiB of free space for genpolicy's temporary directory on
  the trusted host. This sizing was verified with the pinned Community image.

## Prepare the workers

Follow the [CoCo TDX host guide][host-guide] to set up the host kernel,
firmware and quote generation service. On each worker, choose the same new
absolute `GUEST_DIRECTORY` for the release and run:

```bash
python3 deployment/baremetal/prepare-guest.py \
  "$GUEST_QCOW2" "$GUEST_DIRECTORY" > guest.toml
```

The script converts the system disk to raw and extracts its UKI. When the Go
shim attaches an image it generates root parameters for its own filesystem
profile. The drop-in clears Kata's packaged verity table and selects the real
root device and filesystem type. The UKI initrd locates the data and hash
partitions by PARTUUID using its embedded roothash. These overrides can go
away when the shim supports a system disk whose root is managed by the UKI.

On the cluster administrator's machine, use the worker's `guest.toml` and the
Kata chart version in the [runtime lock][runtime-lock]:

```bash
helm upgrade --install coco \
  oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
  --version 4.4.0 --namespace coco-system --create-namespace \
  --values deployment/baremetal/kata-values.yaml \
  --set-file shims.qemu-tdx.dropIn=guest.toml
kubectl -n coco-system rollout status daemonset/kata-deploy
kubectl label runtimeclass kata-qemu-tdx \
  openshell.ai/sandbox-attachable=true --overwrite
```

Set the chart's `k8sDistribution` for distributions that manage their own
containerd template. The shim boots `kata-containers.target`. Its vsock agent
loads the measured role policy and starts AA and CDH from the initdata disk.

## Set up the trusted services

Run these scripts as root from the installed release. Export `HOST_IP` and
`KUBECONFIG` for the trusted service address and the cluster administrator's
kubeconfig. The scripts use the standard release handoff and operator paths.

### Boot references and Trustee

On the trusted system, derive the references from the verified release using
a new local `GUEST_DIRECTORY`:

```bash
python3 deployment/baremetal/prepare-guest.py \
  "$GUEST_QCOW2" "$GUEST_DIRECTORY" > guest.toml
python3 deployment/baremetal/guest-references.py \
  "$IMAGE_REFERENCES" guest.toml > kata-guest.references.json
export KATA_GUEST_REFERENCES="$PWD/kata-guest.references.json"
```

Trustee binds the role's exact initdata to MRCONFIGID. Its native policy pins
the TDVF MRTD and the static events in a sequence of 16 RTMR0 events. Slot 0
has type `EV_EFI_HANDOFF_TABLES2` and description `TdxTable`. Trustee's
default TDX policy also appraises firmware without pinning each RTMR0 event.

For the [bundled Trustee][trustee], prepare the certificates and services:

```bash
bash deployment/trustee/create-certificates.sh
bash deployment/trustee/install.sh
```

For a separately managed Trustee, follow the [external Trustee steps][external]
and register the native guest and platform references there.

### Driver configuration and service startup

In `/etc/openshell-confidential/driver.env`, set the backend configuration:

```ini
OPENSHELL_CONFIDENTIAL_RUNTIME_CLASS=kata-qemu-tdx
OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS=openshell-local
```

Export the RuntimeClass setting above in the shell that runs the setup scripts.
Trustee startup selects the platform references from it, and Gateway
installation checks access to that RuntimeClass. Set
`OPENSHELL_KATA_OCI_VERSION` in the same file to the OCI spec version emitted by
the cluster runtime. Use the name of your Block StorageClass if it differs from
the [local example](#persistent-workspace).

Start the bundled Trustee, or skip the first command if using an external
Trustee. Prepare the guest initdata and publish the images:

```bash
bash deployment/trustee/start.sh
bash deployment/guest/install-initdata.sh
bash deployment/peerpods/start-registry.sh
bash deployment/peerpods/publish-images.sh
```

CDH uses the registry CA in the measured initdata to fetch image layers inside
the guest. On workers, containerd resolves registry metadata and pulls ordinary
Pods such as the Agent Sandbox controller and cert-manager. For a registry
with a private CA, enable the CRI registry `config_path` in the distribution's
containerd configuration. Under its active registry hosts directory, install
the public CA as `HOST_IP:5000/ca.crt` and the [hosts.toml example][hosts]
as `HOST_IP:5000/hosts.toml`. Substitute the actual IP and CA path. A worker
whose resolver already trusts the registry needs no additional CA.

```bash
bash deployment/peerpods/install-prerequisites.sh
bash deployment/openshell/install.sh
bash deployment/openshell/start-services.sh
bash deployment/openshell/login.sh
```

Check supervisor-to-Gateway TLS connectivity before running a sandbox.

## Persistent workspace

The driver binds the Block PVC to a PV before it opens the Pod scheduling
gate. Use a StorageClass with immediate binding. For a single worker, the
following static PV example uses an unused, zero-filled block device.
Replace the worker name, device path and capacity before applying it.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: openshell-local
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: openshell-workspace-1
spec:
  storageClassName: openshell-local
  capacity:
    storage: 2Gi
  accessModes: [ReadWriteOnce]
  volumeMode: Block
  persistentVolumeReclaimPolicy: Retain
  local:
    path: /dev/disk/by-id/WORKSPACE_DISK
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [tdx-worker]
```

A restartable init container holds the device for the lifetime of the Pod.
During normal Pod termination, kubelet signals it after the workload exits.
Its TERM handler runs `sync` before Kata detaches the device. The configured
default sandbox image must provide `/bin/sh`, `stat -c %t:%T`, `mv`, `sleep`,
`sync` and `/usr/bin/test`.

On first use, the guest initializes LUKS2 and creates ext4 with the measured
sandbox UID and GID.
On reopen, CDH uses the same sandbox key. The guest verifies the active
mapping before mounting it for seed and agent. If opening fails, the startup
probe times out and neither starts.

The driver records the PV UID on the trusted system. With reclaim policy
`Retain`, the storage owner disposes of the device after sandbox deletion.

## Workload network

The workload uses the OpenShell DNS relay at `127.0.0.53`. Local Kata masks
systemd-resolved so the relay can bind both TCP and UDP port 53. CDH needs
the registry before this relay starts. Domain endpoints can be reconsidered
when guest services have bootstrap DNS independent of the workload relay.

Apply the following NetworkPolicy in the workload namespace alongside the
Gateway's supervisor rules. Replace the example address with the trusted
host's IPv4 address.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: native-kata-guest-egress
spec:
  podSelector:
    matchLabels:
      openshell.ai/boundary-role: workload
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock: {cidr: 192.0.2.10/32}
      ports:
        - {protocol: TCP, port: 8443} # KBS
        - {protocol: TCP, port: 5000} # Private registry
```

With storage and egress configured, follow the [first-agent
walkthrough][first-agent] to create a sandbox.

## Recovery

After Kubernetes replaces the workload Pod or the worker restarts, use the
Gateway to authorize the new role guests and reopen the retained workspace:

```bash
openshell sandbox stop NAME
openshell sandbox start NAME
```

If the driver already stopped the sandbox, use `start` alone.

## Updating the Kata boot references

1. Inspect the Go shim configuration in the locked amd64 kata-deploy image.
   Its packaged verity table belongs to Kata's own image.
2. Review the release's `virtcontainers/qemu_amd64.go`, `qemu_arch_base.go`,
   `qemu.go:kernelParameters` and `pkg/katautils/{config,create}.go`.
   Update `KATA_VERSION` and the ordered prefix in `guest-references.py`.
   Check the Helm values, firmware identity and RTMR0 event layout.
3. Repeat the [trusted reference generation](#boot-references-and-trustee).
   RTMR1 extends the UKI Authenticode digest and firmware boot actions.
   RTMR2 extends the verified section seed with both UTF-16LE LoadOptions
   digests and the Linux initrd digest.
4. Cold-boot a guest. Compare the predicted registers, full external command
   line and event order with a verified quote and its replayed CCEL. Check
   the read-only SquashFS root, active verity hash and both role appraisals
   before accepting the release.

[release]: ../../docs/build.md#build-and-transfer
[host-guide]:
  https://confidentialcontainers.org/docs/getting-started/prerequisites/hardware/tdx/
[runtime-lock]: ../runtime/artifacts.lock.json
[trustee]: ../../docs/deployment.md#6-install-and-start-trustee
[external]: ../../docs/deployment.md#existing-or-separately-deployed-trustee
[hosts]: ../peerpods/registry-hosts.example.toml
[first-agent]: ../../docs/first-agent.md
[volume-rfc]:
  https://github.com/confidential-containers/confidential-containers/pull/390
[cdh1648]: https://github.com/confidential-containers/guest-components/pull/1648
[cdh1715]: https://github.com/confidential-containers/guest-components/pull/1715
