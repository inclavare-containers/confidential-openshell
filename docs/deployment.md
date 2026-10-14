# Sequential deployment runbook

This installs the main Ubuntu UKI / CoCo 0.22 profile with native OpenShell 0.1.3.
Build and package using [build.md](build.md), then follow the ten steps below.
For an existing installation, use [upgrade and retention](upgrade.md) first.
Users of a provisioned Gateway start at [first agent](first-agent.md).

**B** is the trusted build role; **T** hosts Gateway, driver, Trustee and private
registry; **U** is the untrusted ACK/cloud worker plane; **G** is the attested
supervisor/workload guest. B may run on T. This profile co-locates trusted services
because the driver and KBS share local resources/policies; splitting them requires
an authenticated layout review. ACK and worker hosts receive sealed descriptors,
not bootstrap or workspace keys.

Run Bash with `set -euo pipefail; umask 077`. T host commands run as root;
worker blocks use the existing administrator connection. Stop on failed checks.
Keep cloud values, credentials, private keys and live state outside the checkout:

| Location | Contents |
| --- | --- |
| `/opt/confidential-openshell` | Verified public source snapshot |
| `/var/lib/openshell-confidential/operator/` | Private handoff, deployment values and ownership records |
| `/etc/openshell-confidential`, `/etc/trustee` | Service configuration and retained PKI |
| `/opt/trustee`, `/var/lib/openshell-confidential` | Authorization resources, key journals and Gateway state |

## 1. Pin sources and build integration binaries/images

**On B:** follow [build preparation and outputs](build.md#obtain-complete-fixed-sources).
The source lock fixes upstream commits and separate patch result trees. Build the
driver, Kata host shim, CAA/CSI images, Alibaba-enabled PeerPod controller, agent
image and patched CSI chart. Run the offline suite and record actual output hashes.
Use released, unmodified AA/CDH/Kata guest binaries; build APF/PUD from the verified
CAA queue. Build recipes live only in build.md.

## 2. Select the guest image and matching references

**On B:** [select a compatible image](build.md#select-the-guest-image), then
[create the verified B → T handoff](build.md#build-and-transfer). The handoff binds
public sources, binaries, image archives, charts, image selection and references
through an independently authenticated checksum list.

### Build a new image (optional)

Use the [maintained guest build recipe](build.md#build-a-new-image-optional).
Its final QCOW/reference hashes must come from the normal build receipt; an offline
build does not establish real TDX acceptance. If reusing an approved compatible
ImageID and matching reference file, skip the build and import.

**On T:** after verifying/extracting the handoff, initialize these variables in
one root shell (repeat when opening a new shell). Supply `HOST_IP` and administrator
`KUBECONFIG` from the existing host/cluster inventory, not from sample addresses:

```bash
set -euo pipefail
umask 077
HOST_IP=REPLACE_WITH_APPROVED_TRUSTED_PRIVATE_IPV4
KUBECONFIG=/absolute/path/to/approved-administrator-kubeconfig
export HOST_IP KUBECONFIG
test -r "$KUBECONFIG"
SOURCE_ROOT=/opt/confidential-openshell
HANDOFF=/var/lib/openshell-confidential/operator/handoff
OPERATOR_DIR=/var/lib/openshell-confidential/operator/cluster-config
PODVM_MODE=$(jq -er .podvm_mode "$HANDOFF/selection.json")
PODVM_REGION=$(jq -er .podvm_region "$HANDOFF/selection.json")
PODVM_IMAGE_ID=$(jq -r .podvm_image_id "$HANDOFF/selection.json")
if [[ "$PODVM_MODE" == import && -f "$OPERATOR_DIR/podvm-image-id.txt" ]]; then
  PODVM_IMAGE_ID=$(cat "$OPERATOR_DIR/podvm-image-id.txt")
fi
GUEST_FILE=$(jq -r '.guest // empty' "$HANDOFF/selection.json")
PODVM_QCOW2=${GUEST_FILE:+"$HANDOFF/outputs/$GUEST_FILE"}
PODVM_REFERENCE_VALUES="$HANDOFF/outputs/$(jq -er .references "$HANDOFF/selection.json")"
CAA_TAG=$(jq -er .caa_tag "$HANDOFF/selection.json")
CSI_TAG=$(jq -er .csi_tag "$HANDOFF/selection.json")
PEERPOD_CTRL_TAG=$(jq -er .peerpod_ctrl_tag "$HANDOFF/selection.json")
AGENT_TAG=$(jq -er .agent_tag "$HANDOFF/selection.json")
AGENT_IMAGE_ID=$(jq -er .agent_image_id "$HANDOFF/selection.json")
CHART_CACHE="$HANDOFF/charts"
CSI_CHART="$HANDOFF/charts/caa-csi-block-driver.tgz"
cd "$SOURCE_ROOT"
```

The three locks in the source snapshot are the authoritative artifact inputs.
Keep edited values in `OPERATOR_DIR`; do not edit the checked-in examples.

## 3. Prepare cluster, select the cloud image and configure identities

**On T administering U:** install Docker, jq, Git, curl, tar, zstd, OpenSSL,
CA certificates, Python 3.11/cryptography and the tools below using approved host
packages/downloads. Verify the pinned tool hashes before the first cluster command:

```bash
LOCK=deployment/runtime/artifacts.lock.json
for tool in docker zstd jq git python3.11 openssl curl tar; do command -v "$tool"; done
systemctl enable --now docker.service
HELM_VERSION=$(jq -er .tools.helm.version "$LOCK")
KUBECTL_VERSION=$(jq -er .tools.kubectl.version "$LOCK")
CRANE_VERSION=$(jq -er .tools.crane.version "$LOCK")
curl -fL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" -o "$OPERATOR_DIR/helm.tgz"
tar -xOf "$OPERATOR_DIR/helm.tgz" linux-amd64/helm > "$OPERATOR_DIR/helm"
curl -fL "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o "$OPERATOR_DIR/kubectl"
curl -fL "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_x86_64.tar.gz" -o "$OPERATOR_DIR/crane.tgz"
tar -xOf "$OPERATOR_DIR/crane.tgz" crane > "$OPERATOR_DIR/crane"
for tool in helm kubectl crane; do
  printf '%s  %s\n' "$(jq -er --arg tool "$tool" '.tools[$tool].sha256' "$LOCK")" "$OPERATOR_DIR/$tool" | sha256sum -c -
  install -m 0755 "$OPERATOR_DIR/$tool" /usr/local/bin/
done
```

### Prepare the infrastructure

Create ACK using the [official workflow](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster):
Terway with shared ENI, enforced ingress/egress NetworkPolicy and RRSA. Verify
real traffic denial, not just successful policy creation. Select containerd workers
with `supplementalGroupsPolicy` support. The tested profile uses Kubernetes 1.36,
containerd 2.3.4/configuration version 3 and OCI policy version 1.3.0; another
runtime needs its actual OCI requests checked against generated guest policy.

```bash
kubectl get nodes -o wide
kubectl get nodes -o json | jq -e '.items | length > 0'
kubectl get nodes -o json | jq -e 'all(.items[];
  .status.features.supplementalGroupsPolicy == true and
  (.status.nodeInfo.containerRuntimeVersion | startswith("containerd://")) and
  any(.status.conditions[]; .type == "Ready" and .status == "True"))'
```

Use the administrator's region, VPC, zone, dedicated PodVM vSwitch/security group
and a compatible TDX instance type (the template uses `ecs.g9i.xlarge`). Provide
worker↔PodVM VXLAN connectivity following the
[upstream Alibaba PeerPods guide](https://confidentialcontainers.org/docs/examples/alibaba-cloud-simple/).
Allow only approved private traffic to T's registry (5000), KBS (8443) and Gateway
(9443); restrict administrative access separately.

### Select the PodVM image

For `existing`, verify the selected ImageID/region against its release record:
publisher, `Available`, Linux/x86_64, UEFI, NVMe support and required disk size.
A region copy requires its own ImageID-to-reference record.

For `import`, upload the verified handoff QCOW to private OSS in the target region
and use [ECS custom-image import](https://www.alibabacloud.com/help/en/ecs/user-guide/import-a-custom-image).
Select Ubuntu/Linux, x86_64, QCOW2, UEFI and NVMe support; system disk at least
20 GiB (the PeerPods template requests 40 GiB). Wait for `Available` and read back
UEFI/NVMe before recording the imported ID. CAA selects TDX when creating the VM;
there is no TPM import setting.

```bash
if [[ "$PODVM_MODE" == import ]]; then
  PODVM_IMAGE_ID=REPLACE_WITH_IMPORTED_IMAGE_ID
fi
: "${PODVM_IMAGE_ID:?selected PodVM ImageID required}"
[[ "$PODVM_IMAGE_ID" =~ ^m-[a-z0-9]+$ ]]
printf '%s\n' "$PODVM_IMAGE_ID" > "$OPERATOR_DIR/podvm-image-id.txt"
printf '%s\n' "$PODVM_REGION" > "$OPERATOR_DIR/podvm-region.txt"
sha256sum "$PODVM_REFERENCE_VALUES" > "$OPERATOR_DIR/podvm-references.sha256"
```

### Configure RAM roles

Use [ACK RRSA](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-rrsa-to-authorize-pods-to-access-different-cloud-services)
to obtain the cluster OIDC provider ARN/issuer. Copy the four
[RAM templates](../deployment/ack/ram/) into `OPERATOR_DIR` and replace their
account, region, cluster, OIDC and configured vSwitch placeholders. Create two
permission policies and two roles; attach each policy only to its matching role:

- CAA/controller: `cloud-api-adaptor` and `peerpodctrl-controller-manager` in
  `confidential-containers-system`, with cluster/tag ownership restrictions.
- CSI: `caa-csi-block` in `caa-csi-block`, with CSI disk ownership restrictions.
  Do not attach cloud creation permissions to node Pods.

Keep role names/ARNs and ownership tags consistent with Helm values. The upstream
Alibaba provider requires `vpc:DescribeVSwitchAttributes` on the **configured**
vSwitch; the CAA/controller template scopes that permission to its exact ARN.
Use RRSA projected tokens, not access keys in Helm values.

## 4. Install Trustee and register the approved image references

**On T:** official `trustee_as` and `trustee_kbs` images come from the runtime lock.
AS includes BuiltIn RVPS on loopback 50004; KBS exposes private HTTPS 8443. Use the
maintained [configs and units](../deployment/trustee/README.md), with one local
driver/policy writer. Initial setup follows; upgrades preserve PKI, signer,
resources, bindings and key journals.

```bash
for image in trustee_as trustee_kbs; do
  ref=$(jq -er --arg image "$image" '.images[$image]' deployment/runtime/artifacts.lock.json)
  docker pull --platform linux/amd64 "$ref"
done
id openshell-gateway >/dev/null 2>&1 || useradd --system \
  --home-dir /var/lib/openshell-confidential --shell /usr/sbin/nologin openshell-gateway
install -d -m 0750 -o root -g openshell-gateway \
  /etc/trustee /etc/trustee/tls /opt/trustee \
  /opt/trustee/attestation-service /opt/trustee/attestation-service/storage
install -d -m 0700 -o openshell-gateway -g openshell-gateway \
  /opt/trustee/attestation-service/storage/attestation_service_policy \
  /opt/trustee/kbs /opt/trustee/kbs/storage /opt/trustee/kbs/storage/kbs \
  /opt/trustee/kbs/storage/repository /opt/trustee/kbs/signing \
  /opt/trustee/kbs/signing/bindings /opt/trustee/kbs/signing/workspace-bindings
```

### Create the host identities

For initial installation, require both CA files absent. If either exists, verify
and retain the existing PKI instead of running generation commands. Edit the server
SAN template with the same `HOST_IP`:

```bash
test ! -e /etc/trustee/tls/ca.key && test ! -e /etc/trustee/tls/ca.pem
cp deployment/trustee/certificates/server.example.ext "$OPERATOR_DIR/server.ext"
${EDITOR:-vi} "$OPERATOR_DIR/server.ext"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/trustee/tls/ca.key
openssl req -x509 -new -sha256 -days 3650 \
  -key /etc/trustee/tls/ca.key \
  -config deployment/trustee/certificates/ca.cnf \
  -out /etc/trustee/tls/ca.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /etc/trustee/tls/server.key
openssl req -new -sha256 -key /etc/trustee/tls/server.key \
  -subj /CN=confidential-openshell-trustee -out /etc/trustee/tls/server.csr
openssl x509 -req -sha256 -days 825 -in /etc/trustee/tls/server.csr \
  -CA /etc/trustee/tls/ca.pem -CAkey /etc/trustee/tls/ca.key -CAcreateserial \
  -extfile "$OPERATOR_DIR/server.ext" -out /etc/trustee/tls/server.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/trustee/tls/as-token.key
openssl req -new -sha256 -key /etc/trustee/tls/as-token.key \
  -subj /CN=confidential-openshell-attestation-signer -out /etc/trustee/tls/as-token.csr
openssl x509 -req -sha256 -days 825 -in /etc/trustee/tls/as-token.csr \
  -CA /etc/trustee/tls/ca.pem -CAkey /etc/trustee/tls/ca.key -CAcreateserial \
  -extfile deployment/trustee/certificates/as-token.ext -out /etc/trustee/tls/as-token.pem
cat /etc/trustee/tls/server.pem /etc/trustee/tls/ca.pem > /etc/trustee/tls/server-chain.pem
cat /etc/trustee/tls/as-token.pem /etc/trustee/tls/ca.pem > /etc/trustee/tls/as-token-chain.pem
openssl x509 -in /etc/trustee/tls/as-token.pem -pubkey -noout > /etc/trustee/tls/as-token-public.pem
chown root:root /etc/trustee/tls/*.key
chmod 0600 /etc/trustee/tls/*.key
chmod 0644 /etc/trustee/tls/*.pem
openssl verify -CAfile /etc/trustee/tls/ca.pem /etc/trustee/tls/server.pem /etc/trustee/tls/as-token.pem
```

The AS P-256 EAR signer is separate from the driver's P-256 vault signer under
`/opt/trustee/kbs/signing`. Keep root-owned TLS/EAR private keys unreadable by the
driver; it needs only public trust and its own resource/signing state. CA rotation
requires coordinated registry, initdata and driver updates.

### Install configuration and initialize deny policies

KBS uses the retained server chain/EAR CA, rejects header-supplied JWKs and has
`DenyAll` remote administration. AS/driver policies start with empty bindings:

```bash
cp deployment/trustee/kbs-config.example.toml "$OPERATOR_DIR/kbs-config.toml"
${EDITOR:-vi} "$OPERATOR_DIR/kbs-config.toml"
install -m 0600 "$OPERATOR_DIR/kbs-config.toml" /etc/trustee/kbs-config.toml
install -m 0600 deployment/trustee/as-config.json /etc/trustee/as-config.json
for directory in /opt/confidential-openshell /opt/confidential-openshell/deployment \
  /opt/confidential-openshell/deployment/runtime /opt/confidential-openshell/deployment/trustee \
  /opt/confidential-openshell/deployment/policy; do
  chown root:openshell-gateway "$directory"
  chmod 0750 "$directory"
done
for source in deployment/runtime/agent_policy.py deployment/trustee/render-kbs-policy.py \
  deployment/policy/agent-policy-workload.rego deployment/policy/agent-policy-guest-pull.rego \
  deployment/policy/kbs-sealed.rego deployment/policy/tdx-podvm.rego; do
  chown root:openshell-gateway "$source"
  chmod 0640 "$source"
  runuser -u openshell-gateway -- test -r "$source"
done
runuser -u openshell-gateway -- python3.11 deployment/trustee/render-kbs-policy.py \
  --bindings-dir /opt/trustee/kbs/signing/bindings \
  --workspace-bindings-dir /opt/trustee/kbs/signing/workspace-bindings \
  --as-policy-output /opt/trustee/attestation-service/storage/attestation_service_policy/default_cpu.rego \
  --output /opt/trustee/kbs/storage/kbs/resource-policy.rego
```

Empty bindings deny release. The driver publishes current role/attempt bindings
under its store lock before opening the scheduling gate. Trustee 0.22 LocalFs
uses flat resource filenames; preserve logical KBS URIs and journals. Do not
replace appraisal with allow-all or put dynamic initdata in static references.

### Start services and register exact references

Set `PODVM_PLATFORM_REFERENCES` and its separately approved checksum to the reviewed
[controlled ECS map](../deployment/trustee/ecs-tdx-platform.references.json), or an
independently reviewed replacement. Register it together with the selected image map:

```bash
printf 'TRUSTEE_AS_IMAGE=%s\nTRUSTEE_KBS_IMAGE=%s\n' \
  "$(jq -er .images.trustee_as deployment/runtime/artifacts.lock.json)" \
  "$(jq -er .images.trustee_kbs deployment/runtime/artifacts.lock.json)" \
  > /etc/trustee/images.env
chmod 0600 /etc/trustee/images.env
install -m 0644 deployment/trustee/units/as.service /etc/systemd/system/as.service
install -m 0644 deployment/trustee/units/kbs.service /etc/systemd/system/kbs.service
systemctl daemon-reload
systemctl enable --now as.service
: "${PODVM_PLATFORM_REFERENCES:?reviewed platform map required}"
: "${PODVM_PLATFORM_REFERENCE_SHA256:?approved platform map checksum required}"
printf '%s  %s\n' "$PODVM_PLATFORM_REFERENCE_SHA256" "$PODVM_PLATFORM_REFERENCES" | sha256sum -c -
python3.11 deployment/trustee/register-references.py \
  --address http://127.0.0.1:50004 \
  --references "$PODVM_REFERENCE_VALUES" --references "$PODVM_PLATFORM_REFERENCES"
systemctl enable --now kbs.service
systemctl is-active as.service kbs.service
: "${HOST_IP:?approved trusted private IPv4 required}"
code=$(curl --noproxy '*' --cacert /etc/trustee/tls/ca.pem -sS \
  -o /dev/null -w '%{http_code}' \
  "https://${HOST_IP}:8443/kbs/v0/resource/default/bootstrap/anonymous-check")
case "$code" in 401|403) ;; *) exit 1 ;; esac
```

The image map derives RTMR1/full RTMR2 from the final UKI; the platform map pins
MRTD and three static RTMR0 events. Policy requires exactly six RTMR0 events in
order, with dynamic ACPI contents explicitly accepted as untrusted VMM input
handled by approved TDVF/kernel. All four RTMRs still require signed-quote replay.
Do not enroll measurements from a live quote. The registrar queries back active
reference names; unexpected values block admission. Inactive retained legacy RVPS
names are not authorization inputs. See [the policy contract](../deployment/trustee/README.md).
The anonymous HTTPS probe above proves listener/trust/denial, not attestation.

## 5. Generate measured base initdata

**On T:** render the deny-only base using the same private address and Trustee CA.
It contains public AA/CDH configuration and policy; the driver binds each real
role/attempt/resource before scheduling. CAA's fallback uses this exact file:

```sh
test -f /etc/trustee/tls/ca.pem
install -d -o root -g openshell-gateway -m 0750 /etc/openshell-confidential
initdata_file="$(mktemp)"
python3.11 deployment/guest/render-guest-initdata.py \
  "$HOST_IP" /etc/trustee/tls/ca.pem > "$initdata_file"
install -o root -g openshell-gateway -m 0640 "$initdata_file" \
  /etc/openshell-confidential/guest-initdata-base.toml
rm "$initdata_file"
```

## 6. Configure registry and transfer digest-pinned images

**On T, then each U worker:** use the same public CA as measured AA/CDH trust.
Start the pinned private registry and verify HTTPS:

```bash
: "${HOST_IP:?approved trusted private IPv4 required}"
REGISTRY_ADDR="${HOST_IP}:5000"
install -d -m 0755 "/etc/docker/certs.d/${REGISTRY_ADDR}"
install -m 0644 /etc/trustee/tls/ca.pem "/etc/docker/certs.d/${REGISTRY_ADDR}/ca.crt"
if command -v update-ca-trust >/dev/null; then
  install -m 0644 /etc/trustee/tls/ca.pem /etc/pki/ca-trust/source/anchors/openshell-registry.crt
  update-ca-trust
else
  install -m 0644 /etc/trustee/tls/ca.pem /usr/local/share/ca-certificates/openshell-registry.crt
  update-ca-certificates
fi
install -d -m 0700 /var/lib/openshell-confidential/registry
docker run -d --name openshell-registry --restart unless-stopped \
  -p "${HOST_IP}:5000:5000" \
  -v /etc/trustee/tls/server-chain.pem:/certs/domain.crt:ro \
  -v /etc/trustee/tls/server.key:/certs/domain.key:ro \
  -v /var/lib/openshell-confidential/registry:/var/lib/registry \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  "$(jq -er .images.registry deployment/runtime/artifacts.lock.json)"
curl --noproxy '*' --cacert /etc/trustee/tls/ca.pem -fsS "https://${REGISTRY_ADDR}/v2/"
```

On each worker, merge the edited
[registry hosts template](../deployment/peerpods/registry-hosts.example.toml)
into `/etc/containerd/certs.d/PRIVATE_REGISTRY/hosts.toml`, with its public `ca.crt`:

```bash
cp deployment/peerpods/registry-hosts.example.toml "$OPERATOR_DIR/registry-hosts.toml"
${EDITOR:-vi} "$OPERATOR_DIR/registry-hosts.toml"
scp /etc/trustee/tls/ca.pem ADMIN@WORKER:/tmp/openshell-registry-ca.crt
scp "$OPERATOR_DIR/registry-hosts.toml" ADMIN@WORKER:/tmp/openshell-registry-hosts.toml
```

```bash
sudo install -d -m 0755 /etc/containerd/certs.d/PRIVATE_REGISTRY
sudo install -m 0644 /tmp/openshell-registry-ca.crt /etc/containerd/certs.d/PRIVATE_REGISTRY/ca.crt
sudo install -m 0644 /tmp/openshell-registry-hosts.toml /etc/containerd/certs.d/PRIVATE_REGISTRY/hosts.toml
rm /tmp/openshell-registry-ca.crt /tmp/openshell-registry-hosts.toml
```

Back on T, mirror the pinned runtime images and record each destination digest:

```bash
for name in pause supervisor sandbox workload_python; do
  ref=$(jq -er --arg name "$name" '.images[$name]' deployment/runtime/artifacts.lock.json)
  dest="$REGISTRY_ADDR/openshell/mirror/$name:locked"
  crane copy --platform linux/amd64 "$ref" "$dest"
  digest=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$dest")
  printf '%s@%s\n' "${dest%:*}" "$digest" > "$OPERATOR_DIR/$name-image.txt"
done
```

Use those digest references consistently in CAA, worker CRI and driver settings.
Mirror other controllers/Kata/CSI sidecars if upstream registries are unavailable,
keeping source-to-destination digest records. No insecure registry flags are needed.
Load/publish the verified built archives and record the returned digests:

```bash
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
for archive in caa csi peerpod-controller agent; do
  docker load -i "$HANDOFF/outputs/$archive.tar"
done
test "$(docker image inspect "$AGENT_IMAGE_ID" --format '{{.Id}}')" = "$AGENT_IMAGE_ID"
for pair in "cloud-api-adaptor:$CAA_TAG" "caa-csi-block-driver:$CSI_TAG" "peerpod-ctrl:$PEERPOD_CTRL_TAG"; do
  docker tag "openshell/$pair" "$REGISTRY_ADDR/openshell/$pair"
  docker push "$REGISTRY_ADDR/openshell/$pair"
  SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest "$REGISTRY_ADDR/openshell/$pair"
done
```

```bash
AGENT_DEST="$REGISTRY_ADDR/openshell/opencode:${AGENT_TAG##*:}"
docker tag "$AGENT_IMAGE_ID" "$AGENT_DEST"
docker push "$AGENT_DEST"
AGENT_DIGEST=$(SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane digest --platform=linux/amd64 "$AGENT_DEST")
AGENT_IMAGE="${AGENT_DEST%:*}@$AGENT_DIGEST"
SSL_CERT_FILE=/etc/trustee/tls/ca.pem crane manifest --platform=linux/amd64 "$AGENT_IMAGE" | \
  jq -e --arg id "$AGENT_IMAGE_ID" '.config.digest == $id'
printf '%s\n' "$AGENT_IMAGE" > "$OPERATOR_DIR/agent-image.txt"
```

Set private Helm values to the returned CAA/CSI/controller digests, not their
tags or the official runtime bases. `AGENT_IMAGE` is the digest passed to the user
walkthrough. Registry certificate renewal requires restarting its listener and
checking the served certificate.

## 7. Install Kata, PeerPods and CSI, then verify workers

**On T administering U:** first [package the patched Kata host shim](build.md#package-the-kata-host-shim)
inside kata-deploy's component archive. Set `kata-deploy.image.reference` to that
published digest. The released guest agent, genpolicy and remaining archives stay
unchanged. Install dependencies, then PeerPods/CSI, then verify every worker.

### Install cluster dependencies

Download/hash-check the fixed dependencies using the runtime lock:

```bash
for item in agent_sandbox_manifest cert_manager_chart; do
  path="$OPERATOR_DIR/$item"
  curl -fL "$(jq -er --arg item "$item" '.downloads[$item].url' deployment/runtime/artifacts.lock.json)" -o "$path"
  printf '%s  %s\n' "$(jq -er --arg item "$item" '.downloads[$item].sha256' deployment/runtime/artifacts.lock.json)" "$path" | sha256sum -c -
done
cp "$OPERATOR_DIR/agent_sandbox_manifest" "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
${EDITOR:-vi} "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
kubectl apply --server-side -f "$OPERATOR_DIR/agent-sandbox-pinned.yaml"
kubectl -n agent-sandbox-system rollout status deployment/agent-sandbox-controller --timeout=10m
kubectl get crd sandboxes.agents.x-k8s.io
helm upgrade --install cert-manager "$OPERATOR_DIR/cert_manager_chart" \
  --namespace cert-manager --create-namespace \
  --values deployment/peerpods/cert-manager-values.json --wait --timeout=15m
```

In the edited Agent Sandbox manifest, change only the controller image to the
lock's `agent_sandbox_controller` digest or recorded mirror. A compatible existing
cert-manager installation can be used instead of adding another release.

### Install PeerPods

Copy/edit the example in `OPERATOR_DIR`. Parameter sources are:

| Values | Source |
| --- | --- |
| CAA, controller, kata-deploy and pause images | Published exact digests from steps 6–7 |
| `IMAGEID`, `REGION` | Verified image selection in step 3 |
| VPC/vSwitch/security group, instance type, tags | Approved cloud inventory; same ownership tags as RAM/CSI |
| CAA/controller role and OIDC values | RRSA identities from step 3 |
| `INITDATA` | `gzip -n -c /etc/openshell-confidential/guest-initdata-base.toml \| base64 -w0` |

```bash
cp deployment/peerpods/peerpods-values.example.yaml "$OPERATOR_DIR/peerpods-values.yaml"
${EDITOR:-vi} "$OPERATOR_DIR/peerpods-values.yaml"
```

The fallback initdata denies workload startup; real Pods get measured per-role
bindings from the driver. Label each intended Ready worker and assemble the clean
CAA chart with the exact dependency archives from the handoff:

```bash
kubectl label node WORKER_NODE node.kubernetes.io/worker= --overwrite
kubectl get nodes -l node.kubernetes.io/worker -o wide
# The build handoff includes checksum-pinned public chart dependencies.
mkdir -p .local/charts/peerpods
cp -a repos/cloud-api-adaptor/src/cloud-api-adaptor/install/charts/peerpods/. .local/charts/peerpods/
mkdir -p .local/charts/peerpods/charts
CHART_CACHE="$HANDOFF/charts"
while IFS=$'\t' read -r name digest; do
  printf '%s  %s\n' "$digest" "$CHART_CACHE/$name" | sha256sum -c -
  cp "$CHART_CACHE/$name" ".local/charts/peerpods/charts/$name"
done < <(jq -r '.charts | to_entries[] | [.key,.value] | @tsv' deployment/runtime/artifacts.lock.json)
```

```bash
helm template peerpods .local/charts/peerpods \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/peerpods-values.yaml" \
  > "$OPERATOR_DIR/peerpods-rendered.yaml"
helm upgrade --install peerpods .local/charts/peerpods \
  --namespace confidential-containers-system --create-namespace \
  --values "$OPERATOR_DIR/peerpods-values.yaml" --timeout=25m
kubectl -n confidential-containers-system patch deployment peerpodctrl-controller-manager \
  --type=strategic --patch-file deployment/peerpods/peerpod-controller-rrsa.patch.yaml
kubectl -n confidential-containers-system rollout status daemonset/kata-deploy --timeout=25m
kubectl -n confidential-containers-system rollout status daemonset/cloud-api-adaptor-daemonset --timeout=15m
kubectl -n confidential-containers-system rollout status deployment/peerpodctrl-controller-manager --timeout=15m
kubectl -n peer-pods-webhook-system rollout status deployment/peer-pods-webhook-controller-manager --timeout=15m
```

The controller RRSA patch supplies the missing projected-token mount; reapply it
after chart upgrades. Verify the expected role annotations and token mount.
After provider ConfigMap changes, restart both CAA and controller to reload envFrom:

```bash
kubectl -n confidential-containers-system rollout restart daemonset/cloud-api-adaptor-daemonset
kubectl -n confidential-containers-system rollout restart deployment/peerpodctrl-controller-manager
kubectl -n confidential-containers-system get daemonset/kata-deploy daemonset/cloud-api-adaptor-daemonset
```

DaemonSet desired/ready counts must cover every selected worker; zero desired is
not success. Read back `/opt/kata/bin/containerd-shim-kata-v2` SHA-256 on each worker
and compare with the handoff binary before allowing confidential sandboxes.

### Configure each worker's Kata profile

Repeat after every kata-deploy rollout because it replaces configuration files.
Resolve `kata-remote.options.ConfigPath` from containerd's **merged** configuration;
editing an unused copy does not configure the runtime. Confirm the containerd
config argument with `systemctl show containerd.service -p ExecStart` first.
During `sudoedit` below, merge
[kata-remote-settings.example.toml](../deployment/peerpods/kata-remote-settings.example.toml)
into the resolved file. Keep CRI registry `config_path=/etc/containerd/certs.d`
and the same private pause digest, editing the owning fragment when imported.

```bash
WORKER_SSH=REPLACE_WITH_EXISTING_WORKER_SSH_ALIAS
CONTAINERD_CONFIG=/etc/containerd/config.toml
WORKER_EVIDENCE="$OPERATOR_DIR/worker-profile/$WORKER_SSH"
install -d -m 0700 "$WORKER_EVIDENCE"
ssh "$WORKER_SSH" "sudo containerd --config '$CONTAINERD_CONFIG' config dump" \
  > "$WORKER_EVIDENCE/containerd.effective.before.toml"
KATA_REMOTE_CONFIG=$(python3.11 - "$WORKER_EVIDENCE/containerd.effective.before.toml" <<'PYCONFIG'
import pathlib, re, sys, tomllib
with open(sys.argv[1], 'rb') as f:
    merged = tomllib.load(f)
handler = merged['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
path = handler['options']['ConfigPath']
assert re.fullmatch(r'/opt/kata/[A-Za-z0-9_./-]+/configuration-remote\.toml', path)
assert '..' not in pathlib.PurePosixPath(path).parts
print(path)
PYCONFIG
)
printf '%s\n' "$KATA_REMOTE_CONFIG" > "$WORKER_EVIDENCE/effective-kata-config-path.txt"
ssh "$WORKER_SSH" "sudo cat '$KATA_REMOTE_CONFIG'" > "$WORKER_EVIDENCE/kata.before.toml"
ssh -t "$WORKER_SSH" "sudoedit '$KATA_REMOTE_CONFIG' '$CONTAINERD_CONFIG'"
ssh "$WORKER_SSH" 'sudo systemctl restart containerd.service'
ssh "$WORKER_SSH" 'sudo systemctl is-active --quiet containerd.service'
ssh "$WORKER_SSH" "sudo containerd --config '$CONTAINERD_CONFIG' config dump" \
  > "$WORKER_EVIDENCE/containerd.effective.after.toml"
ssh "$WORKER_SSH" "sudo cat '$KATA_REMOTE_CONFIG'" > "$WORKER_EVIDENCE/kata.after.toml"
python3.11 - "$WORKER_EVIDENCE" "$KATA_REMOTE_CONFIG" <<'PYCONFIG'
import pathlib, sys, tomllib
area, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
with (area/'containerd.effective.after.toml').open('rb') as f:
    merged = tomllib.load(f)
assert merged['version'] == 3
handler = merged['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
assert handler['options']['ConfigPath'] == expected
with (area/'kata.after.toml').open('rb') as f:
    kata = tomllib.load(f)
assert kata['hypervisor']['remote']['shared_fs'] == 'none'
assert kata['runtime']['experimental_force_guest_pull'] is True
assert kata['runtime']['create_container_timeout'] == 600
PYCONFIG
sha256sum "$WORKER_EVIDENCE"/*.toml > "$WORKER_EVIDENCE/profile.sha256"
```

The effective profile requires `shared_fs=none`, guest image pull and a 600-second
container creation timeout for first-use whole-disk/LUKS initialization. Preserve
other settings and propagate this profile through node-pool initialization.
Then verify/label the RuntimeClass:

```bash
kubectl get runtimeclass kata-remote -o yaml
kubectl label runtimeclass kata-remote openshell.ai/sandbox-attachable=true --overwrite
```

Its handler is `kata-remote`, with pinned overhead `cpu: 250m`, `memory: 120Mi`.
Keep sandbox scheduling stopped until every selected worker passes these checks.

### Install CSI

Install the patched chart from the authenticated handoff, not the upstream source
chart. Verify its manifest hash/provenance and edit the private values:

```bash
CSI_CHART="$HANDOFF/charts/caa-csi-block-driver.tgz"
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
CSI_CHART_SHA256=$(jq -er '.artifacts["csi-chart"].sha256' "$HANDOFF/build-manifest.json")
printf '%s  %s\n' "$CSI_CHART_SHA256" "$CSI_CHART" | sha256sum -c -
tar -xOf "$CSI_CHART" caa-csi-block-driver/source-provenance.json > "$OPERATOR_DIR/csi-chart-source.json"
jq -e --slurpfile source "$OPERATOR_DIR/csi-chart-source.json" \
  '.artifacts["csi-chart"].source == $source[0] and
   .sources["caa-csi-block-driver"].patch_check == "verified" and
   $source[0].patched_result_tree == .sources["caa-csi-block-driver"].expected_patched_result_tree and
   $source[0].source_upstream_commit == .sources["caa-csi-block-driver"].source_upstream_commit' \
  "$HANDOFF/build-manifest.json"
```

```bash
cp deployment/peerpods/csi-values.example.yaml "$OPERATOR_DIR/csi-values.yaml"
${EDITOR:-vi} "$OPERATOR_DIR/csi-values.yaml"
```

Use the CSI digest and its separate RRSA role. Controller state uses a durable PVC
on the **host ACK ESSD StorageClass**, not the PeerPod class it provisions. Keep one
controller replica with `Recreate` strategy.

```bash
kubectl create namespace caa-csi-block
helm template caa-csi-block "$CSI_CHART" \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/csi-values.yaml" \
  > "$OPERATOR_DIR/csi-rendered.yaml"
helm upgrade --install caa-csi-block "$CSI_CHART" \
  --namespace confidential-containers-system --values "$OPERATOR_DIR/csi-values.yaml" \
  --wait --timeout=20m
kubectl -n caa-csi-block rollout status deployment/caa-csi-block-controller --timeout=15m
kubectl -n caa-csi-block rollout status daemonset/caa-csi-block --timeout=15m
kubectl -n caa-csi-block get pvc
kubectl get storageclass alicloud-disk-essd-peerpod -o yaml
```

Resources live in `caa-csi-block`; the Helm release namespace remains
`confidential-containers-system`. The PeerPod StorageClass uses
`caa-csi-block.csi.confidentialcontainers.io`, expansion disabled and `Delete`
reclaim policy. Stop/Start retains the original Sandbox/PVC/disk identity; final
PVC deletion deletes the owned disk. Do not recreate a workspace with a new UID.

## 8. Install the native Gateway and confidential driver

**On T:** install lock-pinned Gateway/CLI and the verified driver, then the official
Kata policy tools. Gateway/driver receive restricted ServiceAccount credentials,
not the administrator kubeconfig.

```sh
install -d -m 0700 /var/lib/openshell-confidential/downloads
for release in gateway cli; do
  curl -fL --retry 5 \
    "$(jq -er --arg release "$release" '.downloads[$release].url' deployment/runtime/artifacts.lock.json)" \
    -o "/var/lib/openshell-confidential/downloads/$release.tar.gz"
  printf '%s  %s\n' \
    "$(jq -er --arg release "$release" '.downloads[$release].sha256' deployment/runtime/artifacts.lock.json)" \
    "/var/lib/openshell-confidential/downloads/$release.tar.gz" | sha256sum -c -
done
tar -xzf /var/lib/openshell-confidential/downloads/gateway.tar.gz \
  -C /usr/local/bin openshell-gateway
tar -xzf /var/lib/openshell-confidential/downloads/cli.tar.gz \
  -C /usr/local/bin openshell
chmod 0755 /usr/local/bin/openshell-gateway /usr/local/bin/openshell
(cd "$HANDOFF" && sha256sum -c SHA256SUMS)
install -m 0755 "$HANDOFF/outputs/openshell-driver-confidential-kubernetes" \
  /usr/local/bin/openshell-driver-confidential-kubernetes
/usr/local/bin/openshell-driver-confidential-kubernetes --version
```

```sh
DOWNLOADS=/var/lib/openshell-confidential/downloads
POLICY_TOOLS=/opt/openshell/kata-policy
curl -fL --retry 5 "$(jq -er .downloads.kata_tools.url deployment/runtime/artifacts.lock.json)" \
  -o "$DOWNLOADS/kata-tools.tar.zst"
printf '%s  %s\n' "$(jq -er .downloads.kata_tools.sha256 deployment/runtime/artifacts.lock.json)" \
  "$DOWNLOADS/kata-tools.tar.zst" | sha256sum -c -
zstd -dc "$DOWNLOADS/kata-tools.tar.zst" > "$DOWNLOADS/kata-tools.tar"
install -d -m 0755 "$POLICY_TOOLS"
for name in genpolicy rules.rego genpolicy-settings.json; do
  if [[ "$name" == genpolicy ]]; then path=./opt/kata/bin/$name; else path=./opt/kata/share/defaults/kata-containers/$name; fi
  tar -xOf "$DOWNLOADS/kata-tools.tar" "$path" > "$POLICY_TOOLS/$name"
done
rm "$DOWNLOADS/kata-tools.tar"
chmod 0755 "$POLICY_TOOLS/genpolicy"
chmod 0644 "$POLICY_TOOLS/rules.rego" "$POLICY_TOOLS/genpolicy-settings.json"
python3.11 - "$POLICY_TOOLS" <<'PYTOOLS'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("agent_policy", "deployment/runtime/agent_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
policy._checked_tools(pathlib.Path(sys.argv[1]))
PYTOOLS
```

Create the native Gateway certificate/JWT set with the same `HOST_IP` in its SAN.
Retain an existing complete set; operator client private keys stay only on T.
Guests receive the public CA and their own attestation-gated launch credentials:

```sh
install -d -o root -g openshell-gateway -m 0750 /var/lib/openshell-confidential
install -d -o openshell-gateway -g openshell-gateway -m 0700 \
  /var/lib/openshell-confidential/data
test -e /var/lib/openshell-confidential/tls || \
  /usr/local/bin/openshell-gateway generate-certs \
    --output-dir /var/lib/openshell-confidential/tls --server-san "$HOST_IP"
openssl x509 -in /var/lib/openshell-confidential/tls/server/tls.crt \
  -checkip "$HOST_IP" -noout
for name in ca.crt ca.key client/tls.crt client/tls.key \
  server/tls.crt server/tls.key jwt/signing.pem jwt/public.pem jwt/kid; do
  test -f "/var/lib/openshell-confidential/tls/$name"
done
TLS_ROOT=/var/lib/openshell-confidential/tls
for directory in "$TLS_ROOT" "$TLS_ROOT/server" "$TLS_ROOT/jwt"; do
  chown root:openshell-gateway "$directory"
  chmod 0750 "$directory"
done
chown root:openshell-gateway "$TLS_ROOT/server/tls.key" "$TLS_ROOT/jwt/signing.pem"
chmod 0640 "$TLS_ROOT/server/tls.key" "$TLS_ROOT/jwt/signing.pem"
chmod 0644 "$TLS_ROOT/ca.crt" "$TLS_ROOT/server/tls.crt" "$TLS_ROOT/client/tls.crt" \
  "$TLS_ROOT/jwt/public.pem" "$TLS_ROOT/jwt/kid"
chmod 0700 "$TLS_ROOT/client"
install -o root -g openshell-gateway -m 0640 \
  deployment/openshell/gateway.toml /etc/openshell-confidential/gateway.toml
python3.11 - "$HOST_IP" <<'PYCONFIG'
from pathlib import Path
import ipaddress, sys
address = str(ipaddress.IPv4Address(sys.argv[1]))
assert ipaddress.IPv4Address(address).is_private
path = Path("/etc/openshell-confidential/gateway.toml")
text = path.read_text()
assert 'bind_address = "10.0.0.10:9443"' in text
path.write_text(text.replace('bind_address = "10.0.0.10:9443"', f'bind_address = "{address}:9443"'))
PYCONFIG
```

### Configure the Gateway ServiceAccount kubeconfig

Apply the maintained RBAC and obtain its bound-token Secret using the administrator
kubeconfig. The following writes a private restricted kubeconfig and runs preflight:

```sh
kubectl create namespace openshell --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deployment/openshell/gateway-rbac.yaml
for attempt in $(seq 1 60); do
  if test -n "$(kubectl -n openshell get secret openshell-gateway-token \
      -o jsonpath='{.data.token}')" && \
     test -n "$(kubectl -n openshell get secret openshell-gateway-token \
      -o jsonpath='{.data.ca\.crt}')"; then
    break
  fi
  sleep 2
done
test -n "$(kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.token}')"
test -n "$(kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.ca\.crt}')"
GATEWAY_KUBECONFIG=/etc/openshell-confidential/kubeconfig
ACK_API_SERVER="$(kubectl config view --minify \
  -o jsonpath='{.clusters[0].cluster.server}')"
case "$ACK_API_SERVER" in https://*) ;; *) exit 1 ;; esac
kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /etc/openshell-confidential/ack-ca.pem
test -s /etc/openshell-confidential/ack-ca.pem
chown root:openshell-gateway /etc/openshell-confidential/ack-ca.pem
chmod 0644 /etc/openshell-confidential/ack-ca.pem
install -o root -g openshell-gateway -m 0640 /dev/null "$GATEWAY_KUBECONFIG"
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-cluster ack \
  --server="$ACK_API_SERVER" \
  --certificate-authority=/etc/openshell-confidential/ack-ca.pem \
  --embed-certs=true
set +x
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-credentials \
  openshell-gateway --token="$(kubectl -n openshell get secret \
    openshell-gateway-token -o jsonpath='{.data.token}' | base64 -d)"
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-context openshell \
  --cluster=ack --user=openshell-gateway --namespace=openshell
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config use-context openshell
chown root:openshell-gateway "$GATEWAY_KUBECONFIG"
chmod 0640 "$GATEWAY_KUBECONFIG"
for check in \
  'get persistentvolumeclaims -n openshell' \
  'get runtimeclass/kata-remote' \
  'get services -n openshell' \
  'create services -n openshell' \
  'delete services -n openshell'; do
  test "$(kubectl --kubeconfig /etc/openshell-confidential/kubeconfig \
    auth can-i $check)" = yes
done
runuser -u openshell-gateway -- env \
  KUBECONFIG=/etc/openshell-confidential/kubeconfig \
  /usr/local/bin/openshell-gateway \
  --config /etc/openshell-confidential/gateway.toml config preflight
```

Install namespace ingress default denial before either role is scheduled:

```sh
kubectl apply -f deployment/openshell/network-fence.example.yaml
kubectl -n openshell get networkpolicy confidential-ingress-default-deny -o yaml
```

The driver also adds explicit supervisor ingress denial and workload boundary
rules. Effective NetworkPolicy is additive: inspect the actual union and test
traffic. Supervisor-initiated Gateway/workload connections need no inbound
supervisor exception.

### Prepare public Gateway trust for the sealed supervisor bootstrap

The Gateway enables native operator mTLS, disables anonymous users and accepts
sandbox-scoped JWTs on the same TLS listener. The driver seals the supervisor's
launch/session credentials and reads only the Gateway public CA. Its
`AuthenticateSandbox` denies ServiceAccount bootstrap before TokenReview; retain
native authentication capability so runtime identity survives Stop/Start.

Copy/edit `driver.env.example` with the same `HOST_IP` and step-6 digest references:
`WORKLOAD_IMAGE` is the Python Sandbox work image; `SANDBOX_IMAGE`,
`SUPERVISOR_IMAGE` and `PAUSE_IMAGE` are the mirrored released runtime images.
No private operator client key belongs in bootstrap input.

```sh
install -o root -g openshell-gateway -m 0640 \
  deployment/openshell/driver.env.example /etc/openshell-confidential/driver.env
${EDITOR:-vi} /etc/openshell-confidential/driver.env
if grep -q REPLACE_WITH /etc/openshell-confidential/driver.env; then
  exit 1
fi
install -m 0644 deployment/openshell/openshell-confidential-driver.service \
  /etc/systemd/system/openshell-confidential-driver.service
install -m 0644 deployment/openshell/openshell-confidential-gateway.service \
  /etc/systemd/system/openshell-confidential-gateway.service
systemctl daemon-reload
systemctl enable --now openshell-confidential-driver.service
for attempt in $(seq 1 60); do
  test -S /run/openshell-confidential/driver.sock && break
  sleep 1
done
test -S /run/openshell-confidential/driver.sock
systemctl enable --now openshell-confidential-gateway.service
for attempt in $(seq 1 60); do
  curl --noproxy '*' -fsS http://127.0.0.1:17671/readyz && break
  sleep 1
done
curl --noproxy '*' -fsS http://127.0.0.1:17671/readyz
```

Register the operator CLI with its private native mTLS identity:

```sh
install -d -m 0700 /var/lib/openshell-confidential/cli-config
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
/usr/local/bin/openshell gateway add --name confidential-local --local \
  "https://${HOST_IP}:9443"
export OPENSHELL_GATEWAY=confidential-local
openshell whoami --output json
```

Verify protected RPCs reject anonymous callers and a supervisor JWT cannot manage
or access another sandbox. Public health readiness is a separate check.
[Architecture](architecture.md) explains the attestation-gated credentials and
active-session revocation.

## 9. Run the native coding agent and verify its lifecycle

Follow [first agent](first-agent.md) using the installed Gateway, the step-6
`AGENT_IMAGE`, a configured provider and persistent workspace. It is the single
user route for actual model use, independent output checking and native lifecycle
commands. Keep private ownership/work records under the operator directory.

## 10. Verify both confidential roles

Before accepting a new image or deployment, require actual supervisor/workload
signed TDX appraisal and KBS resource decisions with the configured image/platform
references, current role, attempt, CR UID and initdata. Invalid bindings, descriptor,
image/policy or quote checks must deny release. Policy must be published before
opening the scheduling gate; private guest mounts and network fencing stay active.

Check actual model use, PTY, network denial, anonymous-user and cross-sandbox JWT
rejection. Stop/Start must retain CR UID, ESSD/LUKS header UUID, workspace key identity
and work bytes, while rotating bootstrap attempts and revoking old bindings. Check
raw ciphertext after detaching the stopped owned workspace disk; distribution
`cryptsetup`/`util-linux` on T are operator tools, not a guest diagnostic channel.
Finally native Delete must remove the owned role VMs/disks and controller metadata.

Keep sanitized image/reference/policy hashes, role identities and observed decisions
in private acceptance records. Do not publish plaintext secrets, private keys,
tokens or inference streams. [The test guide](../tests/README.md) defines maintenance
checks and evidence scope. The configured policy currently accepts TCB `UpToDate`
and `OutOfDate`; record the actual status. This explicit staging allowance does
not establish a production TCB requirement.
