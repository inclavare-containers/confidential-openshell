# Upgrade and retention

These steps preserve state when upgrading the Ubuntu/official CoCo 0.22 profile.
Use the [deployment runbook](deployment.md) for installation commands. A different
Trustee resource/policy layout requires an explicit state migration before existing
workspaces or authorization can be reused.

1. Record the installed integration SHA, upstream bases/result trees, driver/shim
   hashes, image digests, reference JSON hash and AS/KBS policy identities.
   Privately back up deployment configuration, Trustee CA/EAR signer keys,
   Gateway PKI/JWT/provider state, the KBS repository, bootstrap signer, workspace
   keys and authorization/delete/volume journals. Never initialize over that state
   or include secrets in a source handoff. Workspace identity belongs to its CR UID.
2. Build independent copies, replay each patch queue against its pinned base,
   verify result trees and run `bash tests/run.sh`. Record only the selected public
   outputs in the release manifest; see [build preparation](build.md).
3. Guest filesystem, binary, kernel/initrd or boot-chain changes require a matching
   image/reference pair. Driver-only changes may reuse an approved published pair
   after compatibility is checked with fresh attempts for both roles.
4. Stop new admission and retire affected role guests in Kubernetes and the cloud.
   Preserve each original CR UID and encrypted workspace. Stop affected services
   for image/reference replacement; run only one driver policy writer.
5. With admission and KBS stopped, preserve the existing RVPS state and update
   only the selected image measurements. AS must run for its built-in RVPS API;
   require the registration helper's exact query readback before starting KBS.
   Every active-policy reference must match exactly. Inventory retained names that
   the active policy does not query; do not widen accepted values to hide a mismatch.
   Keep initdata in dynamic AS/KBS bindings, not static references; never register
   test digests as approved measurements.
6. Check [native authentication](#native-authentication-and-existing-tls-state) and
   update [existing network fences](#update-existing-runtime-network-fences) if
   their version differs. Deploy the matching driver/image/references, regenerate
   the deny-only base and CAA fallback when their inputs changed, and create fresh
   measured role/attempt bindings. Reapply and verify the worker private-volume
   and guest-pull profile after kata-deploy installation. Resolve the active
   `kata-remote` ConfigPath from containerd's merged configuration; verify the
   three keys there, including the 600-second first-use creation timeout.
7. Start driver then Gateway and complete the [native agent walkthrough](first-agent.md)
   before reopening admission. Verify TLS/JWT authorization, policy-before-gate,
   real network denial and same-UID workspace persistence. Roll back only to a
   complete compatible driver/image/reference/policy combination; never regenerate
   workspace keys or assign retained disks to a replacement Sandbox UID.

Normal stop/delete remove KBS serving copies and authorization while retaining
private workspace recovery keys and volume journals on the trusted host. Preserve
that state and its permissions across upgrades; deletion is not key destruction.
The [driver resource contract](../components/confidential-driver/README.md#bootstrap-resources)
also describes interrupted-delete recovery. Runtime credentials and journals stay
outside source and release packages. The current test policy accepts `UpToDate`
and `OutOfDate`; all other quote, boot, initdata and authorization checks remain
required. See [trust boundaries](architecture.md).

## Sealed workload environment

Back up the driver's private `workload-environments/` directory with the store signer
and journals. Records are bound to namespace and Sandbox CR UID, with directory mode
0700 and file mode 0600. Stop retains them; final delete removes the matching record.
The Gateway's private state and KBS resource repository also contain sensitive values
and remain within the trusted host.

Sandboxes created before sealed environment persistence have no such record. Before
upgrading, export any needed files and recreate those sandboxes through the Gateway
from trusted configuration. Do not reconstruct environment state from Kubernetes.
For a newer sandbox, restore its original private record from a trusted backup if it
is missing or invalid. Start fails until that state is available; creating a replacement
Sandbox UID does not transfer ownership of the old encrypted workspace.

## Native authentication and existing TLS state

Upgrade Gateway, CLI and both runtime images to the locked v0.1.3 artifacts together.
Use `mtls_auth.enabled=true`, `allow_unauthenticated_users=false`, and the direct
private Gateway endpoint with its public CA in driver bootstrap inputs. Operator
client private keys remain on the trusted host. Keep native
`supports_sandbox_authentication=true` for persisted runtime identity;
`AuthenticateSandbox` rejects all requests before TokenReview/Kubernetes API access.
ServiceAccount tokens cannot replace sealed launch credentials.

Check the server's private-address SAN before running native certificate generation.
With an existing complete PKI/JWT set, v0.1.3
`generate-certs --server-san "$HOST_IP"` replaces the CA/server/operator TLS bundle
if that SAN is missing, while preserving JWT signing keys. Back up the existing
state first, then refresh the operator CLI bundle and guest public CA after rotation.
Use [the install step](deployment.md#8-install-the-native-gateway-and-confidential-driver)
for the final configuration and permissions; retain AS EAR signing and dynamic bindings.

KBS revocation blocks future release; native stop/delete terminate running guests.
Native `auth_epoch`/current `jti` checks reject subsequent RPC authentication, without
rechecking every frame of an existing stream or performing hardware appraisal at
new TLS handshakes. Verify same-sandbox JWT access and cross-sandbox denial.

## Update existing runtime network fences

The driver strictly validates existing policies; it does not reconcile an old spec.
Both `openshell-sandbox-workloads` and `openshell-sandbox-supervisors` must match
its current enforcement or create/restart fails closed. Workloads accept the
supervisor boundary connection and deny new outbound traffic. Supervisors deny
new inbound connections and retain native egress; reply traffic remains allowed.
Review any other selecting policies, including managed SSH, because their rules add
to the effective permissions.

For each configured namespace, stop admission and retire both roles and cloud VMs
before replacement. Preserve the original CR UID, workspace keys/volumes and journals.
The commands below require both existing policies and their expected owner labels.
If neither exists in an unused namespace, let the driver create them. Inspect partial
or unexpected ownership instead of replacing blindly. Keep default-deny throughout:

```bash
set -euo pipefail
umask 077
cd /opt/confidential-openshell
NS=openshell # Use the namespace actually configured in the driver.
BOUNDARY_PORT=5500 # Confirm against --sandbox-runtime-boundary-port / its environment.
FENCE_BACKUP="/var/lib/openshell-confidential/operator/fence-upgrade/$(date -u +%Y%m%d%H%M%S)-$NS"
install -d -m 0700 "$FENCE_BACKUP"
systemctl stop openshell-confidential-gateway.service openshell-confidential-driver.service
# Old role Pods AND their cloud guests must have retired before this point.
kubectl -n "$NS" get pods -l 'openshell.ai/boundary-role in (supervisor,workload)' -o json | \
  jq -e '.items | length == 0'
# Preserve/establish namespace ingress default-deny throughout the replacement.
kubectl create --dry-run=client -f deployment/openshell/network-fence.example.yaml -o json | \
  jq --arg ns "$NS" '.metadata.namespace=$ns' | kubectl apply -f -
kubectl -n "$NS" get networkpolicy confidential-ingress-default-deny -o json | \
  jq -e '.spec.podSelector == {} and (.spec.policyTypes | index("Ingress") != null) and ((.spec.ingress // []) | length == 0)'
kubectl -n "$NS" get networkpolicy -o json > "$FENCE_BACKUP/all-policies.before.json"
for name in openshell-sandbox-workloads openshell-sandbox-supervisors; do
  kubectl -n "$NS" get networkpolicy "$name" -o json > "$FENCE_BACKUP/$name.before.json"
  component=sandbox-workload-fence
  if test "$name" = openshell-sandbox-supervisors; then component=sandbox-supervisor-egress; fi
  jq -e --arg component "$component" \
    '.metadata.labels["openshell.ai/managed-by"] == "openshell" and
     .metadata.labels["openshell.ai/component"] == $component' "$FENCE_BACKUP/$name.before.json"
done
jq --argjson port "$BOUNDARY_PORT" '.spec = {
  podSelector:{matchLabels:{"openshell.ai/boundary-role":"workload"}},
  policyTypes:["Ingress","Egress"], egress:[],
  ingress:[{from:[{podSelector:{matchLabels:{"openshell.ai/boundary-role":"supervisor"}}}],
    ports:[{port:$port,protocol:"TCP"}]}]
}' "$FENCE_BACKUP/openshell-sandbox-workloads.before.json" > "$FENCE_BACKUP/workload.new.json"
jq '.spec = {
  podSelector:{matchLabels:{"openshell.ai/boundary-role":"supervisor"}},
  policyTypes:["Ingress","Egress"], ingress:[], egress:[{}]
}' "$FENCE_BACKUP/openshell-sandbox-supervisors.before.json" > "$FENCE_BACKUP/supervisor.new.json"
# Review the two spec diffs and effective union of every other selecting policy.
# replace preserves UID/resourceVersion preconditions; never use --force.
kubectl replace -f "$FENCE_BACKUP/workload.new.json"
kubectl replace -f "$FENCE_BACKUP/supervisor.new.json"
for name in openshell-sandbox-workloads openshell-sandbox-supervisors; do
  kubectl -n "$NS" get networkpolicy "$name" -o json > "$FENCE_BACKUP/$name.after.json"
done
python3.11 - "$FENCE_BACKUP" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for role, name in [('workload', 'openshell-sandbox-workloads'), ('supervisor', 'openshell-sandbox-supervisors')]:
    expected = json.loads((root / f'{role}.new.json').read_text())
    actual = json.loads((root / f'{name}.after.json').read_text())
    def normalized(spec):
        return {k: v for k, v in spec.items() if k not in ('ingress', 'egress') or v}
    assert actual['metadata']['uid'] == expected['metadata']['uid'], name
    assert normalized(actual['spec']) == normalized(expected['spec']), name
    for key, value in expected['metadata']['labels'].items():
        assert actual['metadata']['labels'][key] == value, (name, key)
PY
kubectl -n "$NS" get networkpolicy confidential-ingress-default-deny -o json | \
  jq -e '.spec.podSelector == {} and (.spec.policyTypes | index("Ingress") != null) and ((.spec.ingress // []) | length == 0)'
```

Keep admission stopped on failed ownership/readback/concurrency checks; inspect
saved specs without restoring an obsolete allow rule. Start driver then Gateway
only after the matching artifacts and prerequisites are installed. Confirm both
fences pass driver validation and real network denial before reopening admission;
preserve the original CR UID and workspace key while creating fresh role attempts.

## Renew the Gateway ServiceAccount credential

Use this when rotating or recovering the Secret-backed kubeconfig.
The bound token normally has no `exp`, but Secret/ServiceAccount or cluster-signing
changes can invalidate it. Inspect expiry without printing the token:

```sh
kubectl -n openshell get secret openshell-gateway-token -o json | \
  python3.11 -c 'import base64,json,sys,time; s=json.load(sys.stdin); t=base64.b64decode(s["data"]["token"]).decode(); c=json.loads(base64.urlsafe_b64decode(t.split(".")[1]+"==")); e=c.get("exp"); print("no exp claim" if e is None else time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(e)))'
```

Plan an interruption before invalidation/expiry. Stop both services, recreate only
the bound Secret, then repeat the token-population and `kubectl config set-*` steps in
[Gateway ServiceAccount kubeconfig setup](deployment.md#configure-the-gateway-serviceaccount-kubeconfig):

```sh
systemctl stop openshell-confidential-gateway.service openshell-confidential-driver.service
kubectl -n openshell delete secret openshell-gateway-token
kubectl apply -f deployment/openshell/gateway-rbac.yaml
```

After replacing the kubeconfig, require all five setup `auth can-i` checks and
Gateway preflight to pass before starting driver then Gateway. A short-lived
`kubectl create token` replacement requires automatic renewal and service restart
before expiry; it is not a drop-in static kubeconfig credential.
