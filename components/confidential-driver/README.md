# Confidential Kubernetes compute driver

This standalone binary implements the OpenShell v0.1.9 `ComputeDriver` contract for a
supervisor/workload pair running in attested Pod VMs. It is a controlled derivative of
NVIDIA's Kubernetes driver, with project-owned bootstrap publication and lifecycle
integration. See [source provenance](UPSTREAM.md), the
[pinned upstream README](../../repos/openshell/crates/openshell-driver-kubernetes/README.md),
and the [deployment runbook](../../docs/deployment.md).

| Code | Responsibility |
|---|---|
| Imported `config`, `grpc`, `lifecycle`, `otel_tracing`, `resource_admission` | Unchanged pinned upstream modules and their tests. |
| `sandbox_runtime.rs` | Upstream builders and tests, with a thin wrapper for guest-memory state, explicit guest-pull process groups and disabled service links. |
| `isolation.rs` | Upstream boundary provisioning and network policy. |
| `driver.rs`, `main.rs` | Local derivation integrating confidential admission, scheduling gates, Secret sealing, UID checks and lifecycle recovery. |
| `launch.rs`, `confidential.rs`, private `bootstrap.rs` | Project-owned measured initdata, signed resource descriptors, KBS publication, authorization bindings, workspace keys and durable journals. |

Both Pods require the configured confidential RuntimeClass and immutable image digests. The
driver verifies each admitted Pod against the launch template retained on T, generates
Kata policy from that trusted template, binds the policy and resource
URIs into SHA-384 of the raw initdata TOML, and checks the Pod UID, spec and annotation
again before gate release. Initdata includes role, namespace, Sandbox CR UID, bootstrap
generation and fresh attempt, and resource URIs. These fields are authorized through the measured document digest; a
host-supplied role field alone grants no access.

## Bootstrap resources

Each original bootstrap Secret value becomes a signed CDH vault descriptor before any
Kubernetes Secret write. The Secret names, keys and mounts remain compatible with native
runtime binaries. Kata uses its native Secret mount handling to invoke CDH inside
the guest. Released CoCo CDH 0.22 accepts the `sealed.<ES256 JWS>` vault descriptor;
its persistent host P-256 signer publishes the verification JWK at
`kbs:///default/bootstrap-signer/key`. The publisher retains desired resources and authorization in T's private
state, then uses authenticated KBS APIs to upload resources and update AS/KBS policy.
Each startup stages both roles' bootstrap files and the optional workspace key under one
lock, then invokes the publisher once before creating Kubernetes Secrets. A failed batch
withdraws its newly staged serving copies and bindings while retaining the private workspace
key and unchanged prior publications.
Its publication journal records requests before sending them, so retries can clean
up resources even after a successful upload's response is lost. Trustee storage
paths and filesystem ownership are not part of the driver interface. This
publication and recovery code belongs to this project.

User environment from the template and `--env` travels only in the workload's sealed
`boundary.json.child_env`. Native OpenShell applies it to workload child processes after
CDH unseals the file. Template values are overridden by sandbox values; accepted values,
including empty strings, are preserved. Native OpenShell API validation rejects newline
and carriage-return values. Kubernetes receives no user environment values in Pod env, the CR,
Secrets or generated policy. Only public driver-controlled `OPENSHELL_` runtime settings
remain in Pod env; reserved `OPENSHELL_` keys cannot set child environment. Policy admission
rejects user env or `envFrom` reintroduced into a role Pod.

The trusted store retains a mode-0600 environment record under `workload-environments/`,
bound to namespace and CR UID. Stop retains it; start uses it for the next sealed bootstrap
and fails if it is missing or invalid, rather than reading values from Kubernetes. Final
delete removes the matching environment record. Preserve this private state for restart.

The supervisor connects directly to the native Gateway HTTPS endpoint with the trusted host's
public CA and gateway-minted sandbox JWT released through its sealed bootstrap. User client
certificates and private keys stay outside both guests. The native
`supports_sandbox_authentication=true` capability is retained because Gateway also uses it to
persist the Kubernetes runtime identity needed by stop/start. In a confidential deployment,
`AuthenticateSandbox` rejects host-controlled ServiceAccount credentials before TokenReview or
any Kubernetes API access; the sealed launch JWT uses native refresh.

The Kubernetes runtime identity binds namespace, CR UID and supervisor Pod UID. Restart keeps
the original CR/PVC ownership, requires that persisted binding, and creates a fresh bootstrap
attempt and new role Pods. Native JWT `runtime_generation` remains stable across stop/start
while `auth_epoch` and token identity rotate. The driver bootstrap-generation field in
initdata is separate from that JWT identity; it must not be treated as a guarantee of
credential rotation.

Persistent workspaces use one private 32-byte key for the namespace and Sandbox CR UID. Owner
and PVC/PV/cloud-disk journals are recorded before release and support recovery after CR
deletion. A measured initializer formats a new LUKS volume with stock cryptsetup; released CDH
SecureMount reopens it. Only the first creation permits blank-disk initialization; restart
refuses it. Before mounting, APF checks the active kernel mapping for LUKS2,
AES-XTS with a 512-bit key and 4096-byte sectors. Ephemeral workloads receive no workspace
key or encrypted-volume manifest. The driver verifies their admitted Pod against the trusted
launch template, and the measured Kata policy constrains its mounts. Explicit delete first
withdraws every T-owned authorization for that sandbox, even if Kubernetes is unavailable.
Cleanup records a durable UID-specific marker, issues UID-preconditioned deletion, and
succeeds only after the CR and both role Pods are absent. A
replaced CR or Secret is not adopted for cleanup. Failed revocation remains retryable.

Stop/delete remove serving copies and authorization while retaining the private workspace key
and volume journal. This is access withdrawal, not automatic cryptographic erasure of retained
disks or host recovery material. KBS revocation also cannot erase secrets already delivered to
a running guest. Stop/delete terminate the role Pods; native epoch/token checks reject later
authentication, while already-open streams require runtime termination.

Supervisor sockets, TLS state and logs use guest-memory EmptyDir volumes, with explicit
UID/GID, fsGroup and `supplementalGroups: [0]` for guest pull, and no service-link
environment injection. These volumes consume guest memory. The default OCI spec version is `1.3.0`; set
`OPENSHELL_KATA_OCI_VERSION` to match another runtime. KBS and registry trust roots are configured independently in measured AA/CDH
configuration before resource retrieval and image pulls. Registry pulls use system trust roots;
an optional `--kata-policy-registry-ca` file adds certificates while preserving the base
CDH configuration's extra roots. `REGISTRY_CA` supplies the deployment default, and an empty
value selects system roots without adding a certificate.

The [driver service](../../deployment/openshell/openshell-confidential-driver.service) shows
the required operator paths and configuration. `OPENSHELL_COMPUTE_DRIVER_SOCKET` carries the
private Gateway/driver connection, and `OPENSHELL_GRPC_ENDPOINT` selects the direct HTTPS
endpoint verified using `OPENSHELL_CONFIDENTIAL_CLIENT_TLS_CA`. Run one driver writer
and keep its signer, private environment records and journals on T.

Run `cargo test -p openshell-driver-confidential-kubernetes` for driver, imported upstream and
bootstrap tests. Use the
[deployment checks](../../docs/deployment.md#10-verify-both-confidential-roles) for hardware
attestation, CDH unseal, KBS release and lifecycle behavior.

Restart uses the private launch template, command and identity, not CR annotations.
Stop and explicit delete withdraw authorization from T-owned attempt/owner records before
waiting for Kubernetes. Failed remote revocation remains pending and is retried at
startup and during reconciliation; failure is not reported as successful withdrawal.
Busy lifecycle gates are skipped by background reconciliation and revisited later.

Create and restart share generation installation and release checks. Restart rebuilds the
bootstrap init container from the current trusted runtime image configuration while retaining
the saved business container image and command. Lifecycle serialization uses the deployed
single driver's shared gates and durable trusted attempt records; Kubernetes attempt
annotations do not elect a writer or authorize secret publication. Completed revocations are
no-ops, and interrupted batches retry one policy publication before retiring their markers.
