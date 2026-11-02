# Upstream bases and controlled patches

The submodule gitlinks point to unmodified upstream commits. Build copies apply
the following local patch queues; the main runtime therefore includes patched
components. Exact bases and result trees are authoritative in the
[source lock](../deployment/build/sources.lock.json).

| Component | Ordered series | Required behavior |
| --- | --- | --- |
| CAA | [10 patches](cloud-api-adaptor/series) | Immutable direct-volume metadata; Alibaba VPC and retained ESSD attachment/deletion; bounded userdata and host credential exclusion; guest disk discovery, stock CDH encrypted-device unlock, a measured embedded-LUKS initializer, sealed mounts and on-link Pod routes |
| CSI | [5 patches](caa-csi-block-driver/series) | Alibaba ESSD through existing provider interfaces; atomic v1 metadata and delegated fsGroup for the paired CAA; separate controller/node deployment; shared conformance runner and pinned build/runtime bases |
| PeerPod controller | [1 independent backport](peerpod-ctrl/README.md) | Confirm exact instance absence after an otherwise unhandled Alibaba deletion failure, preserving other errors and existing IAM scope |
| Kata host Go shim | [1 patch](kata-containers/README.md) | Preserve `NoNewPrivileges` in exec requests; use the released guest agent and genpolicy unchanged |

Build copies are prepared by `deployment/build/prepare-sources.sh` from local
pinned upstream objects and the explicit `series` order. The helper verifies
SHA256SUMS and the resulting Git tree. It refuses to overwrite an existing build
copy. `repos/` stays at the clean upstream base. No upstream versions change.

The [build guide](../docs/build.md) is the single source-preparation, binary/container
and Kata-packaging route. Follow the [deployment runbook](../docs/deployment.md) for
installation. Exact bases and result trees are in the source lock.
CAA's sealed-volume path verifies the measured descriptor digest and successful
CDH unsealing before exposing a private read-only mount; worker-provided plaintext
cannot substitute for an attested release. CSI owns disk lifecycle metadata and
does not handle workspace plaintext keys. The independent controller build uses
only its own queue, rather than the CAA adapter queue.

Generic fixes can be removed after the selected upstream version supplies their
behavior and the corresponding acceptance checks pass. When guest inputs change,
rebuild the image and extract its references together.

The local CSI build uses one paired v1 metadata contract. It does not carry the
legacy writer, format-migration switches, a pending-create journal, additional
provider interfaces or a separate credential-refresh coordinator. Completed
volume records and tag recovery use the pinned upstream implementation. Alibaba
storage is scoped by cluster/driver tags and uses ESSD PL0. Disk creation carries a stable
cluster/volume ClientToken. Per-RPC providers share the SDK credential object so its native
refresh cache survives; credential identity remains the controller process configuration.
The Alibaba profile omits the unused resizer, while upstream provider profiles retain it.

CAA uses ECS ClientToken for instance-create retries and queries current cloud
attachments during deletion instead of maintaining a second operation/attachment
journal. Guest disk discovery uses the same kernel serial/WWID identities as the
measured workspace initializer. Disk-retention checks, measured disk/key binding,
encrypted-mount validation and sealed-resource verification remain required.

The Kata and independent PeerPod controller queues remain narrow fixes: dropping
them would respectively break no-new-privileges exec requests and exact-instance
cleanup after a tag-conditioned deletion race. OpenShell's v0.1.6 source imports
and existing confidential wrappers remain pinned; no upstream release is rolled
back by this simplification.

The initdata transport uses upstream cloud-config generation. The guest strips only outer
base64 transport CR/LF before strict decoding; decoded TOML and its SHA-384 measurement
remain byte-for-byte unchanged. The native AA adapter retains the published ttrpc subset:
it uses the existing protobuf/ttrpc dependencies without vendoring a generated protocol
library. AA performs the actual
measurement; canonical eventlog checks prevent duplicate extension.

Patch authorship is retained. AI-attributed sign-off lines are removed; these local overlays
do not substitute for a contributor's DCO certification when submitting upstream.
