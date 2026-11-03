# Upstream bases and controlled patches

The submodule gitlinks point to unmodified upstream commits. Build copies apply
the following local patch queues; the main runtime therefore includes patched
components. Exact bases and result trees are authoritative in the
[source lock](../deployment/build/sources.lock.json).

| Component | Ordered series | Required behavior |
| --- | --- | --- |
| CAA | [11 patches](cloud-api-adaptor/series) | Separate generic instance-deletion handling and retained-disk protection; immutable direct-volume metadata; Alibaba per-instance image selection and retained ESSD attachment/deletion; bounded userdata, optional image-pull credential forwarding and reduced diagnostic output; guest disk discovery, stock CDH encrypted-device unlock, a measured embedded-LUKS initializer, sealed mounts and on-link Pod routes |
| CSI | [6 patches](caa-csi-block-driver/series) | Capacity validation for recovered disks; Alibaba ESSD through existing provider interfaces; atomic v1 metadata and delegated fsGroup for the paired CAA; separate controller/node deployment; shared conformance runner and pinned build/runtime bases |
| PeerPod controller | [2 CAA patches](peerpod-ctrl/README.md) | Apply the same generic deletion fix and retained-volume protection used by CAA |
| Kata host Go shim | [1 patch](kata-containers/README.md) | Preserve `NoNewPrivileges` in exec requests; use the released guest agent and genpolicy unchanged |

Build copies are prepared by `deployment/build/prepare-sources.sh` from local
pinned upstream objects and the explicit `series` order. The helper verifies
SHA256SUMS and the resulting Git tree. It refuses to overwrite an existing build
copy. Patches are owned by their upstream repository: the PeerPod controller
queue references two files in `cloud-api-adaptor/`, because both binaries belong
to CAA. The controller does not inherit attachment or guest code. `repos/` stays at
the clean upstream base. No upstream versions change.

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

The [classification and review ledger](storage-review.md) distinguishes two
storage workstreams: confidential-volume additions awaiting design discussion,
and fixes/enhancements to storage behavior already present upstream. Mixed patches
identify both parts explicitly; their generic portions need separate extraction
before submission. Other generic changes are listed separately. A dependency on
an existing CDH or CSI API does not make the whole confidential-volume profile a
generic bug fix.

The CAA queue carries the submitted patches for
[on-link routes (#3435)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3435)
at `e32c515ef83987587241170514f337c6f847958c` and
[per-instance image selection (#3437)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3437)
at `e72ea9828161bc9dad15568871979d239354d28d` verbatim. The retained-disk
patch builds on the image fix instead of carrying a second copy.

The former explicit-VPC overlay bypassed discovery in restricted environments.
CAA now uses the pinned upstream vSwitch discovery path, as the independent
PeerPod controller already does. The maintained
[RAM policy](../deployment/ack/ram/caa-permissions.example.json) grants
`vpc:DescribeVSwitchAttributes` on the configured vSwitch; generated PeerPods
values no longer supply the overlay-only `VPC_ID` setting.

The measured workspace and sealed-volume/TDX patches are product overlays, not
claims of generic upstream behavior. Their per-request disk, key and descriptor
authorization remains in the measured guest. Moving constants into deployment
configuration would not replace these checks. A future Kata Storage migration
must cover filesystem flags, recursive fsGroup, readonly replay and shared mount
cleanup before removing the current layer. Likewise, PodInfoOnMount alone does
not supply identity to NodeUnpublishVolume; the existing ownership checks remain.
Helm is the source for CSI raw manifests, which are retained for the upstream
installation interface and regenerated together. The node requires privileged
mode for its current bidirectional mount propagation.

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

The Kata queue fixes no-new-privileges exec requests. The independent PeerPod
controller queue contains both the generic exact-instance cleanup fix and the
retained-volume protection profile; the latter belongs to the confidential-volume
workstream. OpenShell's v0.1.6 source imports
and existing confidential wrappers remain pinned; no upstream release is rolled
back by this simplification.

The initdata transport uses upstream cloud-config generation. The guest strips only outer
base64 transport CR/LF before strict decoding; decoded TOML and its SHA-384 measurement
remain byte-for-byte unchanged. The native AA adapter retains the published ttrpc subset:
it uses the existing protobuf/ttrpc dependencies without vendoring a generated protocol
library. AA performs the actual
measurement; canonical eventlog checks prevent duplicate extension.

Local patch commits use `Weidong Sun <sunweidong@linux.alibaba.com>` as their author,
with scoped subjects and a rationale for the complete change. Existing sign-offs
are retained, and AI assistance is recorded in `Generated-by` trailers. Metadata
normalization is separate from the reviewed code/test changes; upstream submission still
uses the target project's contribution and DCO requirements.
