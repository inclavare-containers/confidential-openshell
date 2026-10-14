# Upstream bases and controlled patches

The submodule gitlinks point to unmodified upstream commits. Build copies apply
the following local patch queues; the main runtime therefore includes patched
components. Exact bases and result trees are authoritative in the
[source lock](../deployment/build/sources.lock.json).

| Component | Ordered series | Required behavior |
| --- | --- | --- |
| CAA | [11 patches](cloud-api-adaptor/series) | Immutable direct-volume metadata; Alibaba VPC and retained ESSD operations; bounded userdata and host credential exclusion; guest disk discovery, stock CDH encrypted-device unlock, a measured embedded-LUKS initializer, sealed mounts and on-link Pod routes |
| CSI | [5 patches](caa-csi-block-driver/series) | Atomic direct-volume metadata, durable volume-create journal, Alibaba ESSD operations, delegated fsGroup and pinned runtime base |
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
See [upgrade and retention](../docs/upgrade.md).
