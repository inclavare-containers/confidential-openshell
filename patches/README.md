# Maintained patches

Builds use the exact upstream bases and result trees in
[sources.lock.json](../deployment/build/sources.lock.json).
[prepare-sources.sh](../deployment/build/prepare-sources.sh) replays each ordered
queue, verifies its checksums and result tree, and leaves `repos/` unchanged.

| Component | Queue | Scope |
| --- | --- | --- |
| CAA | [12 patches](cloud-api-adaptor/series) | Nine common fixes/features, two Alibaba disk integration patches, one measured workspace overlay |
| CSI | [4 patches](caa-csi-block-driver/series) | Capacity, mount properties, atomic publication/replay, and an Alibaba provider |
| PeerPod controller | [1 shared CAA patch](peerpod-ctrl/series) | Exact instance absence after deletion errors |
| Kata host shim | [1 patch](kata-containers/series) | Exec no-new-privileges fix, merged upstream and retained for the selected base |

Each component numbers patches consecutively within `generic`, `provider` and
`confidential-volume` categories. The controller references the CAA patch directly.
Common fixes and provider support remain separate from measured disk/key policy.

CSI uses the upstream combined DaemonSet, local volume store and cloud recovery.
Mount properties extend the existing metadata without requiring version labels.
The CSI CI workflow, conformance runner and Dockerfile use the upstream versions.
Sealed Secrets use native Kata/CDH unsealing and ordinary Kubernetes Secret mounts.

CAA's [on-link route fix (#3435)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3435)
is open. The [image selection fix (#3437)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3437)
is merged upstream and retained for the selected base. Both patches retain their
submitted code diffs.

The APF target-hint [PR #3439](https://github.com/confidential-containers/cloud-api-adaptor/pull/3439)
was closed without merging. Its patch remains downstream; any renewed upstream
submission needs agreement on the approach.

Other CAA/CSI patches require separate upstream review of their prerequisites and
runtime contracts, including capacity, filesystem support, topology, version
skew and attachment identity. The measured workspace overlay remains a downstream
integration; its authorization and LUKS header handling have not become a shared
CDH/guest-components solution. DCO trailers do not establish upstream readiness.

All 17 patch files carry their human author's `Signed-off-by` trailer. CAA/CSI patches use
`Co-authored-by: Codex <noreply@openai.com>`; Kata uses
`Assisted-by: OpenAI Codex <noreply@openai.com>`.

Run the [offline suite](../tests/README.md) after changing a queue. Runtime
acceptance follows the [live validation procedure](../docs/live-acceptance.md).
