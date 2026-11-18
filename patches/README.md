# Maintained patches

Builds use the exact upstream bases and result trees in
[sources.lock.json](../deployment/build/sources.lock.json).
[prepare-sources.sh](../deployment/build/prepare-sources.sh) replays each ordered
queue, verifies its checksums and result tree, and leaves `repos/` unchanged.

| Component | Queue | Scope |
| --- | --- | --- |
| CAA | [10 patches](cloud-api-adaptor/series) | Seven common fixes/features, two Alibaba disk integration patches, one measured workspace overlay |
| CSI | [5 patches](caa-csi-block-driver/series) | Capacity, mount properties, atomic publication, restart recovery, and an Alibaba provider |
| PeerPod controller | [1 shared CAA patch](peerpod-ctrl/series) | Exact instance absence after deletion errors |

Each component numbers patches consecutively within `generic`, `provider` and
`confidential-volume` categories. The controller references the CAA patch directly.
Common fixes and provider support remain separate from measured disk/key policy.

CSI uses the upstream combined DaemonSet, local volume store and cloud recovery.
Mount properties extend the existing metadata without requiring version labels.
The CSI CI workflow, conformance runner and Dockerfile use the upstream versions.
Sealed Secrets use native Kata/CDH unsealing and ordinary Kubernetes Secret mounts.

The APF target-hint [PR #3439](https://github.com/confidential-containers/cloud-api-adaptor/pull/3439)
was closed without merging. Its patch remains downstream; any renewed upstream
submission needs agreement on the approach.

Other CAA/CSI patches require separate upstream review of their prerequisites and
runtime contracts, including capacity, filesystem support, topology, version
skew and attachment identity. The measured workspace overlay remains a downstream
integration; its authorization and LUKS header handling have not become a shared
CDH/guest-components solution. DCO trailers do not establish upstream readiness.

Kata uses the official 4.4.0 release, including the upstream exec no-new-privileges fix.

Run the [offline suite](../tests/README.md) after changing a queue. Runtime
acceptance follows the [live validation procedure](../docs/live-acceptance.md).
