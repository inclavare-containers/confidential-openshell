# Upstream bases and maintained patches

Builds use the exact bases and result trees in
[sources.lock.json](../deployment/build/sources.lock.json). `repos/` stays at the
unmodified upstream inputs; [prepare-sources.sh](../deployment/build/prepare-sources.sh)
replays each ordered queue and verifies its checksum and result tree.

| Component | Queue | Scope |
| --- | --- | --- |
| CAA | [17 patches](cloud-api-adaptor/series) | Eleven common fixes/features, four Alibaba disk integration patches, two measured guest overlays |
| CSI | [6 patches](caa-csi-block-driver/series) | Five common fixes/features and one Alibaba provider; no confidential-volume metadata schema |
| PeerPod controller | [3 shared CAA patches](peerpod-ctrl/series) | Exact absence, deletion completion and retained-disk guard |
| Kata host shim | [1 patch](kata-containers/0001-fix-runtime-preserve-exec-no-new-privileges.patch) | Already merged upstream; retained for the selected base |

The [review ledger](storage-review.md) identifies each patch's single purpose,
evidence, dependencies and validation. It is the starting point for discussing
the final queue. Ordinary metadata, filesystem access and lifecycle handling are
separate from measured disk/key authorization and sealed-resource admission.
The PeerPod controller references CAA files rather than duplicating them.

The code diffs of CAA [on-link routes (#3435)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3435)
and [image selection (#3437)](https://github.com/confidential-containers/cloud-api-adaptor/pull/3437)
are unchanged. Their local mail-patch attribution trailers were normalized;
transport checksums therefore differ from earlier copies. No remote PR was
rewritten during this cleanup.

CSI preserves the upstream combined DaemonSet, local completed-volume store and
cloud tag recovery. Mount properties and atomic publication extend ordinary CSI
behavior; old metadata remains readable without mandatory version/mode labels or
an explicit readonly field. No controller state PVC, custom pending-create
journal, role split or production test-path switch is introduced.

The deployment pulls registry images anonymously, with HTTPS certificate checks
and digest pinning. CAA uses its upstream image-pull Secret behavior; the local
opt-out and diagnostic-suppression overlay have been removed. The separate CAA
instance-create idempotency overlay and its additional tag/checks have also been
removed. CSI's provider disk-create token is part of its distinct provisioning
implementation and is not that removed CAA overlay.

For upstream work, common fixes must reproduce against the intended target and
be submitted with only their actual prerequisites. fsGroup is prioritized near
the front; its end-to-end field path is documented separately from its ownership
implementation. The confidential guest overlays remain a separate design topic.
Full ACK/TDX validation is deferred until the patch review converges; the current
cleanup uses replay, compilation and targeted regression checks.

Patch authors and existing human DCO sign-offs are preserved. CAA/CSI patches use
`Co-authored-by: Codex <noreply@openai.com>`, following
[Codex's attribution form](https://github.com/openai/codex/blob/e4a3612/codex-rs/core/src/commit_attribution.rs)
and community co-author practice. Kata uses
`Assisted-by: OpenAI Codex <noreply@openai.com>`, following the
[OpenInfra policy](https://openinfra.org/legal/ai-policy/) and
[Kata precedent](https://github.com/kata-containers/kata-containers/commit/5b9ad3c7d792156da177c1cb60465a0dec7fae55).
AI attribution is separate from human DCO. Top-level repository commits retain
the repository's ordinary subject/body style; the tool attribution lives in the
maintained patch messages.
