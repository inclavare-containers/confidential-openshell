# Patch review ledger

This ledger describes the rebuilt queues, not a list of pending edits. Bases and
result trees are in [sources.lock.json](../deployment/build/sources.lock.json).
Each row names the behavior covered by one patch. Tests follow that behavior;
shared prerequisites are explicit rather than copied into later patches.

## CAA common changes

These patches apply before Alibaba data-disk support and measured guest policy.
The common prefix is compiled and tested independently of those overlays.

| Patch | Concrete purpose and evidence | Dependency / targeted check |
| --- | --- | --- |
| [G01 image selection](cloud-api-adaptor/generic/0001-alibabacloud-image-overrides.patch) | Honor the per-instance image in both system-disk branches; existing PR #3437 code diff unchanged. | Upstream request recorder, two image branches. |
| [G02 on-link routes](cloud-api-adaptor/generic/0002-preserve-onlink-routes.patch) | Preserve link-scope routes across worker/guest conversion; existing PR #3435 code diff unchanged. | Existing worker and guest route tests. |
| [G03 fsGroup access](cloud-api-adaptor/generic/0003-volume-group-access.patch) | Fix Go setgid usage and apply group access to retained contents without changing owners or following symlinks. Real file/process comparison reproduces wrong inherited group and inaccessible retained files before the change. | Existing guest mount path; real ownership/inheritance and readonly tests. G07 supplies the ordinary CSI property path. Prioritized for upstream. |
| [G04 exact delete absence](cloud-api-adaptor/generic/0004-alibabacloud-confirm-delete-absence.patch) | After a deletion error, accept only typed absence of that exact instance; other errors remain errors. | No disk feature; API result/error table. |
| [G05 userdata transport](cloud-api-adaptor/generic/0005-alibabacloud-bounded-userdata.patch) | Compress oversized userdata and bound guest decompression. Host and guest agree on the 1 MiB decoded limit, preventing a host-accepted payload from being rejected only after VM creation. | Host encode and guest decode boundary tests; unrelated cloud-config test removed. |
| [G06 Pod disk selection](cloud-api-adaptor/generic/0006-resolve-csi-pod-identity.patch) | Resolve missing Pod UID before filtering direct volumes. The selected Kata request lacks that UID; an unmodified upstream reproducer selected both Pods' disks instead of only the requested Pod's. | Existing UID parser; lazy API lookup and two-Pod fixture. No new metadata schema. |
| [G07 mount properties](cloud-api-adaptor/generic/0007-volume-mount-properties.patch) | Carry and apply readonly, mount options and fsGroup through the existing CSI→proxy→guest path. Old records without readonly remain readable. | G03/G06; CSI mount-property producer. Typed transport and filesystem/bind option tests. |
| [G08 attachment mapping](cloud-api-adaptor/generic/0008-reuse-sandbox-volume-plan.patch) | Read direct-volume records once and reuse their disk/LUN mapping for containers. Bound those reads; preserve legacy cloud-volume-path and optional Pod UID. Unrelated CSI mounts follow upstream forwarding. | G06/G07; changed/deleted metadata, container subsets, legacy records and property propagation. Mutation tests, not a claimed wrong-disk production incident. |
| [G09 deletion completion](cloud-api-adaptor/generic/0009-alibabacloud-delete-completion.patch) | Reconcile accepted/ambiguous instance deletion until exact absence, with bounded cancellation and documented transition retries. | G04 only; independently tested without retained disks. |
| [G10 guest mount lifecycle](cloud-api-adaptor/generic/0010-guest-volume-lifecycle.patch) | Track acquired versus reused ordinary mounts; roll back on preparation/agent failure and retain failed cleanup for retry. Use the existing containerd mount implementation and verify reused mounts. | G07/G08; ordinary rollback, reuse, filesystem identity, optional loop-device tests. No key, CDH or measured policy. |
| [G11 dialer test fixture](cloud-api-adaptor/generic/0011-proxy-dialer-test-fixture.patch) | Synchronize the existing listener-reopen test and close the correct handles. | Test-only repair; isolated from volume mapping, checked under the race detector. |

## CAA provider changes

These are ordinary Alibaba data-disk capabilities, useful without encryption.

| Patch | Concrete purpose | Dependency / targeted check |
| --- | --- | --- |
| [P01 deletion guard](cloud-api-adaptor/provider/0001-alibabacloud-retained-delete-guard.patch) | Inspect retention attributes and security locks before every instance deletion attempt. Share the guard with the controller. | G04/G09; incomplete/unsafe inventory and finalizer retry tests. |
| [P02 retained release](cloud-api-adaptor/provider/0002-alibabacloud-retained-release.patch) | Wait for retained disks to be released after instance deletion, accepting absence or rebinding to another instance. | P01 inventory; timeout, cancellation and rebound tests. |
| [P03 retained attachment](cloud-api-adaptor/provider/0003-alibabacloud-retained-attachment.patch) | Validate and attach supported retained ESSD disks, reconciling ambiguous attach responses. | P01 disk parser; fake SDK request/state tests. No instance-create token. |
| [P04 guest disk identity](cloud-api-adaptor/provider/0004-alibabacloud-guest-disk-identity.patch) | Resolve Alibaba disk IDs using kernel serial/WWID; reject ambiguous, partitioned and system-backing devices. Permit mounted data disks for reuse. | G10; kernel fixture tests. This establishes device identity, not measured authorization. |

## CAA confidential guest overlays

| Patch | Concrete purpose | Dependency / targeted check |
| --- | --- | --- |
| [C01 measured workspace](cloud-api-adaptor/confidential-volume/0001-measured-workspace.patch) | Authorize disk/key/filesystem and optional initialization from measured policy. Use upstream CDH to open LUKS devices; enforce mapper parameters/readonly and extend ordinary ownership tracking to mapper resources. | G10/P04; policy, initialization, mapper and cleanup-order tests. Host annotations cannot choose the key. |
| [C02 sealed admission](cloud-api-adaptor/confidential-volume/0002-sealed-admission.patch) | Verify manifest-named descriptors, unseal through CDH and expose only private verified outputs before agent dispatch. | C01 CDH client, G10 rollback; descriptor tampering, confined symlinks, FIFO, cleanup and sealed-rejection tests. Ordinary volume rollback remains in G10. |

CAA's ordinary mounts do not automatically invoke Kata `Storage` ownership.
The selected Kata sealed-file path logs unseal errors and continues; it cannot
replace mandatory descriptor admission. CDH's selected filesystem path ignores
mount flags, so C01 requests an opened device and enforces access modes locally.
These are specific API/behavior differences, not a reason to fold generic fixes
into the confidential overlays. Sealed admission stays after volume rewriting so
later rewriting cannot replace a verified source.

## CSI changes

CSI has no confidential-volume patch. Its metadata contains ordinary mount and
ownership information, never workspace plaintext keys.

| Patch | Concrete purpose | Targeted check |
| --- | --- | --- |
| [G01 capacity](caa-csi-block-driver/generic/0001-recovered-capacity.patch) | Validate actual cached/recovered capacity against CreateVolume's requested range. | Shared table for both paths. |
| [G02 mount properties](caa-csi-block-driver/generic/0002-volume-mount-properties.patch) | Publish readonly/options/fsGroup and advertise delegated group handling. | Existing NodePublish fixtures, including ro options. |
| [G03 atomic publication](caa-csi-block-driver/generic/0003-atomic-volume-publication.patch) | Publish complete metadata atomically; preserve restart identity and verify volume ownership on reuse/unpublish. | Legacy republish, wrong-volume unpublish and atomic/restart tests. Version/mode labels are not required. |
| [G04 conformance runner](caa-csi-block-driver/generic/0004-conformance-runner.patch) | Share the upstream CSI sanity invocation between local runs and CI. | Existing runner with normal PodInfoOnMount context; no production test-path switch. |
| [G05 build bases](caa-csi-block-driver/generic/0005-build-runtime-bases.patch) | Pin compatible build/runtime images. | Source/build configuration checks; no Dockerfile-text test. |
| [P01 Alibaba ESSD](caa-csi-block-driver/provider/0001-alibabacloud-essd.patch) | Add the provider through upstream interfaces, cloud recovery and SDK credential caching, with combined-DaemonSet configuration. | Provider tests; no controller state PVC, service split or operation journal. |

## Removed and retained boundaries

- Removed the image-pull Secret opt-out, its test hook and deployment flag, plus
  the bundled debug-copy/log-suppression changes. Registry pulls are anonymous;
  HTTPS certificate verification and image digest pinning remain.
- Removed the complete CAA instance-create idempotency patch, including its
  extra SandboxId tag, validation/error changes and dedicated test. It was an
  optional retry enhancement without a reproduced current deployment blocker.
- Removed mandatory transport-version/mode/readonly labels. CAA and CSI retain
  compatibility with original upstream mount records and the old fixture.
- Removed Kata's historical PR prose, captured evidence and contribution scripts.
  Only its patch, series and checksum remain. The upstream change is merged.
- OpenShell/Kata bases are unchanged. Existing CAA #3435/#3437 code diffs are
  unchanged; only local attribution metadata is normalized.

## Validation and next review

Validation for this cleanup is deliberately local and targeted: clean patch
replay/checksums/tree equality, each extracted stage's package tests, independent
common-prefix tests, final CAA host/guest race tests and binary compilation, CSI
package tests, controller finalizer tests and Kata's existing conversion test.
The maintained documentation and deployment-value generator are also checked.
No new ACK/TDX deployment, cloud fault experiment or full end-to-end run is claimed.
Those checks follow review convergence.

The repository's three iterative cleanup commits are consolidated after the
unchanged CoCo migration commits. Top-level commits use the original scoped
subject/body convention. Patch attribution follows the
[community-specific conventions](README.md) and stays inside patch messages.
