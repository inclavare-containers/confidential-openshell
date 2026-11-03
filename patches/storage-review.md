# Patch classification and review

The migration branch uses the exact bases in
[sources.lock.json](../deployment/build/sources.lock.json). Selection and validation
are tracked in [the CoCo migration record](../docs/coco-migration.md). The saved
main branch remains on the previously accepted release-based stack.

## Scope and submission rules

- `generic/` fixes or improves existing upstream behavior. These changes do not
  require the confidential-volume wire format or measured workspace policy.
- `provider/` supplies ordinary Alibaba disk/instance integration. These changes
  are useful for plain retained data disks as well as encrypted workspaces.
  New provider support is described as a feature, not an existing-upstream bug.
- `confidential-volume/` contains the paired metadata contract, measured disk/key
  authorization, initialization policy and sealed resources. This workstream
  waits for upstream storage design discussion.

A patch can have an implementation dependency without belonging to the same
workstream. The ordered `series` records build dependencies. Generic/provider
patches should be proposed separately; the confidential-volume contract is not
included merely to make a generic fix apply. New standalone upstream submissions
must reproduce their issue against the target upstream revision.

The CAA PeerPod controller is selected from the same upstream repository. Its
queue references the generic deletion fix and provider retention guard, without
copying attachment, metadata, or guest policy code.

## CAA queue

| Patch | Scope | Review and validation decision |
| --- | --- | --- |
| [generic/0001 image selection](cloud-api-adaptor/generic/0001-alibabacloud-image-overrides.patch) | Existing provider bug | Preserve the submitted #3437 patch verbatim. Two disk-size cases cover the two image assignment branches using one existing request recorder. |
| [generic/0002 on-link routes](cloud-api-adaptor/generic/0002-preserve-onlink-routes.patch) | Existing networking bug | Preserve the submitted #3435 patch verbatim. Extend the upstream worker/guest route tests. |
| [generic/0003 deletion absence](cloud-api-adaptor/generic/0003-alibabacloud-confirm-delete-absence.patch) | Existing instance cleanup | Accept only exact typed absence after a deletion error. Keep the shared result/error table; no disk enumeration is introduced. |
| [generic/0004 userdata](cloud-api-adaptor/generic/0004-alibabacloud-bounded-userdata.patch) | Transport enhancement | Host compression and guest bounded decompression travel together. Keep separate boundary tests and one byte-preservation check. |
| [generic/0005 credentials and diagnostics](cloud-api-adaptor/generic/0005-image-pull-credentials-and-diagnostics.patch) | Optional credential forwarding and reduced diagnostics | Preserve default behavior; test both forwarding modes and reuse existing TLS propagation tests. |
| [provider/0001 create retries](cloud-api-adaptor/provider/0001-alibabacloud-idempotent-create.patch) | Ordinary instance creation | Extracted from retained-disk attachment. Stable native ECS token, deterministic tags and checked response shape. Reuses the image patch's request recorder; the test-fixture dependency should be considered when submitting before #3437 merges. |
| [generic/0006 fsGroup](cloud-api-adaptor/generic/0006-recursive-fsgroup.patch) | Existing storage permissions | Extracted from encrypted mounting. Preserve owners, apply group access to retained contents and setgid to directories, skip symlinks and readonly requests, and propagate errors. Tests exercise real file permissions and inheritance. |
| [confidential-volume/0001 metadata](cloud-api-adaptor/confidential-volume/0001-immutable-metadata-contract.patch) | Paired CSI/CAA v1 contract | Immutable sandbox resolution and strict host/guest inputs. Use upstream Pod UID parsing before a lazy API lookup. Requires the matching CSI writer; generic readonly/immutability ideas must be extracted without forcing this schema upstream. |
| [provider/0002 retention guard](cloud-api-adaptor/provider/0002-alibabacloud-retained-delete-guard.patch) | Ordinary retained-disk safety | Shared by adapter and controller. Keep full inventory, retention/security-lock checks, retry-time rechecks and finalizer coverage. Multi-attach restrictions describe this provider profile, not a universal cloud API rule. |
| [provider/0003 ESSD attachment](cloud-api-adaptor/provider/0003-alibabacloud-retained-essd.patch) | New Alibaba data-disk support | Attachment/release reconciliation and bounded cleanup. Retain ambiguous-result, cancellation, timeout, rebinding and concurrent deletion tests; duplicate guard cases have been removed. Depends on the retention and creation helpers. |
| [provider/0004 guest identity](cloud-api-adaptor/provider/0004-alibabacloud-guest-disk-identity.patch) | New Alibaba device discovery | Match serial/WWID; reject ambiguous, partitioned, consumed and system devices. Host ID validation cannot replace guest device verification. |
| [confidential-volume/0002 workspace mounts](cloud-api-adaptor/confidential-volume/0002-measured-workspace-mounts.patch) | Measured persistent encryption | CDH opens existing encrypted devices; initialization is explicitly authorized by measured policy. Encrypted host annotations without measured workspace policy are rejected. Reuse upstream CDH protobuf types; no restoration of the reverted permissive CAA path. Keep ownership/rollback and readonly checks. |
| [confidential-volume/0003 sealed admission](cloud-api-adaptor/confidential-volume/0003-sealed-mount-admission.patch) | Measured sealed resources | Check descriptors before unsealing and container dispatch. Retain transaction-level rollback tests distinct from resource cleanup tests. The custom AA extension RPC, event encoder and their dedicated tests are removed; upstream AA now owns binding. |

## CSI queue

| Patch | Scope | Review and validation decision |
| --- | --- | --- |
| [generic/0001 capacity](caa-csi-block-driver/generic/0001-recovered-capacity.patch) | Existing CreateVolume bug | Validate cached and recovered actual capacity against the requested range. One table covers the two distinct paths and prevents persisting an incompatible result. |
| [provider/0001 Alibaba](caa-csi-block-driver/provider/0001-alibabacloud-essd.patch) | New ordinary provider | Reuse provider interfaces, tag recovery and SDK credential caching. No encryption key handling or second volume journal. |
| [confidential-volume/0001 metadata](caa-csi-block-driver/confidential-volume/0001-versioned-metadata.patch) | Paired v1 wire contract | Atomic publication, ownership and readonly/fsGroup metadata. Restart/replay coverage is consolidated. The atomic-write and restart fixes can be separately proposed against the old upstream format. |
| [generic/0002 deployment](caa-csi-block-driver/generic/0002-controller-node-deployment.patch) | Existing CSI deployment enhancement | Separate controller credentials/state from node publication. Helm generates the raw manifests. Alibaba values depend on the provider feature; neither deployment mode requires measured workspace policy. |
| [generic/0003 conformance](caa-csi-block-driver/generic/0003-conformance-runner.patch) | Existing test infrastructure | One runner and skip list for local/CI; cleanup is confined to its own temporary directory. The explicit test path adapter follows the node metadata contract. |
| [generic/0004 image bases](caa-csi-block-driver/generic/0004-build-runtime-bases.patch) | Build maintenance | Digest-pinned bases; verify actual builds rather than adding a Dockerfile text test. |

Kata's [no-new-privileges patch](kata-containers/0001-fix-runtime-preserve-exec-no-new-privileges.patch)
and the OpenShell pins are unchanged. The existing Kata conversion test remains
sufficient for that field-forwarding fix.

## Remaining intentional overlap

- CSI writer, host resolver and guest each validate their own trust boundary.
  A shared golden fixture connects the schemas without introducing another
  cross-repository library.
- CAA captures disk IDs for post-delete waiting and rechecks current inventory
  before every deletion attempt. Returning the checked inventory from the
  mutation helper could remove the first double read, but deleting a read alone
  loses recovery information or retry-time protection.
- Acquired/borrowed resource flags and cleanup retries represent different
  lifecycle states. They are retained, with one successful-cleanup test and
  separate reuse/failure-order cases.
- Required metadata and measured policy remain explicit. Successful use of
  `SecureMount` does not prove authenticated LUKS headers, ciphertext integrity
  or rollback protection; those are separate storage-design capabilities.

Validation does not use a target test-to-code line ratio. The migration reuses
upstream test fixtures and removes obsolete extension/host-path tests rather
than replacing upstream APIs with parallel implementations.
