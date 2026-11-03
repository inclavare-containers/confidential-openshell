# Patch classification and review

Reviewed on 2026-11-03 against the exact upstream bases in
[sources.lock.json](../deployment/build/sources.lock.json): CAA
`e3e0f00480b41c08e3e4dbc6b64aba7722fb65f9` and CSI
`aa4e40abeab760240569979680bc985c86783ce8`. The classification describes the local
changes relative to those bases; it is not a claim of upstream acceptance.

## Workstreams

| Class | Scope | Upstream treatment |
| --- | --- | --- |
| A — confidential-volume additions | New capabilities used by our persistent encrypted-disk and sealed-volume design, including the paired metadata contract and Alibaba disk integration | Keep locally while the upstream storage design discussion stabilizes. New provider support can be proposed separately, but must be described as a feature, not an existing-upstream bug fix. |
| B — existing storage fixes and enhancements | Corrections or improvements to disk lifecycle, direct-volume metadata, mounting, or CSI deployment already present upstream | Extract small changes against the existing upstream contract, with a concrete reproduction and focused regression coverage. These need not wait for the confidential-volume design. |
| C — other generic changes | Instance lifecycle, networking, credentials/diagnostics, transport, and build/runtime maintenance | Review independently of the storage design. |

Mixed patches remain marked with both classes below. A generic fix embedded in a
profile patch is a candidate for extraction, not a reason to submit the complete
profile as a bug fix. In particular, upstream already has `mountInfo.json`,
`CloudVolumeAnnotation`, CDH `secureMount`, and fsGroup handling. Their presence
does not imply that upstream already supports our v1 schema, measured workspace
authorization, or first-use initialization policy.

The existing upstream paths can be inspected in
[CAA direct-volume parsing](https://github.com/confidential-containers/cloud-api-adaptor/blob/e3e0f00480b41c08e3e4dbc6b64aba7722fb65f9/src/cloud-api-adaptor/pkg/util/cloud.go),
[container annotation construction](https://github.com/confidential-containers/cloud-api-adaptor/blob/e3e0f00480b41c08e3e4dbc6b64aba7722fb65f9/src/cloud-api-adaptor/pkg/adaptor/proxy/service.go),
[guest mounting](https://github.com/confidential-containers/cloud-api-adaptor/blob/e3e0f00480b41c08e3e4dbc6b64aba7722fb65f9/src/cloud-api-adaptor/pkg/forwarder/interceptor/interceptor.go),
and the clean CSI checkout under `repos/caa-csi-block-driver`.

## CAA, including the PeerPod controller

Patch files belong to the CAA upstream repository. The controller's
[series](peerpod-ctrl/series) selects 0001a and 0001b from that directory; it is
not a separate upstream project or a third classification called “shared”.

| Patch | Class and boundary | Code and test review |
| --- | --- | --- |
| [0001a — deletion absence](cloud-api-adaptor/0001a-alibabacloud-confirm-instance-absence-after-delete-errors.patch) | **C.** Existing `DeleteInstance` error handling: confirm exact absence after a failed deletion and preserve other errors. | Split from the former shared patch. The common deletion helper carries no disk inventory logic or `DescribeDisks` requirement. Keep the table covering success, exact not-found, denied/ambiguous deletion, and failed or inconclusive reads; these distinguish errors that must not clear a finalizer. The same table now remains available in both builds. |
| [0001b — retained-disk protection](cloud-api-adaptor/0001b-alibabacloud-protect-retained-disks-before-instance-deletion.patch) | **A.** Our retained-volume profile: inspect attached disks, require retention settings, and reject security locks before mutation. | Keep protection in both deletion entry points. Preserve the retry-time recheck and the controller finalizer regression. The guard table is the single home for the repeated security-lock and missing/true retention-attribute cases. Detachability and multi-attach restrictions are profile constraints, not universal CAA deletion requirements. |
| [0002 — immutable volume plans](cloud-api-adaptor/0002-volumes-preserve-immutable-direct-volume-mount-plans.patch) | **B:** resolve disk identity once per sandbox, prevent later host metadata changes from altering the mount plan, preserve readonly/options, and isolate by Pod UID. **A:** require the paired v1 metadata schema and its additional identity fields. | Keep a parser test matrix and a small number of proxy integration cases: decoding, immutable resolution, and propagation exercise different boundaries. Independent option slices prevent callers from changing the cached plan. Generic fixes must be extracted against the upstream metadata format; the full patch is not independently compatible with an unmodified CSI writer. |
| [0003 — per-instance image override](cloud-api-adaptor/0003-alibabacloud-keep-image-overrides-local-to-each-instance.patch) | **C.** Existing provider configuration mutation bug. | Keep the submitted patch byte-for-byte. The existing fake and two disk-size cases exercise the separate image assignment branches; no additional test scaffold is needed. |
| [0004 — Alibaba retained ESSD attachment](cloud-api-adaptor/0004-alibabacloud-attach-and-retain-ESSD-data-disks.patch) | **A:** new Alibaba data-disk attachment, retained-disk release waiting, and attachment reconciliation. **C:** native instance ClientToken, cancellation, and deletion transition handling embedded in the same patch. | Keep cloud discovery after provider restart, ambiguous mutation reconciliation, timeout/cancellation, rebinding, and concurrent cleanup coverage. Remove five redundant test functions and two duplicate retention cases; move the discovery assertion into the existing delete-and-wait test. Reuse the generic deletion helper and preserve its tests instead of deleting them later in the queue. Generic retry/idempotency changes need separate extraction before submission. |
| [0005 — Alibaba guest disk identity](cloud-api-adaptor/0005-guest-resolve-Alibaba-disks-by-their-measured-identities.patch) | **A.** New Alibaba serial/WWID resolution used by the retained-volume path; it is provider support rather than a fix to pre-existing Alibaba data-disk support. | Keep whole-disk, partition/root backing-device, ambiguous identity, and consumed-prefix cases. These reject different wrong-device selections. Host disk IDs and guest kernel identities cross a trust boundary, so validation in both places is intentional. |
| [0006 — encrypted mounting through CDH](cloud-api-adaptor/0006-guest-mount-retained-encrypted-volumes-through-CDH.patch) | **B:** existing CDH mount readonly/options, mount reuse validation, ownership-aware rollback, and recursive fsGroup handling. **A:** measured disk/key authorization, optional first-use initializer, and fixed LUKS2/AES-XTS/sector-size workspace profile. | Remove the CDH-only successful-cleanup test already covered by the full owned-resource cleanup test. Keep reused-resource and failed-cleanup-order tests, real fsGroup inheritance checks, and initializer cancellation coverage. The generic mounting improvements must be separated from measured workspace policy before upstream submission. |
| [0007 — credentials and diagnostics](cloud-api-adaptor/0007-security-exclude-host-credentials-from-peer-pod-data.patch) | **C.** Optional image-pull credential forwarding, removal of the APF debug copy, and reduced diagnostic output. | Correct the subject/body to describe these actual changes: the patch does not implement a new cloud-provider credential transport. Keep the two forwarding modes and extend existing TLS propagation tests. The filename is retained for local queue continuity. Logging changes do not need additional string-matching tests. |
| [0008 — bounded userdata transport](cloud-api-adaptor/0008-alibabacloud-bound-compressed-instance-user-data.patch) | **C.** Existing userdata size limits plus a paired compression/decompression enhancement. | Keep host compression-boundary and guest decompression-boundary tests; they enforce different limits. Keep the native cloud-config byte-preservation check, but remove the redundant SHA-384 equality assertion after byte-for-byte equality. Host and guest changes must be delivered together. |
| [0009 — sealed mounts and AA binding](cloud-api-adaptor/0009-guest-verify-sealed-mounts-and-native-initdata-binding.patch) | **A:** measured sealed descriptors and ephemeral-profile volume rejection. **B:** container-create rollback spanning failures before and after mount preparation. **C:** manual initdata extension/event encoding, now superseded upstream but still needed with our pinned binaries. | Keep tampering, unseal failure, path confinement, and transaction rollback cases. Replace the manual AA protocol/measurement code and its dedicated tests as part of the coordinated upstream migration described below. Unit cleanup tests and container-create rollback tests check different behavior. |
| [0010 — on-link routes](cloud-api-adaptor/0010-podnetwork-preserve-on-link-routes-during-guest-setup.patch) | **C.** Existing worker-to-guest route conversion bug. | Keep the submitted patch byte-for-byte. It extends the existing network tests rather than creating a separate test program. |

## CSI block driver

| Patch | Class and boundary | Code and test review |
| --- | --- | --- |
| [0001 — recovered capacity](caa-csi-block-driver/0001-controller-validate-actual-capacity-on-recovered-volumes.patch) | **B.** Existing cached/cloud-recovered CreateVolume results must satisfy the requested range and report actual capacity. | Keep the common table across cached and provider paths: either path can bypass the other. Failure must not persist an incompatible record. No extra provider interface or duplicate volume journal is needed. This is the clearest independent storage bug-fix candidate. |
| [0002 — Alibaba provider](caa-csi-block-driver/0002-alibabacloud-add-ESSD-support-through-the-provider-interface.patch) | **A.** New provider integration used by our storage stack, without guest encryption or plaintext key handling. It can be discussed independently as a provider feature. | Keep existing provider interfaces, cloud-tag recovery, and SDK credential caching. The local SDK tests cover real request/token behavior and credential reuse, not just mock call counts. No custom credential refresh worker or pending-create journal remains. |
| [0003 — atomic versioned metadata](caa-csi-block-driver/0003-node-publish-versioned-direct-volume-metadata-atomically.patch) | **B:** atomic publication, idempotent replay, recovered device identity, readonly/options, delegated fsGroup, ownership checks, and cleanup error propagation. **A:** the required paired v1 schema and its compatibility boundary with CAA. | Merge the overlapping restart/replay tests into one that actually recreates the node server, verifies caller context remains unchanged, and rejects a different disk. Keep atomic rename-failure cleanup, conflicting readonly replay, and ownership/path rejection tests. Generic fixes can be extracted while retaining the existing upstream wire format. |
| [0004 — controller/node deployment](caa-csi-block-driver/0004-deploy-separate-CSI-controller-and-node-responsibilities.patch) | **B.** Existing CSI deployment enhancement: split credentials, service accounts, and durable controller state from node publication. Alibaba values additionally depend on the new provider. | Most size comes from generated raw manifests. Keep Helm as the source and the renderer as the generation route because upstream supports both install interfaces. The credential-placement, RRSA, topology, and rejected-configuration tests cover distinct deployment contracts. Do not remove node privileges without changing mount propagation. |
| [0005 — conformance runner](caa-csi-block-driver/0005-test-share-the-CSI-conformance-runner-with-CI.patch) | **B.** Existing CSI testing and cleanup improvements; local and CI use one runner. | This already removes a duplicate CI implementation and broad temporary-directory cleanup. Keep the single version/skip list. The target-path adapter is explicitly test-only and accompanies the stricter node path contract; extract only applicable parts for upstream. No test of the shell script's literal text is needed. |
| [0006 — build/runtime bases](caa-csi-block-driver/0006-build-pin-supported-build-and-runtime-base-images.patch) | **C.** Reproducible image maintenance. | A small Dockerfile change; no bespoke unit tests. Image availability and rebuild validation belong to a deliberate base-image refresh, not this classification/test cleanup. |

The [Kata no-new-privileges patch](kata-containers/0001-fix-runtime-preserve-exec-no-new-privileges.patch)
is **C**. It forwards an existing OCI field and extends the existing conversion
test for false/true. It does not belong to either storage workstream and needs no
additional test harness.

## Redundancy decisions

This review removes or merges seven duplicate test functions, two repeated
retention cases, and one digest assertion implied by byte equality. It does not
use a target test-to-code line ratio. The generic deletion table existed in the
old shared patch but was deleted by 0004; it is now retained to test the same
deletion primitive in both builds, including inconclusive-read error cases.

The following similar-looking code remains intentionally:

- CSI writer, host resolver, and guest checks validate different inputs and
  trust boundaries. A shared golden fixture connects the contracts; a new
  cross-repository validation library would add coupling without removing the
  need to validate untrusted inputs at each boundary.
- CAA snapshots attached disk IDs for post-delete waiting, while the guard
  refreshes inventory before each deletion attempt. The first attempt currently
  reads twice. These could be combined by returning the checked snapshot from
  the deletion helper, but simply removing either read loses recovery state or
  retry-time protection. This is a possible API simplification, not removed code.
- Finalizer retention is an existing controller behavior. One integration test
  verifies that the new provider refusal reaches it; the provider tests alone
  cannot establish that the PeerPod object survives.
- Mount ownership flags distinguish acquired and borrowed resources and retain
  ownership after a failed cleanup. Combining them would weaken rollback and
  retry behavior. Measured policy validation also remains per request.

The generic deletion fix is now physically separate from retained-volume
protection. The other mixed patches are explicitly classified above; further
upstream extraction should preserve the old public contract and prove each
issue independently rather than submit the paired local stack wholesale.

## Upstream replacement for manual initdata measurement

Follow-up inspection of guest-components #1787 changes the classification of the
AA portion of 0009: it is a temporary compatibility layer, rather than part of
the confidential-volume design that must wait for storage discussion.

| Upstream change | Verified status | Relevance |
| --- | --- | --- |
| [guest-components #1787](https://github.com/confidential-containers/guest-components/pull/1787) | Merged 2026-10-20, `6b82bc66e002f31561c7f98816833c7c9641f5f8` | AA binds initdata at startup. An unset TDX MRCONFIGID falls back to a standard `InitData` event; same-digest restarts do not extend again, conflicting/duplicate entries fail, and eventlog must be enabled. |
| [Trustee #1632](https://github.com/confidential-containers/trustee/pull/1632) | Merged 2026-10-08, `7735c99e936d9e7fbe82522fb55cac8b985e4002` | Verifies the standard event after replay against quoted RTMRs, including event-content integrity. Nonzero MRCONFIGID must still match. |
| [CAA #3352](https://github.com/confidential-containers/cloud-api-adaptor/pull/3352) | Merged 2026-10-29, `706e06cc9db740bfafdd4890293a7d5431573078` | Writes decoded `initdata.toml`, supplies it to AA at startup, removes the old manual PCR extension, and updates guest-components. It is not in our pinned CAA base. |

Our guest-components `eae0bf63...` and Trustee `512fed65...` pins are still the
0.22.0 implementations without these new paths. Adopting the upstream flow would
allow removal of `pkg/userdata/measure.go`, its dedicated unit tests, the local
`measure-initdata` command, and the `extend-initdata` post-start wrapper, once
equivalent startup ordering and failure propagation are verified.

This is a coordinated migration, not an immediate patch deletion. Our current
event is `confidentialcontainers.org initdata <hex>`; upstream uses domain
`github.com/confidential-containers`, operation `InitData`, and JSON content
`{"digest":"sha384:<hex>"}`. Update the AS/KBS policies and event-digest renderer
together with the binaries and AA startup configuration. Do not run both the
manual extension and the new AA binding path. Rebuild guest measurements and
validate attestation/key release, restart behavior, and mismatched initdata.

The PR uses TDX register state rather than a GCP-specific branch. Whether an
Alibaba VM takes the fallback depends on its actual MRCONFIGID. It does not
replace disk/key authorization, LUKS initialization, CDH mount handling,
sealed-descriptor validation, or retained-disk deletion protection.

## Validation

Passed:

- CAA provider: `go test -race ./alibabacloud` from `src/cloud-providers`.
- CAA guest/adapter: `go test ./pkg/forwarder/interceptor ./pkg/adaptor/cloud`
  from `src/cloud-api-adaptor`.
- Standalone 0001a and the independent controller queue: `go test ./alibabacloud`
  from each tree's `src/cloud-providers`.
- Controller: `go test -tags alibabacloud ./controllers -run
  TestFinalizerRetainsPeerPodUntilProviderAllowsDeletion` from `src/peerpod-ctrl`.
- CSI: `go test -race ./pkg/driver`, including Helm rendering checks.
- Integration repository: all 23 existing `test_build_*.py` contract tests,
  layout checks, `bash -n deployment/build/prepare-sources.sh`, and
  `git diff --check`.
- Fresh `prepare-sources.sh` runs for CAA, CSI, and the controller verify every
  patch checksum and the resulting locked tree. `manifest.py --check-test-sources`
  verifies the installed build copies. The two submitted CAA patches remain
  byte-for-byte identical to the copies reviewed before this cleanup.

The build-contract run uses Python 3.11 for both the test process and subprocess
`python3` commands. The first attempt inherited the host's Python 3.6 for those
subprocesses; it was rerun successfully with the required interpreter on PATH.

This review does not rebuild or deploy cloud images or claim a new cloud
end-to-end run.
