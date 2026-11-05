# CoCo migration validation record

Migration and live acceptance passed on 2026-11-03 for the release identified
below. These results apply to that release; later revisions need separate live
validation. The dedicated test infrastructure has been retired.

## Preserved baseline

The baseline is `dd1460e512e48e80c834688bbdfe447b873589f1`. Its runtime code
matches the live-accepted `a550a3ae72e812fed0456adeef2cffdacbd547a4`; subsequent
commits changed documentation and a commented image example. The 2026-11-03
acceptance covered real TDX/verified EARs, own/cross-role key release, unexpired
Stop/Delete denial, persistent workspace restart, raw-disk plaintext checks,
native cleanup, and actual OpenCode/Codex/Claude tasks. This is evidence for the
documented deployment profile, not a claim of authenticated LUKS headers or full
disaster-recovery testing.

## Selected inputs

These are pinned upstream commits with completed relevant CI and published
artifacts, not release tags. The latest releases at selection were CAA 0.23.0
and guest-components/Trustee 0.22.0.

| Component | Selected commit | Selection reason |
| --- | --- | --- |
| CAA | `9ca88115b6daa43f023a8a3b61ee48190707b6e1` | 2026-11-03 completed upstream checks and image builds; includes native AA initdata startup integration. |
| guest-components | `de1142e1dfb9d56ece0bd758c6efda7fb52c56bd` | 2026-10-30 completed CI and published TDX/amd64 artifacts; includes InitData fallback while preceding the newer RTMR ioctl and eventlog-switch changes. |
| Trustee | `ade2f25782d69d16efa9aeaf6d58c5a48bd5bc56` | 2026-11-02 completed component CI and published staged images; includes standard InitData event verification. |
| CSI | `aa4e40abeab760240569979680bc985c86783ce8` | Existing 2026-10-27 base retained. |
| Kata / OpenShell | Existing 4.2.0 / 0.1.6 pins | No runtime, source-base or image upgrades. |

Exact artifact digests and extracted binary hashes are in the existing locks.
The AA/CDH/REST artifacts passed CAA's upstream provenance verification for the
selected source and hosted runners. The new GNU binaries require OpenSSL 3 in
the guest image. CAA requires Go 1.26.10; its Kata protocol module did not change
between the selected old and new CAA bases.

## Compatibility changes

CAA reverted its permissive LUKS integration in
[`16a1d27f`](https://github.com/confidential-containers/cloud-api-adaptor/commit/16a1d27fe51e1fa41e94c76436531c8681f7e2de)
because host annotations could alter encryption/key choices and LUKS headers
were unauthenticated. CDH still exposes `SecureMount`; CAA also removed its
separate scratch-space feature. The migration retains only the measured
workspace path and rejects encrypted annotations without measured policy.
Header authentication, ciphertext integrity and rollback protection remain
separate design capabilities.

[guest-components #1787](https://github.com/confidential-containers/guest-components/pull/1787),
[Trustee #1632](https://github.com/confidential-containers/trustee/pull/1632), and
[CAA #3352](https://github.com/confidential-containers/cloud-api-adaptor/pull/3352)
replace the custom initdata-extension bridge. AA consumes exact decoded TOML at
startup. Policies and report readers consume the standard domain
`github.com/confidential-containers`, operation `InitData`, and JSON digest
`sha384:<hex>`. Per-resource authorization and measured workspace checks remain
in place.

The [patch queues](../patches/README.md) separate generic fixes, ordinary
provider capabilities and confidential-volume policy. The code diffs submitted in CAA PRs
[#3435](https://github.com/confidential-containers/cloud-api-adaptor/pull/3435) and
[#3437](https://github.com/confidential-containers/cloud-api-adaptor/pull/3437)
remain in the patch queues.

## Validated build

The migration-tested release was `ab6d488b865f55e94378c65ce07fea01445a9c06`. Its handoff
`SHA256SUMS` file has SHA-256
`8f7a1c5370bb32905dcb785294a3473ae92921f8c71775175c017adc0ebfd252`.
The complete release archive and validation evidence were copied back and
verified locally before retiring the test host.

Passed: upstream artifact provenance, exact patch replay/tree locks,
generic-only CAA tests, provider race tests, the complete project offline suite,
official AS/KBS policy execution, native component builds, guest verity and
measurement derivation, and clean release packaging. The offline suite includes
driver/observer, adapter/guest, controller finalizer, CSI Go tests, policy,
build-contract and rendered-chart checks.

The guest receipt remains at `9de7ff00`. The subsequent build-only commit changed
the CSI build network option, test PATH and build documentation; guest inputs
were checked unchanged before packaging. The original accepted Kata shim was
reused byte-for-byte. The new guest and all migrated runtime components were
tested in the cloud.

The official runtime-policy harness covers 15 bindings, authorized resource
delivery, six exact policy denials, reference registration/readback, policy
storage and signed rejection of synthetic non-TDX evidence. Its isolated
reference fixture uses loopback AS gRPC; deployed management uses authenticated
KBS. The harness includes the new image's `/usr/local/lib` search path, and the
observer's standalone tests declare their crypto backend explicitly.

## Live migration

A dedicated ACK/TDX deployment first ran the accepted `a550a3ae` release, created
an encrypted workspace and wrote a marker, sealed environment value and private
file. After Stop, its control state and disk snapshots were preserved before
installing the migrated release.

The following checks passed:

- The same sandbox CR, PVC, PV, cloud disk and private workspace key survived
  migration and another Stop/Start cycle. Each start used a new role attempt and
  workload Pod. Restart initialization remained disabled.
- Marker and sealed-environment hashes remained identical. The workspace used
  the encrypted ext4 mapper; recursive fsGroup permissions and directory setgid
  inheritance worked. The administrator's Gateway configuration was preserved.
- Independent read-only scans of the entire 2 GiB stopped disk before and after
  migration found no plaintext marker. The LUKS UUID was unchanged. The inspection
  did not transfer a key or unlock either clone; both clones were deleted.
- Both roles produced real, signature-verified TDX EARs with the standard
  `InitData` event. Own-resource requests returned 200; cross-role requests and
  requests using unexpired EARs after Stop returned 403 on the migrated stack.
  Native CLI conditions matched the independently verified current reports.
- Native Delete removed the migrated sandbox's CR, PVC, PV, disk and role VMs.
  A separate fresh sandbox recorded both roles changing from HTTP 200 before
  Delete to HTTP 403 afterwards while their EARs were still unexpired, followed
  by exact resource-absence checks.

Both roles reported `OutOfDate` TCB status. The existing TCB acceptance policy
was retained, and native conditions correctly displayed `AttestedWithWarning`.
The policy was not relaxed for this validation.

Delete withdraws runtime authorization and serving copies. The operator's private
recovery key and retained volume journal remain by existing design; this is not
a cryptographic key-erasure claim. The off-host control-state backup is encrypted
and excludes rebuildable registry/release caches; both public release packages
are retained separately.

Kata/OpenShell pins and workload images were unchanged. This migration exercised
native create, exec, upload/download, Stop/Start/Delete, workspace and sealed
environment operations; external coding-provider calls were not rerun. Full
recovery onto a replacement host/cluster, LUKS-header authentication, ciphertext
integrity and rollback protection were not claimed or tested.

## Subsequent validation on 2026-11-05

The later full build and live acceptance covered commit
`54c256df403a80688486ff8e5c2d0a0471ca5fcd`, tree
`a03053ffd8dd3488839431e6b4950c55249f381a`. Its release archive SHA-256 is
`3ed8d42a5ea26a2c2e0229c70cd32838b8d3f4dcfe410d89da74da2e2c8c4b5b`;
the handoff SHA-256 is
`c9303973bced58e2896399d5c320b438d3937af76f13ce4ebaf77a75d354ecc8`.
Private evidence is retained locally in
`.local/full-validation-20261105/validation.json`. That deployment was retired.
Later workspace-authorization, lifecycle and CSI fixes have separate local
regression coverage; the earlier cloud result does not validate those revisions.

## Retirement

After native sandbox deletion, both Helm releases were uninstalled and the CSI
state PVC, PV and disk were removed. Cloud readbacks confirmed absence of the
dedicated ACK cluster, owned compute, disks, images, snapshots, OSS bucket,
networks, load balancer, NAT, EIPs, scaling group and deployment identities.
The temporary builder and its private network were deleted. Its dedicated API
ACL was removed, the shared ACL's rules remained unchanged, and the temporary
proxy tunnel was stopped. Public release packages and private validation records
remain available locally.
