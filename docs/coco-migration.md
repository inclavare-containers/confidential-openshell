# CoCo migration validation record

Status: migration in progress; the new stack is not yet a live-accepted release.

## Preserved baseline

`main` remains at `dd1460e512e48e80c834688bbdfe447b873589f1`. Its runtime code
matches the live-accepted `a550a3ae72e812fed0456adeef2cffdacbd547a4`; subsequent
commits changed documentation and a commented image example. The 2026-11-03
acceptance covered real TDX/verified EARs, own/cross-role key release, unexpired
Stop/Delete denial, persistent workspace restart, raw-disk plaintext checks,
native cleanup, and actual OpenCode/Codex/Claude tasks. This is evidence for the
documented deployment profile, not a claim of authenticated LUKS headers or full
disaster-recovery testing.

The subsequent patch classification/cleanup is saved as `89173caf` on
`codex/coco-migration-20261103`, followed by the migration work. Its complete
offline suite passed before migration. It was not relabeled as a new cloud run.
The previous isolated cloud environment was retired; its old endpoints must not
be reused for new validation.

## Selected inputs

These are pinned upstream commits with completed relevant CI and published
artifacts, not release tags. The latest releases at selection were CAA 0.23.0
and guest-components/Trustee 0.22.0.

| Component | Selected commit | Selection reason |
| --- | --- | --- |
| CAA | `9ca88115b6daa43f023a8a3b61ee48190707b6e1` | 2026-11-03 completed upstream checks and image builds; includes native AA initdata startup integration. |
| guest-components | `de1142e1dfb9d56ece0bd758c6efda7fb52c56bd` | 2026-10-30 completed CI and published TDX/amd64 artifacts; includes InitData fallback while preceding the newer RTMR ioctl and eventlog-switch changes. |
| Trustee | `ade2f25782d69d16efa9aeaf6d58c5a48bd5bc56` | 2026-11-02 completed component CI and published staged images; includes standard InitData event verification. |
| CSI | `aa4e40abeab760240569979680bc985c86783ce8` | Latest upstream remains the existing 2026-10-27 base. |
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
`sha384:<hex>`. Per-resource authorization and measured workspace/sealed-descriptor
checks remain in place.

The [patch ledger](../patches/storage-review.md) separates generic fixes, ordinary
provider capabilities and confidential-volume policy. Both pending CAA PRs
[#3435](https://github.com/confidential-containers/cloud-api-adaptor/pull/3435) and
[#3437](https://github.com/confidential-containers/cloud-api-adaptor/pull/3437)
remain verbatim patches, rather than assuming they are already merged.

## Validation status

Passed so far: selected artifact provenance, exact patch replay/tree locks,
generic-only CAA tests, migrated CAA provider tests with the race detector,
the complete offline suite, and official AS/KBS runtime-policy tests. These
include adapter/guest tests, controller finalizer checks, CSI conformance,
policy tests, guest initdata validation, and attestation-observer tests. The observer's standalone
test now declares its existing crypto backend explicitly instead of depending
on feature unification with the driver test suite.

The runtime-policy harness covers 15 distinct bindings, successful authorized
resource delivery, six exact policy denials, reference registration/readback,
policy storage and signed rejection of synthetic non-TDX evidence. It now includes
the official image's `/usr/local/lib` search path and uses loopback AS gRPC for
its isolated reference fixture. Deployed management still uses authenticated KBS.

Pending: guest/container builds and measurement derivation,
real cloud attestation/key release, persistent-volume lifecycle and cleanup.
Results will be updated with exact committed inputs; old live evidence is not
used as proof for the migrated binaries.
