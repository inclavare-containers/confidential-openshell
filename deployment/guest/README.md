# Upstream Ubuntu TDX guest

The main profile uses the locked CAA main revision's Ubuntu mkosi image definitions,
production profile, UKI boot and SquashFS dm-verity root. Released CoCo guest
components at the locked upstream commit provide the TDX AA and CDH. Kata agent 4.4.0 and pause remain
unmodified released binaries. `deployment/artifacts.lock.json` pins source,
OCI artifacts and binary hashes.

The only compiled guest integrations are CAA's APF and process-user-data from
the verified patch tree. The image reuses upstream systemd units; small drop-ins
validate measured initdata, pass its exact TOML to native AA startup binding,
and order CDH/Kata/APF startup. AA/CDH retain upstream automatic restart. Ubuntu `python3` supports the validator and
workspace initializer; `systemd-timesyncd` with Alibaba NTP corrects the ECS RTC
before KBS authentication. AA/CDH daemon sources are unchanged. The upstream
container-facing REST path is disabled because this profile uses native ttRPC.

CDH's native `image.work_dir` points to `/var/lib/confidential-containers/image`.
The verified UKI's `systemd.volatile=state` keeps `/var` in guest memory. This gives
the Community image room to unpack without filling the smaller `/run` tmpfs.

Prepare the locked sources as described in [build preparation](../../docs/build.md),
then run:

```sh
export GOCACHE="$PWD/.local/go-build-guest"
bash deployment/guest/build-image.sh
```

Host prerequisites: Docker with privileged native containers, Go, make, jq,
Python 3.11 or newer, curl, tar, zstd, readelf, crane and runc. Fetching missing CoCo or Kata
release binaries also needs oras and gh for the upstream provenance verifier.
Kata uses the same standalone OCI agent artifact as CAA; the complete Kata runtime
release archive is not needed.
Checksum-verified official binaries may be reused from `artifacts/cache`.
`build-payload.sh` runs automatically, and builds new APF/PUD outputs from the
verified CAA sources.

`Dockerfile.mkosi-tools` follows the upstream Ubuntu 24.04 tool-container recipe
and pins mkosi v26 at `84af20892b61c8e177e391f997ded8b4cb5514f2`. It adds only
image verification/conversion utilities. `OPENSHELL_MKOSI_TOOLS_IMAGE` can select
a retained tools image; the builder checks its exact clean mkosi checkout and
required utilities, then mounts a new copy of the pinned upstream image inputs
over `/image`. `OPENSHELL_MKOSI_TOOLS_BASE_IMAGE` can reuse that verified Ubuntu
tools base while installing missing verification packages with the maintained
Dockerfile. `artifacts/cache/mkosi-packages` is only the distro package cache.
No previous project payload or disk image is used. The ECS native kernel builds
the image without nested virtualization or NBD mappings.

For a digest-identical private pause mirror, set
`OPENSHELL_GUEST_PAUSE_IMAGE_REF` and `SSL_CERT_FILE` to its public CA. The
amd64 manifest, image command and pause binary still must match the lock.

Outputs are `artifacts/guest-payload.tar` and
`artifacts/guest/openshell-guest-<qcow-sha12>.qcow2` with its `.references.json`.
The private build metadata records tools/source/payload/output hashes,
the independent root-verity check, PE Authenticode comparison with pesign,
ordered UKI section hashes and the comparison with `systemd-measure`.
Static references include `measurement.uki.sha384`, the full independently
derived `measurement.uki.rtmr2.sha384`, the audit section seed
`measurement.uki.sections.sha384`, `measurement.uki.section.<name>.<name|data>.sha384`
and `measurement.uki.linux.<load_options|initrd>.sha384`. The Linux EFI command
line and initrd digests are derived from the final UKI, including the upstream
systemd-stub generated os-release cpio. Only the verified systemd-stub
259.5-0ubuntu3.4 profile without extra credential/addon initrds is accepted;
the overlay pins this released Ubuntu `systemd-boot-efi` package version.
Other versions or additional embedded initrds fail closed. The repository's ECS
platform map supplies MRTD and three static RTMR0 event digests. Policy requires
the exact six event types, names and order; dynamic ACPI contents remain accepted
untrusted VMM input handled by trusted TDVF/kernel, not independently approved
references. All four quoted RTMRs require full replay. RTMR1 is independently derived
from the final UKI's Authenticode digest and the reviewed single-UKI launch sequence;
it is emitted with the image references.
Actual TDX quote/CCEL verification and the configured platform policy remain
required before accepting the image.

For persistent workspaces, the driver adds measured `workspace.toml` with the
stable KBS key URI and trusted cloud disk IDs. APF resolves and checks the disk
identity. A fresh disk must be an unused, partition-free whole disk, entirely
zero-filled and explicitly authorized for initialization on the first sandbox creation.
Restart sets `allow_initialize=false`, so a substituted blank disk is rejected. The small initializer
receives exactly 32 CDH-released key bytes on stdin and calls Ubuntu's standard
cryptsetup to create an embedded LUKS2 header, formats the measured filesystem
(default ext4), then closes it. Existing
LUKS disks are never initialized or repaired. Upstream CDH SecureMount opens
`sourceType=encrypted,targetType=device`; APF verifies the active kernel mapping uses
LUKS2, AES-XTS with a 512-bit key and 4096-byte sectors before mounting, including reused
mappers. It enforces the requested read-only mode across the raw device, mapper and filesystem. CDH's ephemeral detached-header `sourceType=empty` is
not used for retained disks. Stop/Start keeps the same ESSD, header and KBS key.

Image/reference changes require the [two-role deployment checks](../../docs/deployment.md#10-verify-both-confidential-roles),
including sealed bootstrap, resource denials and encrypted workspace restart.
