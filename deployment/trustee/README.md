# Upstream Trustee

The runtime uses the two official Trustee 0.22 images pinned in
[the runtime lock](../runtime/artifacts.lock.json): `images.trustee_as` and
`images.trustee_kbs`. The gRPC AS includes BuiltIn RVPS. Its administrative API
listens on `127.0.0.1:50004`; KBS exposes the trusted HTTPS endpoint.

Install the two [units](units/) and the public configuration templates under
`/etc/trustee`. Their required `/etc/trustee/images.env` contains
`TRUSTEE_AS_IMAGE` and `TRUSTEE_KBS_IMAGE`, populated from those exact lock
entries. Preserve the existing CA, KBS server certificate and ES256 AS signer in
`/etc/trustee/tls`; the configuration does not generate credentials.

Upstream LocalFs uses these paths:

| Content | Path |
| --- | --- |
| AS CPU policy | `/opt/trustee/attestation-service/storage/attestation_service_policy/default_cpu.rego` |
| BuiltIn RVPS values | `/opt/trustee/attestation-service/storage/reference_value/` |
| KBS resource policy | `/opt/trustee/kbs/storage/kbs/resource-policy.rego` |
| Driver bootstrap store | `/opt/trustee/kbs/storage/repository/` |

Resource keys use upstream flat filenames: a logical `default/bootstrap/ID`
becomes the literal filename `default\x2Fbootstrap\x2FID`. The signed
`kbs:///default/...` URI and the trusted binding journal's
`resource/default/...` identity stay the same. Private ownership records and
workspace key journals remain in their separate trusted directories.

Start AS after installing the strict CPU policy. Register the final image's
independently derived reference file and the separately reviewed ECS firmware
reference map with the official loopback API, then start KBS:

```sh
python3 deployment/trustee/register-references.py \
  --address http://127.0.0.1:50004 \
  --references FINAL_IMAGE.references.json \
  --references deployment/trustee/ecs-tdx-platform.references.json
```

The registrar verifies every reference by querying BuiltIn RVPS. It accepts
public image/platform digests; current initdata authorization comes from
[the trusted binding renderer](render-kbs-policy.py), whose checked-in
templates deny release until rendered. Registration does not enroll arbitrary
measurements observed in a new guest.

The [ECS platform map](ecs-tdx-platform.references.json) pins MRTD and the
first three static RTMR0 event digests for the supported ECS firmware profile.
RTMR0 also measures per-VM ACPI configuration, so its complete value is not a
portable firmware reference.
The image verifier derives RTMR1 as `SHA384(48 zero bytes || UKI Authenticode SHA384)`
for this profile's single-UKI launch sequence and emits it with the image references.
The policy requires exactly six ordered RTMR0 events: the three pinned static
events followed by `EV_PLATFORM_CONFIG_FLAGS` for `etc/table-loader`,
`etc/acpi/rsdp` and `etc/acpi/tables`, each with one SHA-384 digest. These three
ACPI contents are explicitly accepted as untrusted VMM inputs handled by the
approved TDVF and guest kernel; their contents are not individually approved
reference values. All six digests must replay into the signed RTMR0 through
the native verifier. Firmware identity, static event changes, reordered or
extra events still fail appraisal. No new quote enrolls an observed RTMR0.
This split follows the firmware-code and dynamic-configuration distinction in
[Intel’s TDVF design guide](https://cdrdv2-public.intel.com/733585/tdx-virtual-firmware-design-guide-rev-004-20231206.pdf),
sections 8.1 and 8.3.

[The CPU policy](../policy/tdx-podvm.rego) requires the exact UKI Authenticode
measurement, ordered systemd section events, Linux's independently derived
LoadOptions and combined initrd events, full RTMR2, and the approved ECS
MRTD, static RTMR0 prefix and event layout, and derived RTMR1 profile. The UKI's measured cmdline binds the verified root's
roothash. Upstream quote verification validates REPORTDATA and replays all four
RTMRs. Current initdata must appear exactly once in register 4, with
`digest_matches_event=true` and the SHA-384 of its complete canonical tagged
AAEL event.

[The KBS policy](../policy/kbs-sealed.rego) consumes upstream's native
`plugin="resource"` and three-element resource-path array. It checks the signed
EAR vector, non-debug TDX status, canonical initdata and the exact current
per-role resource binding; workspace keys require the workload role. KBS trusts
the existing CA and rejects header-supplied JWKs. Its remote administrative API
is disabled; trusted local files/API own policy and reference publication.

Follow the [deployment runbook](../../docs/deployment.md) for installation and
recovery. Policy-denial tests must identify the actual `PolicyDeny` error;
an unrelated HTTP 500 is a failed test. Runtime credentials and state belong
outside this checkout.
