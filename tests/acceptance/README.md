# Acceptance helpers

The [live-session helper](check-live-release.py) checks naturally issued signed
TDX sessions and current/cross-role KBS release on a deployed trusted host.
Follow the [live procedure](../../docs/live-acceptance.md) for its prerequisites,
private evidence, native Stop/Start and cleanup.

The remaining optional helpers run official Trustee 0.22 on disposable loopback endpoints
with synthetic signed claims and resources. They check policy loading and resource
decisions; they do not contact deployed KBS or establish hardware attestation.

```sh
python3 tests/acceptance/check-policy-denials.py --help
python3 tests/acceptance/test-renderer-release.py --help
```

`check-policy-denials.py` accepts `--kbs-binary` or an extracted official image via
`--kbs-rootfs`, plus `--policy`, synthetic `--binding` and `--output` paths. The
rootfs supplies the matching loader when host ABI differs. A denial requires an
actual `PolicyDeny` witness; an unrelated HTTP 500 is a failure.

To check both official services:

```sh
python3 tests/acceptance/test-renderer-release.py \
  --kbs-rootfs /absolute/path/to/kbs-rootfs \
  --grpc-as-rootfs /absolute/path/to/as-rootfs
```

This checks generated AS/KBS policies, BuiltIn RVPS registration/query and signed
synthetic EAR handling. Local CDH encrypted-device checks with a synthetic key
cover embedded-LUKS reopen and read-only behavior, not attestation-gated release.

Use the [live acceptance procedure](../../docs/live-acceptance.md)
for real quote/EAR verification, KBS decisions, native authorization/network
enforcement, workspace restart and owned-resource cleanup.

To exercise authenticated management with independent TLS/AS roots, including the
Rust driver's actual publisher and restart/revoke path:

```sh
python3 tests/acceptance/check-trustee-api.py \
  --kbs-rootfs /absolute/path/to/kbs-rootfs \
  --as-rootfs /absolute/path/to/as-rootfs \
  --output /path/to/private-results.json
```

This starts temporary loopback services, checks anonymous/wrong-key denial,
reference registration/readback, policy publication, synthetic resource release
and revocation, then terminates both services. It uses the cached Cargo toolchain
and synthetic resources; it does not establish real TDX attestation.
