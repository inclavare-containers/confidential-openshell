# Optional attestation records

The confidential driver can include dated Trustee appraisals in the existing
OpenShell sandbox conditions. This feature is off by default. OpenShell's
protocol, CLI and TUI, Trustee images, guest AA/CDH and supervisor are unchanged.
The records do not affect readiness, authorization, revocation or secret delivery.

## Enable

`./cos build driver` builds the driver and `openshell-attestation-observer`;
`./cos build package` includes both in the authenticated release handoff.
After installing that release and the normal Trustee/Gateway services:

```sh
# On the Trustee host:
./cos trustee reports
# On the Gateway/driver host (may be the same host):
./cos gateway reports
```

These commands restart the corresponding running service. Enable the Trustee
side during a maintenance window: official KBS connects to configured external
plugins at startup and cannot start until the observer is reachable. Systemd
starts the observer before KBS. A later observer outage makes report queries
unavailable; it does not add a runtime dependency to KBS resource authorization.

For an existing remote Trustee, its administrator runs the Trustee step there.
The driver uses the existing `trustee-client.json` HTTPS origin, CA and admin
identity. It does not mount Trustee storage. The installer supports this
repository's LocalFs deployment layout. An independently configured Trustee
must use persistent `session_storage_type = "LocalFs"` (a top-level setting),
expose that namespace read-only to the observer, and merge this registration
into its KBS configuration:

```toml
[[plugins]]
name = "external"
backends = [{ name = "attestation-reports", endpoint = "http://127.0.0.1:50005", timeout_ms = 2000 }]
```

Add this entry to the existing `[admin.authorization.regex_acl].acls` array:

```toml
{ role = "confidential-openshell", allowed_endpoints = "^/kbs/v0/external/attestation-reports/[0-9a-f]{96}$" }
```

The observer always requires KBS admin authentication. Its gRPC listener is
loopback-only; the public query uses KBS's existing HTTPS listener and certificate.
The DynamicUser service receives only the session namespace and public AS
verification key through read-only mounts. KBS's private storage parent remains
mode 0700; resource keys and AS private keys are not exposed to the observer.

For a driver managed outside these units, set `OPENSHELL_ATTESTATION_REPORTS=true`
or pass `--attestation-reports`. Configuration or network errors become `Unknown`.

## Read

```sh
openshell sandbox get NAME --output json |
  jq '.conditions[] | select(.type == "SupervisorAttestation" or .type == "WorkloadAttestation") |
      {type, status, reason, detail: (.message | fromjson)}'
```

The stock CLI carries the report as a JSON string in `message`. There is no new
TUI tab or CLI command. Get, list and watch use the same driver conditions.
Queries run in the background, so the first snapshot may be `Unknown`; subsequent
snapshots pick up the report. The default scan interval is five seconds and the
driver refresh interval is ten seconds. When enabled, the driver publishes
read-only watch snapshots every five seconds so the stock Gateway's sandbox
store receives fresh collection status even while a sandbox is idle. This
display publisher does not run lifecycle reconciliation.

Each condition includes the role, Sandbox CR UID, generation, attempt, expected
initdata SHA-384 and the reduced appraisal. The driver resolves these identities
from its own private binding records and replaces any same-named conditions
supplied by Kubernetes. Reports from previous attempts or replacement UIDs are
not used for the current binding. After stop/revoke there is no active binding:
the native condition becomes `Unknown / NoActiveBinding`. Observer history is
retained by digest and survives an observer restart; the driver's query cache
is temporary and refills after restart.

`True / HistoricalAppraisalAffirming` means the observer found a signed affirming
EAR for that binding. `False / HistoricalAppraisalNotAffirming` describes an
observed warning or contraindicated appraisal. Missing records, unsigned or
unrecognized data, an unavailable observer, stale collection status and an
unspecified appraisal all produce `Unknown`. A previously cached report may
remain in the message during an outage, with `Unknown` status. None of these
conditions establishes current VM liveness or proves a secret was delivered.

`attested_at`, `token_expires_at`, `observed_at` and `last_scan_at` are Unix seconds.
An expired EAR is intentionally accepted as a historical record after signature
verification. Its expiration does not turn history into a current credential.
The summary contains appraisal/policy, TDX TCB status, selected measurements,
trustworthiness values and a SHA-256 fingerprint of the EAR. It excludes the
raw EAR, session cookie, public-key payload, evidence body and secret values.

## Collection limits and upkeep

The observer reads the official KBS `kbs_protocol_session` namespace and verifies
ES256 EARs with the configured AS public key. This read adapter depends on the
private persisted session format of Trustee v0.22.0; its query interface uses the
official external-plugin protocol. Recheck both when upgrading Trustee.
Verbose EAR evidence is required to extract the measured initdata event.

Stock sessions expire roughly five minutes after authentication and are cleaned
periodically. An observer outage can miss a session permanently. No quote refresh,
extra `/auth`, `/attest` or resource request is made to fill gaps. Absence is not
proof of rejection: KBS need not save a failed appraisal as an attested session.
Partial session writes are retried. A report is kept per initdata digest, choosing
the latest EAR issue time; reduced history grows as new bindings are observed.

Rotate the observer's public verification key with the AS signer and restart the
observer. Already reduced records remain historical observations made with the
previous configured key. The normal units store these reports under
`/var/lib/openshell-attestation-observer/reports`; back up or remove that history
according to operator retention needs while the observer is stopped. Never copy
raw session files into release artifacts or logs.

Disable with `./cos gateway reports --disable`, then
`./cos trustee reports --disable`. These remove display/registration and stop the
observer while retaining its reduced history. Disabling Trustee registration
also restarts a running KBS.

## Validation

Offline Rust tests exercise signature checks, partial reads, durable retry,
restart/outage behavior and current-binding display. The optional local
integration test uses the locked official KBS/AS binaries, temporary credentials
and synthetic signed session records; it is not a hardware-attestation test:

```sh
cargo build --locked -p openshell-attestation-observer
python3 tests/acceptance/check-attestation-reports.py \
  --kbs-rootfs /path/to/released-kbs-rootfs \
  --as-rootfs /path/to/released-as-rootfs \
  --output /path/to/result.json
```

It checks official session persistence at `/auth`, plugin registration, TLS/admin
authentication, historical reporting, the production driver query, unchanged
condition protobuf transport, and KBS management availability after observer exit.

With `grpcio-tools` installed in the test environment, add
`--openshell /path/to/released/openshell` to check the actual stock CLI's JSON
output too. That check passes the production driver's encoded condition through
a loopback Gateway fixture using the unchanged upstream protobufs; the Gateway
in this specific test is simulated.
