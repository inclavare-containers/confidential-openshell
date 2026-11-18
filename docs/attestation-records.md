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
plugins at startup and cannot start until the observer is reachable. The observer
uses `Type=notify` and signals readiness after binding its loopback listener;
systemd waits for that signal before starting KBS. An invalid or unreadable AS
verification key degrades collection while keeping the plugin available. Later
scans can recover after an in-place repair of an already mounted key. The unit
also starts with unavailable collection when a session directory or key mount
source is missing. After creating a missing source, restart the observer to
establish its mount; atomic key replacement also requires a restart (see upkeep
below). Other fatal startup failures can still prevent KBS startup.
A later observer outage makes report queries
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
or pass `--attestation-reports`. Before a result is known, configuration or network
errors become `Unknown`. An already observed result is retained for its attempt.

## Read

```sh
openshell sandbox get NAME --output json |
  jq '.conditions[] | select(.type == "SupervisorAttested" or .type == "WorkloadAttested") |
      {type, status, reason, message}'
```

Each role has one condition with a short, plain-text `message`. There is no
additional summary condition, TUI tab or CLI command. Ready keeps its existing
lifecycle meaning; these records do not gate it. Get, list and watch use the same driver conditions.
Queries run in the background, so the first snapshot may be `Unknown`; subsequent
snapshots pick up the report. The observer scans every five seconds. Reports
queries independently of sandbox reads: initially about every five seconds with
jitter, then every 60–75 seconds after a conclusion or the capture window expires. The HTTP client,
CA and parsed admin key are reused; changes to the configuration, CA or key
invalidate the cached client. Each query signs a fresh short-lived admin JWT.

Only a changed public condition notifies the watch publisher, which reads that
sandbox and sends its current status. Equivalent results do not read Kubernetes
or write the Gateway. There is no five-second full-list publisher. The existing
30-second lifecycle reconcile still republishes snapshots and recovers lost
notifications; this change does not remove those pre-existing writes. Watch
reconnection also receives the normal initial snapshots. Queries have an
eight-request concurrency bound; removed or suspended bindings stop polling, and
unobserved sandbox cache entries expire after ten minutes (at most 1024 entries).

| Situation | Status | Reason | Message example |
| --- | --- | --- | --- |
| Starting, no conclusive record yet | Unknown | AttestationPending | waiting for a Trustee record for this attempt |
| Affirming appraisal, TCB UpToDate | True | Attested | Intel TDX · verified by Trustee · TCB up to date · ref 4bc4f817 |
| Affirming appraisal, TCB OutOfDate | True | AttestedWithWarning | Intel TDX · verified by Trustee · TCB out of date (allowed by appraisal policy) · ref 4bc4f817 |
| Warning appraisal | True | AttestedWithWarning | Intel TDX · verified by Trustee · TCB up to date · Trustee appraisal warning · ref 4bc4f817 |
| Signed contraindicated appraisal | False | AttestationRejected | Trustee rejected the evidence (appraisal: contraindicated) · ref 4bc4f817 |
| Cannot collect records before a result is known | Unknown | AttestationStatusUnavailable | cannot read Trustee records |
| Capture window elapsed without a record | Unknown | AttestationStatusUnavailable | no Trustee record captured for this attempt |
| Stopped/suspended | Unknown | NotRunning | no running guest |

`ref` is the first eight hexadecimal characters of the signed EAR's SHA-256
fingerprint, for locating the observer record. It is not a UKI measurement or
reference baseline. On the Trustee host, search both current and archived records
(the entire pipeline needs root access; a short prefix may match multiple files):

```sh
sudo sh -c 'grep -l '\''"ear_sha256":"4bc4f817'\'' /var/lib/openshell-attestation-observer/reports/*.json /var/lib/openshell-attestation-observer/reports/by-ref/*.json 2>/dev/null | xargs -r jq .'
```

Missing TCB information is displayed as `TCB status
unavailable` with `AttestedWithWarning`; it is never presented as up to date.
An affirming appraisal allows the quoted TCB under the appraisal policy; this
does not assert that KBS released any resource. A warning is not labelled as a
policy allowance. Detailed rejection causes are not currently available in the
reduced report, so the driver does not invent a cause such as an unapproved image.
Failures that produce no signed record are never inferred to be rejection.
The capture window is five minutes from the driver's first observation of the
role/binding, not the Guest's authentication deadline. It resets on driver restart
or a changed binding. After that window a missing record becomes unavailable;
low-frequency retries continue and a later valid record can recover it. Ready is
not used to fabricate an attestation result for either role.

The driver matches Sandbox CR UID, generation, attempt and measured initdata
SHA-384 using its private binding records. It strips both the old
`SupervisorAttestation` / `WorkloadAttestation` names and the new names from
Kubernetes-supplied conditions, including when this feature is off. Reports from
previous attempts or replacement UIDs cannot satisfy the current binding.
An absent/revoked binding while a guest is expected to run is pending within the
five-minute capture window, then unavailable. An unreadable binding is
unavailable immediately. Stopped guests show NotRunning.

Once a conclusive result is known, query errors, unhealthy scans and missing or
unspecified records do not erase it. Binding-read failures retain history in the
cache but display Unknown until the same trusted binding is confirmed again.
A newer signed appraisal with a changed TCB, policy ID, appraisal, trustworthiness
or measurements replaces the representative record, including a rejection.
Equivalent reattestations advance a persisted timestamp watermark while retaining
the representative EAR fingerprint. `none` never replaces a conclusive record.
Observer history survives observer restarts;
the driver's query cache is temporary and refills after a driver restart.
Attested describes a past event for the current attempt. It does not establish
current VM liveness or prove a secret was delivered.

`transition_time` is supplied for both successful and rejected conditions. The
observer persists the signed time at which the True/False status changed; updates
to reason/message alone preserve that time. Unknown conditions use the time the
driver first observed their status. A duplicate attestation does not move the
displayed ref or transition time. These are historical observations, not fresh
bearer credentials.

`attested_at`, `token_expires_at`, `observed_at` and `last_scan_at` are Unix seconds.
An expired EAR is intentionally accepted as a historical record after signature
verification. Its expiration does not turn history into a current credential.
The observer's admin-authenticated report contains appraisal/policy, TDX TCB status, selected measurements,
trustworthiness values and a SHA-256 fingerprint of the EAR. It excludes the
raw EAR, session cookie, public-key payload, evidence body and secret values.

## Collection limits and upkeep

The observer reads the official KBS `kbs_protocol_session` namespace and verifies
ES256 EARs with the configured AS public key. This read adapter depends on the
private persisted session format of Trustee v0.23.0; its query interface uses the
official external-plugin protocol. Recheck both when upgrading Trustee.
Verbose EAR evidence is required to extract the measured initdata event.

Stock sessions expire roughly five minutes after authentication and are cleaned
periodically. An observer outage can miss a session permanently. No quote refresh,
extra `/auth`, `/attest` or resource request is made to fill gaps. Absence is not
proof of rejection: KBS need not save a failed appraisal as an attested session.
Partial session writes are retried. A representative conclusive report and latest
equivalent-attestation watermark are kept per initdata digest. Semantic transitions
are also archived as `by-ref/<ear-sha256>.json`, so a previously displayed ref
remains searchable. Only reduced records are archived, not bearer tokens.
History grows with new bindings and semantic changes; include both directories
in the operator's retention policy.

Rotate the observer's public verification key with the AS signer and restart the
observer. The key is a single-file bind mount: replacing it atomically with rename
leaves the running observer reading the old inode until restart. Scanner retries
alone only see changes written in place to the mounted inode. Already reduced
records remain historical observations made with the
previous configured key. The normal units store these reports under
`/var/lib/openshell-attestation-observer/reports`; back up or remove that history
according to operator retention needs while the observer is stopped. Never copy
raw session files into release artifacts or logs.

Disable with `./cos gateway reports --disable`, then
`./cos trustee reports --disable`. These remove display/registration and stop the
observer while retaining its reduced history. Disabling Trustee registration
also restarts a running KBS.

If the plugin prevents KBS from starting, disable it on the Trustee host and
explicitly start KBS (`try-restart` used by the normal installer does not start an
inactive service):

```sh
sudo ./cos trustee reports --disable
sudo systemctl reset-failed kbs.service
sudo systemctl start kbs.service
```

The installer refuses to expose sessions unless the storage parent is a real
root-owned directory with mode 0700. Session files are readable only through the
observer's narrow read-only mount or by root through that private parent. The
observer unit restricts network access to loopback and applies syscall, kernel,
namespace and executable-memory restrictions.

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

On a host running systemd, use this separate root-only acceptance test with
`cryptography` and `grpcio-tools` installed in the selected Python environment:

```sh
sudo /path/to/python3 tests/acceptance/check-attestation-systemd.py \
  --observer /path/to/openshell-attestation-observer \
  --output /path/to/systemd-result.json
```

It starts the production unit with temporary fixture paths and all its hardening
directives, then removes its temporary service/state. It checks notify readiness,
real plugin queries, non-root identity, read-only mounts, missing mount sources,
history retention, in-place key repair and atomic key rotation. Existing Trustee
and sandbox services are untouched. The receipt includes `systemd-analyze verify`
and `systemd-analyze security` output (or its absence on older systemd versions).
This verifies runtime compatibility and the targeted mount behavior; the security
score is informational, not an exhaustive test of every syscall/network restriction.
