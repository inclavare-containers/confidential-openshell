# Accept a real deployment

Run this on a disposable test sandbox after [deployment](deployment.md). Use the
native CLI environment from
[first agent](first-agent.md#connect-to-the-deployed-gateway). Keep the
installed handoff checksum with the results. Run the commands on T unless a
block explicitly says **inside the sandbox**. These steps use real cloud/model
resources and the selected image; the offline test suite does not replace them.

## Record identity and attestation

Create a detached shell with a configured provider using the first-agent guide.
Keep its name in `SANDBOX`. The default Kubernetes workspace prefix is
`default--`:

```bash
umask 077
EVIDENCE=/var/lib/openshell-confidential/acceptance/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$EVIDENCE"
cluster_config=/var/lib/openshell-confidential/operator/cluster-config
export KUBECONFIG="$cluster_config/administrator-kubeconfig"
CR=default--$SANDBOX
openshell sandbox get "$SANDBOX" --output json > "$EVIDENCE/native-before.json"
kubectl -n openshell get sandbox "$CR" -o json > "$EVIDENCE/cr-before.json"
kubectl -n openshell get pod "$CR" -o json > "$EVIDENCE/pod-before.json"
CR_UID=$(jq -er '.metadata.uid' "$EVIDENCE/cr-before.json")
kubectl -n openshell get pvc "workspace-$CR" -o json \
  > "$EVIDENCE/pvc-before.json"
PV=$(jq -er '.spec.volumeName' "$EVIDENCE/pvc-before.json")
kubectl get pv "$PV" -o json > "$EVIDENCE/pv-before.json"
```

If historical conditions are desired, enable `./cos trustee reports` on the
Trustee host and `./cos gateway reports` on T before creating the sandbox. After
enabling reports on running services, repeat `./cos gateway start` and
`./cos gateway login` to check readiness after the service restart.
`SupervisorAttested` and `WorkloadAttested` must refer to this CR UID and the
two current attempts. Save their parsed message JSON, initdata digests and
appraisal references. Conditions are a historical display, not proof of current
release.

Run the real-session probe immediately after creation while the natural sessions
are unexpired. On a host with co-located driver, AS and KBS:

```bash
python3 tests/acceptance/check-live-release.py \
  --uid "$CR_UID" --output "$EVIDENCE/release-before.json"
```

The probe verifies the AS ES256 signature and affirmative TDX appraisal, matches
the measured initdata digest against the driver's current trusted attempt, then
requests each role's own resource and the other role's resource. It requires
HTTP 200 for the former and an actual denial for the latter; an unrelated HTTP
500 is a failure. It never reads a resource response body or saves a bearer
token. Keep AS/KBS logs at their configured level; there is no need to enable
token logging.

With separate hosts, run the probe on Trustee, using a private, authenticated
snapshot of the driver's `active-attempts`, `bindings`, `revoked` and `revoking`
metadata via `--driver-state`. Strip the `key` field from binding JSON before
transfer; the probe never uses it. Supply `--trustee-client` with only `kbs_url`
and the local public `ca_cert` path. Do not run lifecycle operations during
capture/probing, and compare the selected generation/attempt with T again
afterward. Copy no workspace key, resource plaintext or administrator key.

Record the actual TCB status from the appraisal. The development policy accepts
both `UpToDate` and `OutOfDate`; the probe's affirmative result is not a
stronger production TCB requirement. Guest/policy/quote mutation regressions are
separate negative tests; an own/cross-role comparison does not cover every
rejection cause.

## Workspace and permissions

Inside the sandbox shell, create a distinctive persistence marker and record
mount/permission state:

```bash
python3 - <<'PY'
import hashlib, json, os, secrets, subprocess
from pathlib import Path
p = Path('/sandbox/acceptance-marker')
assert not p.exists(), 'use a fresh test sandbox'
p.write_text('COS_ACCEPTANCE_' + secrets.token_hex(32))
root = Path('/sandbox').stat()
assert p.stat().st_gid == root.st_gid
mount = subprocess.check_output(
    ['findmnt', '-T', '/sandbox', '-n', '-o', 'SOURCE,FSTYPE,OPTIONS'],
    text=True,
).strip()
assert mount.startswith('/dev/mapper/') and 'ext4' in mount
Path('/sandbox/acceptance-before.json').write_text(json.dumps({
    'marker_sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
    'workspace_gid': root.st_gid, 'workspace_mode': oct(root.st_mode & 0o7777),
    'primary_gid': os.getgid(), 'mount': mount}, indent=2)+'\n')
PY
```

Download the marker and JSON to the private evidence directory:

```bash
openshell sandbox download "$SANDBOX" /sandbox/acceptance-marker "$EVIDENCE"
openshell sandbox download "$SANDBOX" \
  /sandbox/acceptance-before.json "$EVIDENCE"
```

Complete the stop/revocation check below before running a long agent task.
Natural session tokens expire; completing a task first can make those tokens
unusable as revocation evidence. The later task persistence check uses another
native Stop/Start cycle.

On native Kata confirm that the filesystem root has the UID and GID from
measured `workspace.toml`. On Peer Pods additionally verify the directory setgid
bit and fsGroup inheritance. The unit fsGroup regression covers differing
primary GID, existing 0600 files, changed fsGroup, symlinks and readonly
requests; the default live workload normally has the same primary GID and
fsGroup.

## Stop, inspect and start

Record the actual workspace disk and both role instance IDs before stopping. The
PV's `spec.csi.volumeHandle` is a CSI logical handle, not necessarily an ECS
`d-*` ID. The paired node metadata gives the cloud disk ID: on the selected
node's CSI pod in `caa-csi-block`, inspect
`/run/kata-containers/shared/direct-volumes/*/mountInfo.json`. Decode each
direct-volume directory's URL-safe Base64 name to its kubelet target path and
match that path to the workload Pod UID and PVC. Match `volume-handle` (or
legacy `metadata.cloud-volume-id`) to the PV; record `device`, `fs-group` and
`readonly`. Match each PeerPod owner Pod UID to its ECS `spec.instanceID`, and
verify exact IDs through `DescribeInstances`. Save only this sandbox's records,
not an account-wide credential dump.

```bash
# Captures unexpired sessions, stops this exact native sandbox, then checks
# that the same still-valid sessions can no longer release their resources.
python3 tests/acceptance/check-live-release.py --uid "$CR_UID" \
  --stop-sandbox "$SANDBOX" --output "$EVIDENCE/release-and-stop.json"
openshell sandbox get "$SANDBOX" --output json > "$EVIDENCE/native-stopped.json"
kubectl -n openshell get sandbox "$CR" -o json > "$EVIDENCE/cr-stopped.json"
test "$(jq -r '.metadata.uid' "$EVIDENCE/cr-stopped.json")" = "$CR_UID"
```

For Peer Pods, wait for both recorded role instance IDs to be absent and the
recorded ESSD to be `Available` with no instance attachment. Keep the PVC/PV and
driver workspace key records. Check that old role bindings are revoked/removed.
An old unexpired session must no longer release its former resource; expired
tokens are not a revocation test. The `--stop-sandbox` probe performs this
comparison, retains tokens only in memory, and fails if they expire before the
post-stop check. On separate hosts, run that option where the configured native
CLI can reach Gateway as well as the private Trustee session snapshot.

On native Kata, check that the old role Pods are gone, the PVC and PV UIDs are
retained, and the stopped local block device still has its LUKS UUID. Use the
same cold-start check after a worker reboot. Recover on the same worker through
Gateway stop/start, or use start alone if the sandbox is already stopped.

For a Peer Pod raw at-rest check, use the stopped disk's cloud snapshot to
create a **disposable clone** in the same zone, and attach only that clone to an
inspection VM. Record every created snapshot/disk/instance ID for cleanup. Use
`CreateSnapshot`/`DescribeSnapshots` until `Status=accomplished`, then
`CreateDisk` with that `SnapshotId`. Pass the source disk's size, disk category
and ESSD performance level explicitly; a small PL0 workspace is incompatible
with the default PL1 size range. Use `AttachDisk` with
`DeleteWithInstance=false`. Resolve the clone by its ECS disk serial, allowing
the `d-` prefix to be absent, and wait for the device to appear. Do not guess a
`/dev/vdX` position. Verify it is unmounted and not the inspector's system disk.
Set that clone read-only with `blockdev --setro DEVICE`; do not unlock it or
transfer the workspace key.

On the inspector, `cryptsetup isLuks DEVICE` and `cryptsetup luksUUID DEVICE`
must succeed. Save the UUID and
`cryptsetup luksDump --dump-json-metadata DEVICE`. Scan the entire read-only raw
clone for the downloaded marker using a streaming byte search, preserving a
marker-length overlap between chunks. The marker must be absent. Keep only the
result and UUID; do not publish a disk dump. A negative marker search alone is
not cryptographic proof: combine it with the measured guest mapper checks and
the LUKS2/AES-XTS-512/4096-byte-sector rejection tests. Detach/delete the clone
and delete its snapshot after the check. If ECS still reports snapshot
initialization during deletion, retain the exact clone ID and retry after
initialization completes; do not treat that response as successful cleanup.

```bash
openshell sandbox start "$SANDBOX"
openshell sandbox get "$SANDBOX" --output json > "$EVIDENCE/native-after.json"
kubectl -n openshell get sandbox "$CR" -o json > "$EVIDENCE/cr-after.json"
test "$(jq -r '.metadata.uid' "$EVIDENCE/cr-after.json")" = "$CR_UID"
python3 tests/acceptance/check-live-release.py \
  --uid "$CR_UID" --output "$EVIDENCE/release-after.json"
openshell sandbox connect "$SANDBOX"
```

Inside the sandbox, check the marker hash against `acceptance-before.json` and
`/sandbox` mount and ownership. On T, confirm the same PVC/PV, trusted workspace
key identity and, on Peer Pods, cloud disk, with new role attempts/initdata
digests and a new workload Pod UID. Inspect the measured workload
`workspace.toml`: `allow_initialize` must now be false. To compare LUKS UUIDs
directly, repeat the stopped-clone inspection after this restart and compare the
two recorded UUIDs. Never export the key to demonstrate key stability; compare a
private digest of its trusted record in place.

## Run an agent task and preserve its results

Upload the public `tests/e2e/fixtures/project` and ask the actual harness to fix
`clamp.py`, run `python3 test_clamp.py`, and write the requested `result.json`.
Use a real provider response and the normal PTY. Detach with Ctrl-P/Ctrl-Q and
reconnect. Download the completed project to a new private directory on T and
run the non-executing oracle:

```bash
python3 tests/e2e/collect.py --work "$EVIDENCE/downloaded-project" \
  --output "$EVIDENCE/task-check.json"
```

Repeat the native harness workflow for OpenCode, Codex and Claude Code when
accepting their advertised support. Keep separate project directories, tool
success evidence and transcript hashes. Plain model text without completed
edit/test calls is insufficient.

For each backend, exercise both normal termination paths. Before each path,
choose fresh marker bytes on the trusted host and record their length and
SHA-256 there. Write the bytes to a file under `/sandbox` and close it. As
soon as the write command returns, perform the indicated action without an
application `fsync`, `sync`, download or intervening wait:

1. Stop the sandbox through Gateway and start it again.
2. With different marker bytes, delete just the workload Pod with ordinary
   Kubernetes grace. Recover the sandbox through Gateway stop/start.

After each recovery verify the new Pod UID, the same PVC/PV and the exact
length and SHA-256 of the latest marker. Download the retained
projects to new directories, compare every source/test/result file hash against
the pre-stop copies, and rerun the oracle with new output paths. Confirm the
same CR UID, PVC/PV, disk and marker, with fresh role attempts and
`allow_initialize` still false. Probe the fresh sessions immediately after
Start. Do not use expired pre-task sessions as evidence that this later Stop
revoked access.

## Delete and close the evidence

Capture all current owned IDs, then use native deletion while controllers and
Trustee remain available:

```bash
openshell sandbox delete "$SANDBOX"
kubectl -n openshell get sandbox "$CR" --ignore-not-found -o json
kubectl -n openshell get pvc "workspace-$CR" --ignore-not-found -o json
kubectl get pv "$PV" --ignore-not-found -o json
```

On native Kata the Sandbox and PVC disappear. A static local PV with reclaim
policy `Retain` becomes Released. Check its UID, then dispose of the PV and
backing device according to the owner's retention decision.

On ACK with the Peer Pod CSI profile, all three reads must be empty. Poll
`DescribeInstances` for both recorded role VM IDs and `DescribeDisks` for the
workspace disk ID until their result sets are empty. Verify the volume handle is
absent from the CSI controller store and node metadata, and that the trusted
driver has no live role/workspace binding for the CR UID. Do not interpret a
network error as absence. Clean up the inspection snapshot/clone and any
test-only inference provider as well.

A result ledger should identify the release digest, CR UID, before/after
attempts, role VM IDs, PVC/PV/disk IDs, LUKS UUIDs, marker/task hashes, KBS
allow/deny results and cleanup readbacks. Mark unperformed tests as unverified.
For deployment-level retirement, continue with
[owned-resource cleanup](operations.md#retire-owned-resources).
