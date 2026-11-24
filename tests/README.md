# Tests

Run `./cos build test` from the repository root with the pinned toolchain and
cached dependencies and the released Kata policy rules. Cargo uses
offline/locked mode; Go disables proxy/sumdb. The runner prepares missing
CAA/CSI/controller build copies, checks their source identities and leaves the
pinned `repos/` checkouts unchanged.

## Cache dependencies and run

First complete the
[Ubuntu host tools](../docs/build.md#prepare-an-ubuntu-2404-host) and
[fixed source inputs](../docs/build.md#obtain-complete-fixed-sources). Populate
dependency caches while network access is available, then run the suite:

```bash
./cos build test-cache
./cos build test
```

<table>
<thead>
<tr>
<th>Suite</th>
<th>Coverage</th>
</tr>
</thead>
<tbody>
<tr>
<td>Driver Rust and imported upstream tests</td>
<td>Admission, sealed resources, UID/attempt bindings, workspace identity,
lifecycle and recovery</td>
</tr>
<tr>
<td><code>tests/policy</code></td>
<td>Peer Pod AAEL and native Kata MRCONFIGID appraisal, TD HOB event
handling, exact KBS resources and guest mount/pull denials</td>
</tr>
<tr>
<td><code>tests/contracts</code></td>
<td>Build provenance, initdata, permissions; cloud creation/resume with
mocked APIs; step failure logs, worker selection/profile preservation
and atomic release extraction</td>
</tr>
<tr>
<td>CAA/CSI Go tests</td>
<td>The maintained adapter and storage patches</td>
</tr>
<tr>
<td>PeerPod provider tests</td>
<td>Deletion succeeds only after exact typed absence; present instances
and read errors preserve failure</td>
</tr>
<tr>
<td>PeerPod controller</td>
<td>Compile packages and tests; envtest's API server/etcd suite is not run</td>
</tr>
<tr>
<td>Helm and CSI handoff</td>
<td>Source-bound chart package, RRSA, controller/PVC/node/StorageClass
settings and corrupt-input rejection</td>
</tr>
<tr>
<td><code>tests/e2e</code></td>
<td>Coding-task oracle and OpenCode event checks</td>
</tr>
<tr>
<td><code>tests/check-layout.py</code></td>
<td>Maintained links and script/configuration syntax</td>
</tr>
</tbody>
</table>

Helm requires the checksum-pinned archives under `artifacts/cache/helm/` or
`PEERPODS_CHART_CACHE`, plus Helm and the Ubuntu `python3-yaml` package. The
handoff check verifies chart file contents/modes against Git and renders the
transferred package without Git or a cluster connection. Missing dependencies
fail without downloading them.

The default suite uses no cloud API, deployed KBS, real quote or external model.
[Optional policy-engine tests](acceptance/README.md) use official Trustee
binaries with synthetic claims. [Agent-task checks](e2e/README.md) cover
application behavior. Real attestation, resource release, network enforcement
and volume lifecycle require the
[live acceptance procedure](../docs/live-acceptance.md). Fixture digests must
never become deployed approval references.

The core CI workflow runs `bash tests/run-core.sh` after `cargo fetch --locked`.
It covers driver lifecycle and trusted launch behavior, plus deployment
contracts and Trustee API timeout/recovery using a stateful test peer. It does
not allocate cloud resources. The complete `./cos build test` suite additionally
checks the CAA/CSI patches, policy engine and chart handoff.
