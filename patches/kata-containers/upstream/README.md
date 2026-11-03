# Kata upstream contribution record

[Issue #14024](https://github.com/kata-containers/kata-containers/issues/14024)
and [PR #14025](https://github.com/kata-containers/kata-containers/pull/14025)
were published on 2026-10-12. A single fix commit was pushed to
[`fix-exec-no-new-privileges`](https://github.com/wdsun1008/kata-containers/tree/fix-exec-no-new-privileges)
in the author's existing [fork](https://github.com/wdsun1008/kata-containers).
The branch changes only two upstream Go files; the documentation and reproduction
tools in this directory are outside its PR diff.

The submission checks and upstream CI status below are a historical record as of
2026-10-12, not a statement of the current upstream status.

- [Issue text](issue.md): the first line is the published title; the rest is the body.
- [PR text](pr.md): the first line is the published title; the body includes `Fixes: #14024`.
- [Full fix commit](https://github.com/wdsun1008/kata-containers/commit/e11d46ae543cfdd4c96d20de40e508e5a955db61): commit message, DCO and AI trailer.
- [Offline policy reproduction](reproduce-policy.py): complete upstream rules, synthetic policy data that allows the probe, and fixed state after container creation; no VM is started.
- [Captured request evidence](captured-evidence.json): checked against the original protobuf, actual Pod and generated policy; contains only commands, booleans and hashes.
- [Live validation](validation.md): original → patched → original comparisons on both 4.2.0 and the PR's `main` baseline, with reusable CRI inputs.
- [Live evidence summary](live-evidence.json): individual results for six real VMs and 36 exec calls, pinned component hashes and validation scope.

## Contribution checks

The review covered [Kata CONTRIBUTING](https://github.com/kata-containers/kata-containers/blob/46c507fe445370f0728aeefbfd16c49cead0493d/CONTRIBUTING.md),
the organization's default [bug report template](https://github.com/kata-containers/.github/blob/main/.github/ISSUE_TEMPLATE/bug_report.md),
and the commit-format CI checks. The branch used upstream `main` at
`46c507fe445370f0728aeefbfd16c49cead0493d`: one commit, one topic, a title prefixed
with `runtime:` and no longer than 75 characters, and body lines no longer than
150 characters. It used the existing Git identity
`Weidong Sun <sunweidong@linux.alibaba.com>` and included `Signed-off-by` and
`Generated-By: OpenAI Codex`.

After the author's review and authorization, the issue was created and its actual
`Fixes: #14024` reference was added to the fix commit and PR body. Only the commit
message was revised; the source tree matched the commit used for live validation,
and the DCO and AI trailers were preserved. The PR contained one commit changing
two Go files. At that time, upstream CI was waiting for a maintainer to add
`ok-to-test`: Gatekeeper exited because the label was missing, tests were skipped,
and no upstream test results were available.

The 2026-10-12 recheck found that the latest official release was 4.2.0 and `main`
was still at the baseline above. Neither the project nor the organization's
default repository provided a PR template. The issue followed the bug template's
Description / Expected / Actual / Further information sections and retained the
minimal reproduction and comparison results. The issue and PR titles were 62 and
52 characters; body lines were at most 81 and 85 characters, respectively. LF,
gofmt and diff whitespace checks passed. The subsystem, title and body matched
the official commit-message-check regular expressions. The author email matched
the DCO, and `Generated-By` was retained. These were local compliance checks, not
evidence that the full upstream CI had passed.

The fix commit included `Fixes: #14024`. The
[collector comment](https://github.com/kata-containers/kata-containers/issues/14024#issuecomment-6119735795)
required by the bug template contained unmodified stdout from the official script,
stored locally at
`.local/kata-community-review-20261012/compliance/issue-collector-comment.md`.
The published body was read back from GitHub and matched the local output byte
for byte. That file also matched `official-collector.stdout.md`, including real
paths and the default configuration lookup error.

The isolated test used an explicit `ConfigPath`, which the default collector could
not discover automatically. Unmodified output from the official
`kata-runtime --config <actual-config-path> env`, the actual configuration file,
and the test containerd version were also retained and published in a
[supplemental environment comment](https://github.com/kata-containers/kata-containers/issues/14024#issuecomment-6119736468).
The files and collection notes were stored in the same directory; configuration
hashes were checked against the original live records. Earlier redacted drafts
with path placeholders and an incorrectly changed package version were withdrawn
and retained only for audit. The official recommendation for authors to revise
the wording themselves still applied.

Before publication, searches for `NoNewPrivileges`, `no_new_privileges`,
`cmdToKataProcess` and exec/probe issues and PRs found no dedicated fix for this
missing field assignment. Existing issue #10648 concerned containerd 2.0 policy
adaptation during container creation and was not a substitute for this issue.
The latest upstream state was checked again before that submission.

## Validation scope

The primary validation exercised runtime → agent → policy in real VMs using
official Kata 4.2.0 QEMU, kernel, guest image, agent and genpolicy, with a separate
containerd 2.3.4 static installation. It used an ordinary BusyBox Pod without
OpenShell, CAA, cloud services or a custom guest. Pod/CRI inputs, guest, complete
generated policy and all configuration were fixed across comparisons on both the
4.2.0 and PR `main` baselines:

| Observation | Original | Patched | Switched back to original |
| --- | --- | --- | --- |
| Container start | Succeeds | Succeeds | Succeeds |
| Exec field received by the agent | false | true | false |
| Approved probe | Policy denial | Exit 0 | Policy denial |
| Wrong command / UID 0 | Denied | Denied | Denied |

The agent's native request logs and denial text returned through CRI were saved.
Comparing the corresponding Process objects showed that only `NoNewPrivileges`
changed. All test containers, sandboxes and VMs were cleaned up, and the separate
containerd was stopped. The shared cluster was unchanged. Debug consoles were
used only to read existing logs in these isolated test VMs; every probe ran
through the normal CRI/containerd path. Policy enforcement remained active and
all negative cases stayed denied.

Earlier PeerPods health captures and policy replays remain background evidence,
separate from this independent live comparison. Old Pending/NotReady snapshots
are not attributed to this field, and later deployments involving multiple
components are not treated as a comparison of this patch alone. The added Go
assertions prevent regressions; synthetic OPA cases provide supplementary evidence.

Kata 4.2.0 used Go 1.26.7; the PR's `main` baseline used its required Go 1.26.8.
On both baselines, applying only the tests failed and adding the fix made them
pass. The PR baseline also passed `go vet ./virtcontainers`, the official Go shim
build, gofmt and diff whitespace checks. No kubelet was run, so Kubernetes
Ready/liveness transitions were not measured. Cloud TDX/OpenShell lifecycle
tests, the complete `make check`/`make test` suites and upstream CI across backends
were not rerun for this isolated validation.

The official `kata-collect-data.sh`, actual configuration and raw logs were saved
under `.local/kata-exec-live-20261012/`. The official collector's unmodified output
was published to the issue with the author's authorization. The issue and PR
bodies directly described the minimal Kata reproduction and the
original/patched/original comparison; OpenShell appeared only as one sentence
of discovery context. Detailed logs and fixtures remained local validation
records, and the published bodies did not depend on a separate review branch.
The submitted `fix-exec-no-new-privileges` branch changed only two Go files.

Local policy reproduction requires an existing OPA 1.18.2 binary and the matching
complete Kata checkout:

```bash
python3.11 patches/kata-containers/upstream/reproduce-policy.py \
  --kata-source .local/kata-community --opa "$PWD/.local/opa-diagnostic"
```

With the same policy and container state, the permitted probe with true is
allowed. Changing only the field to false, using the wrong command or UID 0, or
adding `CAP_SYS_ADMIN` is denied. The tool supports the verified rule hashes for
4.2.0 and the PR's `main` baseline, using their respective container state formats.
