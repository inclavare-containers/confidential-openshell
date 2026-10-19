# Native agent task acceptance

Follow [the first-agent walkthrough](../../docs/first-agent.md) on the installed
confidential Gateway. Repeat it for OpenCode, Codex and Claude Code using the
pinned Community image. Use native CLI creation and interactive reconnect, ask
each harness to complete the public coding task with tools, download the result,
restart the same sandbox and delete its owned resources.

`fixtures/project` contains a broken clamp function, four public tests and the
task instructions. The agent must edit the function and execute the tests itself.
Credentials and generated task results do not belong in the fixture or image.

The small collector has two independent checks:

```sh
# Optional: read an OpenCode run --format json event stream from stdin.
python3 tests/e2e/collect.py --output /path/to/agent-events.json

# Read the downloaded clamp.py, test_clamp.py and result.json.
python3 tests/e2e/collect.py --work /path/to/downloaded-work --output /path/to/work-check.json
```

The event check accepts OpenCode's JSON format only; it does not parse Codex or
Claude transcripts. It requires model text, a completed edit, a successful
`python3 test_clamp.py` tool call and final stop in one session. It retains counts
and hashes, without copying model text or tool output into the summary. The work
check applies to all three harnesses. It requires unchanged public tests and the
expected result file, then checks 140 boundary cases by interpreting a small AST
grammar. It never executes or
imports downloaded source on the trusted host. Outputs use mode 0600 and must not
already exist.

These checks cover application behavior. Workspace restart must preserve the
original sandbox identity and task files; resource cleanup must be checked
against its recorded owner IDs. See the [deployment checks](../../docs/deployment.md#10-verify-both-confidential-roles)
for attestation, resource release and lifecycle requirements.

Run the oracle regressions offline with:

```sh
python3 -m unittest discover -s tests/e2e -v
```

Synthetic events exercise rejection behavior without model calls or hardware
attestation. The [policy-engine helpers](../acceptance/README.md) test synthetic
authorization separately from this coding task.
