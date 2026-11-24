# Run your first agent

After [deployment](deployment.md), use the official OpenShell CLI and each
harness's native configuration. The default Community image already contains
OpenCode, Codex and Claude Code. Attestation and encrypted workspace setup
happen automatically when OpenShell creates a sandbox.

## Connect to the deployed Gateway

On trusted host **T**, once per terminal:

```bash
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
export OPENSHELL_GATEWAY=confidential-local
export OPENSHELL_WORKSPACE=default
harness_dir=/opt/confidential-openshell/deployment/harness
export OPENSHELL_SANDBOX_POLICY="$harness_dir/community-policy.yaml"
export OPENSHELL_PROVISION_TIMEOUT=900
export OPENSHELL_LIFECYCLE_TIMEOUT=900
openshell whoami
CONFIG_DIR=/var/lib/openshell-confidential/operator/harness
```

The deployment selects the Community image; no image build or `--from` is
needed here. Use sandbox names of at most 19 characters.

The policy is the pinned Community image's default, with only the three obsolete
`tls: terminate` fields removed as required by the
[upstream format migration][upstream-format-migration]. All upstream
destinations, binaries and permissions are preserved. This explicit copy is
needed because the policy embedded in the pinned image still has the old syntax;
OpenShell rejects it if selected automatically. The selected inference provider
adds its endpoint access. This is separate from the Kata policy that validates
container creation inside the guest.

## Configure inference once

Follow the [Bailian example](bailian.md) to select your endpoint/model, create
an OpenShell provider and save the native client configuration files. It takes
the endpoint once and uses it for both the provider profile and client configs.
An existing provider and matching client config can be reused.

| Harness | OpenShell provider | Client configuration on T |
| --- | --- | --- |
| OpenCode | `bailian-openai` | `$CONFIG_DIR/opencode.json` |
| Codex | `bailian-openai` | `$CONFIG_DIR/codex.toml` |
| Claude Code | `bailian-anthropic` | `$CONFIG_DIR/claude.json` |

API keys are entered on T through `openshell provider create`. The workload
receives placeholders; the supervisor checks the destination and substitutes the
real credential. Client config files contain the endpoint and model, not keys.

For native Kata with the pinned Community image, add `--memory 16Gi` to each
`sandbox create` command below so the guest can unpack its layers in memory.

## OpenCode

On **T**, create a shell, upload the OpenCode config and connect:

```bash
SANDBOX=opencode-demo
openshell sandbox create --name "$SANDBOX" --provider bailian-openai \
  --tty --detach
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/opencode.json" \
  /sandbox/opencode.json --no-git-ignore
openshell sandbox connect "$SANDBOX"
```

In the **sandbox shell**:

```bash
opencode
```

OpenCode reads `/sandbox/opencode.json` from its working directory. Start it
inside the connected terminal so its interactive UI can initialize normally.

## Codex

On **T**:

```bash
SANDBOX=codex-demo
openshell sandbox create --name "$SANDBOX" --provider bailian-openai \
  --tty --detach
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/codex.toml" \
  /sandbox/.codex/config.toml --no-git-ignore
openshell sandbox connect "$SANDBOX"
```

In the **sandbox shell**:

```bash
codex --sandbox danger-full-access
```

The Community user's home is `/sandbox`, so Codex reads its native
`~/.codex/config.toml`. The selected endpoint/model must support Responses,
including tool calls and follow-up tool results. OpenShell supplies the
filesystem, process and network isolation, so this command disables Codex's
additional inner sandbox. It follows the
[upstream Codex harness][upstream-codex-harness], while retaining the
interactive CLI's normal approval configuration. Use this command inside the
connected OpenShell sandbox.

## Claude Code

On **T**:

```bash
SANDBOX=claude-demo
openshell sandbox create --name "$SANDBOX" --provider bailian-anthropic \
  --tty --detach
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/claude.json" \
  /sandbox/claude.json --no-git-ignore
openshell sandbox connect "$SANDBOX"
```

In the **sandbox shell**:

```bash
claude --bare --settings /sandbox/claude.json
```

`--settings` loads the native config. `--bare` skips automatic discovery and
first-run Anthropic connectivity checks for this custom endpoint. Complete any
normal terminal and workspace trust prompts.

## Reconnect, stop/start and delete

Press **Ctrl-P, then Ctrl-Q** to detach. Back on **T**, reconnect with:

```bash
openshell sandbox connect "$SANDBOX"
```

Finish writing and close your files under `/sandbox`. A normal Gateway
stop/start preserves those files and uploaded configs. Processes restart, so
reconnect and run the harness command again:

```bash
openshell sandbox stop "$SANDBOX"
openshell sandbox start "$SANDBOX"
openshell sandbox connect "$SANDBOX"
```

If Kubernetes replaces the workload Pod, use the same Gateway stop/start
sequence to recover the workspace. For a native local PV, use the same worker.

Delete the sandbox when finished. With a static local PV and reclaim policy
`Retain`, the storage administrator also disposes of the released volume:

```bash
openshell sandbox delete "$SANDBOX"
```

Provider/profile management, file transfer and lifecycle commands are the
[standard OpenShell workflow][standard-openshell-workflow].

[upstream-format-migration]:
  https://github.com/NVIDIA/OpenShell/blob/ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47/docs/upgrade/0-1-0.mdx
[upstream-codex-harness]:
  https://github.com/NVIDIA/OpenShell/blob/ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47/scripts/agents/runtime/harnesses/codex/exec.sh#L84
[standard-openshell-workflow]:
  https://github.com/NVIDIA/OpenShell/blob/v0.1.9/docs/about/run-your-first-agent.mdx
