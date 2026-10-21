# Run your first agent

After [deployment](deployment.md), use the official OpenShell CLI and each
harness's native configuration. The default Community image already contains
OpenCode, Codex and Claude Code. Attestation and encrypted workspace setup happen
automatically when OpenShell creates a sandbox.

## Connect to the deployed Gateway

On trusted host **T**, once per terminal:

```bash
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
export OPENSHELL_GATEWAY=confidential-local
export OPENSHELL_WORKSPACE=default
export OPENSHELL_SANDBOX_POLICY=/opt/confidential-openshell/deployment/harness/policy.yaml
export OPENSHELL_PROVISION_TIMEOUT=900
export OPENSHELL_LIFECYCLE_TIMEOUT=900
openshell whoami
CONFIG_DIR=/var/lib/openshell-confidential/operator/harness
```

The deployment selects the Community image and policy; no image build or
`--from` is needed here. Use sandbox names of at most 19 characters.

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

## OpenCode

On **T**, create a shell, upload the OpenCode config and connect:

```bash
SANDBOX=opencode-demo
openshell sandbox create --name "$SANDBOX" --provider bailian-openai --tty --detach \
  --env OPENCODE_DISABLE_MODELS_FETCH=true
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/opencode.json" /sandbox/opencode.json --no-git-ignore
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
openshell sandbox create --name "$SANDBOX" --provider bailian-openai --tty --detach
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/codex.toml" /sandbox/.codex/config.toml --no-git-ignore
openshell sandbox connect "$SANDBOX"
```

In the **sandbox shell**:

```bash
codex
```

The Community user's home is `/sandbox`, so Codex reads its native
`~/.codex/config.toml`. The selected endpoint/model must support Responses, including tool calls and
follow-up tool results. Keep Codex's normal approval prompts; nested namespace
sandboxing can be unavailable inside the outer OpenShell sandbox.

## Claude Code

On **T**:

```bash
SANDBOX=claude-demo
openshell sandbox create --name "$SANDBOX" --provider bailian-anthropic --tty --detach
openshell sandbox upload "$SANDBOX" "$CONFIG_DIR/claude.json" /sandbox/claude.json --no-git-ignore
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

Stop/Start preserves workspace files and uploaded configs; processes restart.
Connect and run the harness command again:

```bash
openshell sandbox stop "$SANDBOX"
openshell sandbox start "$SANDBOX"
openshell sandbox connect "$SANDBOX"
```

Delete the sandbox and its owned workspace when finished:

```bash
openshell sandbox delete "$SANDBOX"
```

Provider/profile management, file transfer and lifecycle commands are the
[standard OpenShell workflow](https://github.com/NVIDIA/OpenShell/blob/v0.1.3/docs/about/run-your-first-agent.mdx).
