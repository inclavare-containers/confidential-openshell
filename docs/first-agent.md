# Run coding harnesses

Use the digest-pinned OpenShell Community image configured as the driver's
default. It includes OpenCode, Codex and Claude Code; no image build or `--from`
is needed. Create a sandbox with its default shell, connect, then start the
harness inside that connected session.

## 1. Select the Gateway on trusted host T

After [deployment](deployment.md), run these commands on **trusted host T** using
the installed official OpenShell v0.1.3 CLI and operator identity:

```bash
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
export OPENSHELL_GATEWAY=confidential-local
export OPENSHELL_WORKSPACE=default
export OPENSHELL_SANDBOX_POLICY=/opt/confidential-openshell/deployment/harness/policy.yaml
export OPENSHELL_PROVISION_TIMEOUT=900
export OPENSHELL_LIFECYCLE_TIMEOUT=900
openshell whoami --output json
cd /opt/confidential-openshell
CONFIG_DIR=/var/lib/openshell-confidential/operator/harness
install -d -m 0700 "$CONFIG_DIR"
```

Use a unique sandbox name of at most 19 characters. First creation includes
attestation and workspace initialization. The supplied policy overrides the
Community image's older policy schema; attached providers grant approved egress.
The deployment allows 15 minutes for bootstrap, including image preparation.

## 2. Configure providers once on T

The administrator may reuse existing providers. For OpenCode/Codex, copy the
[OpenAI-compatible profile](../deployment/harness/openai-compatible.example.yaml),
set the approved HTTPS host/port, then run on **T**:

```bash
install -m 0600 deployment/harness/openai-compatible.example.yaml "$CONFIG_DIR/openai.yaml"
${EDITOR:-vi} "$CONFIG_DIR/openai.yaml"
openshell profile lint --file "$CONFIG_DIR/openai.yaml"
openshell profile import --file "$CONFIG_DIR/openai.yaml"
read -r -s -p 'OpenAI-compatible provider API key: ' OPENAI_API_KEY
printf '\n'
export OPENAI_API_KEY
openshell provider create --name coding-openai --type coding-openai --from-existing
```

OpenCode needs Chat Completions; Codex needs Responses with tool calling and
subsequent tool-result requests. For Claude Code, configure the
[Anthropic-compatible profile](../deployment/harness/anthropic-compatible.example.yaml)
for a Messages endpoint. On **T**, with the existing credential in the
administrator's private environment:

```bash
install -m 0600 deployment/harness/anthropic-compatible.example.yaml "$CONFIG_DIR/anthropic.yaml"
${EDITOR:-vi} "$CONFIG_DIR/anthropic.yaml"
openshell profile lint --file "$CONFIG_DIR/anthropic.yaml"
openshell profile import --file "$CONFIG_DIR/anthropic.yaml"
read -r -s -p 'Anthropic-compatible provider API key: ' ANTHROPIC_API_KEY
printf '\n'
export ANTHROPIC_API_KEY
openshell provider create --name coding-anthropic --type coding-anthropic --from-existing
```

Provider placeholders reach the workload; the supervisor resolves credentials at
the approved endpoint. Keep API keys out of files, images and launch arguments.
User `--env` values follow the sealed workload bootstrap after attestation;
reserved `OPENSHELL_` variables remain driver-managed. The profiles' executable
paths must match the selected Community image.

## 3. Create, connect and launch one harness

Choose one example. Each `sandbox create` below omits a trailing command, so its
main process is the default shell. Host variables reach the guest only through
the explicit `--env` inputs.

Start interactive harnesses after connecting so they can complete terminal
initialization. The pinned OpenCode version does not reliably initialize when
started without an attached terminal.

### OpenCode

On **T**, copy the [OpenCode configuration](../deployment/harness/opencode.example.json),
set its base URL/model entry, and keep `{env:OPENAI_API_KEY}` unchanged:

```bash
install -m 0600 deployment/harness/opencode.example.json "$CONFIG_DIR/opencode.json"
${EDITOR:-vi} "$CONFIG_DIR/opencode.json"
SANDBOX=opencode-demo
read -r -p 'OpenCode model identifier (including provider prefix): ' MODEL
openshell sandbox create --name "$SANDBOX" --provider coding-openai --tty --detach \
  --env "OPENCODE_CONFIG_CONTENT=$(jq -c . "$CONFIG_DIR/opencode.json")" \
  --env OPENCODE_DISABLE_MODELS_FETCH=true --env "HARNESS_MODEL=$MODEL"
openshell sandbox provider status "$SANDBOX" coding-openai --wait --timeout 30 --output json
openshell sandbox connect "$SANDBOX"
```

In the **connected sandbox shell**:

```bash
opencode -m "$HARNESS_MODEL"
```

### Codex

On **T**, select a Responses-compatible model and endpoint:

```bash
SANDBOX=codex-demo
read -r -p 'Codex model identifier: ' MODEL
read -r -p 'Responses-compatible HTTPS base URL (including /v1): ' BASE_URL
openshell sandbox create --name "$SANDBOX" --provider coding-openai --tty --detach \
  --env "HARNESS_MODEL=$MODEL" --env "HARNESS_BASE_URL=$BASE_URL"
openshell sandbox provider status "$SANDBOX" coding-openai --wait --timeout 30 --output json
openshell sandbox connect "$SANDBOX"
```

In the **connected sandbox shell**:

```bash
codex --model "$HARNESS_MODEL" \
  --config 'model_provider="approved"' \
  --config 'model_providers.approved.name="Approved endpoint"' \
  --config "model_providers.approved.base_url=\"$HARNESS_BASE_URL\"" \
  --config 'model_providers.approved.env_key="OPENAI_API_KEY"' \
  --config 'model_providers.approved.wire_api="responses"'
```

Codex's nested namespace sandbox can be unavailable inside OpenShell. Review its
normal approval prompts before allowing a retry within the outer boundary.

### Claude Code

On **T**, use the Anthropic-compatible base URL without `/v1/messages`:

```bash
SANDBOX=claude-demo
read -r -p 'Claude model identifier: ' MODEL
read -r -p 'Anthropic-compatible HTTPS base URL (without /v1/messages): ' BASE_URL
openshell sandbox create --name "$SANDBOX" --provider coding-anthropic --tty --detach \
  --env "HARNESS_MODEL=$MODEL" --env "ANTHROPIC_BASE_URL=$BASE_URL" \
  --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
openshell sandbox provider status "$SANDBOX" coding-anthropic --wait --timeout 30 --output json
openshell sandbox connect "$SANDBOX"
```

In the **connected sandbox shell**:

```bash
claude --bare --model "$HARNESS_MODEL"
```

`--bare` uses the API-key provider without automatic plugin/hook discovery or the
first-run Anthropic connectivity check. Complete normal terminal and workspace
trust prompts.

For every example, require provider target `ready` and `wait_outcome=complete`.
Exiting the harness returns to the sandbox shell. Ctrl-P followed by Ctrl-Q
detaches; `sandbox connect` reconnects to the same running session.

## 4. Stop/start and delete from T

After detaching, run on **T**:

```bash
openshell sandbox stop "$SANDBOX"
openshell sandbox start "$SANDBOX"
openshell sandbox connect "$SANDBOX"
```

Persistent mode preserves the same sandbox's files, not process memory or its
terminal session. Stop/Start starts a new shell. In the connected sandbox, run
the chosen harness command again and open the existing workspace.

After detaching, delete on **T**:

```bash
openshell sandbox delete "$SANDBOX"
openshell sandbox get "$SANDBOX" --output json
```

The final get must return explicit NotFound. The administrator checks owned cloud
cleanup through the [deployment guide](deployment.md#10-verify-both-confidential-roles).
