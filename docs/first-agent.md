# Run coding harnesses

The deployment uses the unmodified, digest-pinned OpenShell Community base image
as the driver's default workload image. It includes OpenCode, Codex, Claude Code,
Python and Git. No harness image build or `--from` argument is needed.

Use native OpenShell v0.1.3 `sandbox create` and `sandbox connect`. Attach
providers explicitly with `--provider`.

## 1. Select the Gateway and workspace

Run on trusted host T after [deployment](deployment.md), using the official CLI
and the operator identity configured there:

```bash
export XDG_CONFIG_HOME=/var/lib/openshell-confidential/cli-config
export OPENSHELL_LOCAL_TLS_DIR=/var/lib/openshell-confidential/tls
export OPENSHELL_GATEWAY=confidential-local
export OPENSHELL_WORKSPACE=default
export OPENSHELL_SANDBOX_POLICY=/opt/confidential-openshell/deployment/harness/policy.yaml
export OPENSHELL_PROVISION_TIMEOUT=900
export OPENSHELL_LIFECYCLE_TIMEOUT=900
openshell --version
openshell whoami --output json
```

Use a unique sandbox name of at most 19 characters. First creation includes guest
startup, attestation and workspace initialization. Later starts reuse the files.

The pinned Community image contains a policy in an older schema. The native
`OPENSHELL_SANDBOX_POLICY` setting selects the supplied restrictive policy instead;
attached providers supply approved network access. The image stays unchanged.

## 2. Configure the model provider

The administrator creates providers once; users attach their names when creating
sandboxes. Existing suitable providers can be reused.

For OpenCode and Codex, copy the [OpenAI-compatible profile](../deployment/harness/openai-compatible.example.yaml)
to a private location and set its exact approved HTTPS host and port. The endpoint
must support Chat Completions for OpenCode and Responses for Codex.
Codex needs Responses tool calling, including the next request carrying tool
output; check that the chosen model supports this complete exchange.

```bash
install -d -m 0700 /var/lib/openshell-confidential/operator/harness
cd /opt/confidential-openshell
CONFIG_DIR=/var/lib/openshell-confidential/operator/harness
install -m 0600 deployment/harness/openai-compatible.example.yaml "$CONFIG_DIR/openai.yaml"
${EDITOR:-vi} "$CONFIG_DIR/openai.yaml"
openshell profile lint --file "$CONFIG_DIR/openai.yaml"
openshell profile import --file "$CONFIG_DIR/openai.yaml"
# OPENAI_API_KEY must already be set in the administrator's private environment.
openshell provider create --name coding-openai --type coding-openai --from-existing
```

For Claude Code, use the [Anthropic-compatible profile](../deployment/harness/anthropic-compatible.example.yaml)
and an endpoint that supports Anthropic Messages:

```bash
install -m 0600 deployment/harness/anthropic-compatible.example.yaml "$CONFIG_DIR/anthropic.yaml"
${EDITOR:-vi} "$CONFIG_DIR/anthropic.yaml"
openshell profile lint --file "$CONFIG_DIR/anthropic.yaml"
openshell profile import --file "$CONFIG_DIR/anthropic.yaml"
# ANTHROPIC_API_KEY must already be set in the administrator's private environment.
openshell provider create --name coding-anthropic --type coding-anthropic --from-existing
```

Keep API keys out of image layers, configuration files and launch arguments.
OpenShell supplies credential placeholders and resolves them at the supervisor's
approved egress endpoint. User environment configuration follows the sealed
workload bootstrap path after attestation; Kubernetes objects do not carry its
plaintext. Reserved `OPENSHELL_` variables remain driver-managed.

The profile paths match the pinned Community image. Recheck executable paths
when changing that image; granting network access to a general interpreter is
unnecessary for these native clients.

## 3. Start a harness

Choose one of the following. Set `MODEL` to a model supported by the endpoint and
choose a different `SANDBOX` name for each instance. These commands start the
harness as the sandbox's main process. Remove `--detach` to attach immediately.

### OpenCode

Copy the [OpenCode configuration](../deployment/harness/opencode.example.json),
then set its base URL and model entry. Keep `{env:OPENAI_API_KEY}` as written.

```bash
install -m 0600 deployment/harness/opencode.example.json "$CONFIG_DIR/opencode.json"
${EDITOR:-vi} "$CONFIG_DIR/opencode.json"
SANDBOX=opencode-demo
MODEL=REPLACE_WITH_MODEL_ID
PROVIDER=coding-openai
openshell sandbox create --name "$SANDBOX" --provider "$PROVIDER" --tty --detach \
  --env "OPENCODE_CONFIG_CONTENT=$(jq -c . "$CONFIG_DIR/opencode.json")" \
  --env OPENCODE_DISABLE_MODELS_FETCH=true \
  -- opencode -m "approved/$MODEL"
```

### Codex

Use an OpenAI-compatible endpoint with Responses support. The configuration flags
are native Codex options; the key comes from the attached provider.

```bash
SANDBOX=codex-demo
MODEL=REPLACE_WITH_MODEL_ID
BASE_URL=https://REPLACE_WITH_APPROVED_HOST/v1
PROVIDER=coding-openai
openshell sandbox create --name "$SANDBOX" --provider "$PROVIDER" --tty --detach \
  -- codex --model "$MODEL" \
  --config 'model_provider="approved"' \
  --config 'model_providers.approved.name="Approved endpoint"' \
  --config "model_providers.approved.base_url=\"$BASE_URL\"" \
  --config 'model_providers.approved.env_key="OPENAI_API_KEY"' \
  --config 'model_providers.approved.wire_api="responses"'
```

Codex's nested namespace sandbox can be unavailable inside OpenShell. Its normal
approval flow can retry a command within the outer OpenShell boundary; review
the proposed command before approving it.

### Claude Code

Set the Anthropic-compatible base URL, without the `/v1/messages` suffix:

```bash
SANDBOX=claude-demo
MODEL=REPLACE_WITH_MODEL_ID
BASE_URL=https://REPLACE_WITH_APPROVED_HOST
PROVIDER=coding-anthropic
openshell sandbox create --name "$SANDBOX" --provider "$PROVIDER" --tty --detach \
  --env "ANTHROPIC_BASE_URL=$BASE_URL" \
  --env CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  -- claude --bare --model "$MODEL"
```

The native `--bare` mode uses the API-key provider without the first-run
Anthropic connectivity check. It keeps coding tools available and skips plugin,
hook and other automatic discovery. Complete the terminal theme and workspace
trust prompts normally.

## 4. Connect and run a task

Confirm that the provider was applied, then connect to the running harness:

```bash
openshell sandbox provider status "$SANDBOX" "$PROVIDER" --wait --timeout 30 --output json
openshell sandbox connect "$SANDBOX"
```

Require provider target `ready` and `wait_outcome=complete`. Complete the harness's
normal first-run prompts. Ctrl-P followed by Ctrl-Q detaches while leaving the
main process running; `sandbox connect` attaches to that same process again.

To check editing and tool execution, upload the public coding task after creation:

```bash
openshell sandbox upload "$SANDBOX" tests/e2e/fixtures/project /sandbox
openshell sandbox connect "$SANDBOX"
```

Ask the harness to follow `/sandbox/project/TASK.txt`. Review its proposed actions
and allow the required file edits and test command. After it finishes, detach and
check the result independently:

```bash
openshell sandbox exec --name "$SANDBOX" --workdir /sandbox/project \
  --no-tty --no-login-shell -- python3 test_clamp.py
openshell sandbox download "$SANDBOX" /sandbox/project ./downloaded-work
python3 tests/e2e/collect.py --work ./downloaded-work --output ./work-check.json
```

Use a fresh download directory and output file for each run. The oracle checks
the downloaded implementation and unchanged public tests without executing
workload code on the trusted host. See [task checks](../tests/e2e/README.md).

## 5. Restart and delete

In persistent workspace mode, Stop/Start preserves the sandbox identity and files.
It starts a new main process; it does not preserve process memory or a terminal
session. Reconnect and check the task files after starting:

```bash
openshell sandbox stop "$SANDBOX"
openshell sandbox start "$SANDBOX"
openshell sandbox provider status "$SANDBOX" "$PROVIDER" --wait --timeout 30 --output json
openshell sandbox connect "$SANDBOX"
openshell sandbox delete "$SANDBOX"
openshell sandbox get "$SANDBOX" --output json
```

The final get must return explicit NotFound. The administrator verifies owned
cloud-resource cleanup and the confidential-role checks in the
[deployment guide](deployment.md#10-verify-both-confidential-roles).
