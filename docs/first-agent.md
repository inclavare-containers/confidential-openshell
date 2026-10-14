# First agent on a confidential gateway

Use the official OpenShell v0.1.3 CLI on trusted host T after
[deployment](deployment.md). OpenCode runs in the workload guest; native supervisor
egress supplies provider credentials to the approved endpoint.

## 1. Set the connection inputs

The administrator supplies the Gateway/workspace, a digest-pinned agent image,
an existing provider with the `confidential-opencode` profile, and a model that
supports chat completions and tool calling. Choose a unique sandbox name of at
most 19 characters.

```bash
set -euo pipefail
umask 077
cd /opt/confidential-openshell
GATEWAY=REPLACE_WITH_GATEWAY
WORKSPACE=REPLACE_WITH_WORKSPACE
AGENT_IMAGE=REPLACE_WITH_REPOSITORY_AT_SHA256
PROVIDER=REPLACE_WITH_PROVIDER_NAME
AGENT_MODEL=confidential/REPLACE_WITH_MODEL_ID
SANDBOX=REPLACE_WITH_UNIQUE_NAME
OPERATOR_DIR=/var/lib/openshell-confidential/operator
export OPENSHELL_PROVISION_TIMEOUT=900
export OPENSHELL_LIFECYCLE_TIMEOUT=900
case "$AGENT_IMAGE" in *@sha256:*) ;; *) exit 1 ;; esac
openshell --version
```

The CLI defaults to 300 seconds. The bounded 900-second settings allow first-use
whole-disk checks and encryption setup; workers also need the runbook's
`create_container_timeout=600`. The [pinned upstream guide](https://github.com/NVIDIA/OpenShell/blob/e1f3c82caa3ed3b65de22889ae7ef32a774878ef/docs/about/run-your-first-agent.mdx)
uses the same image/provider/command flow.

## 2. Match the provider configuration

Create private copies of the endpoint/model templates. Match the HTTPS hostname,
port, API path and model to the installed provider.

```bash
CONFIG_DIR="$OPERATOR_DIR/agent-config/$SANDBOX"
test ! -e "$CONFIG_DIR"
install -d -m 0700 "$CONFIG_DIR"
install -m 0600 deployment/agent/provider-profile.example.yaml "$CONFIG_DIR/profile.yaml"
install -m 0600 deployment/agent/opencode.example.json "$CONFIG_DIR/opencode.json"
${EDITOR:-vi} "$CONFIG_DIR/profile.yaml" "$CONFIG_DIR/opencode.json"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" profile lint --file "$CONFIG_DIR/profile.yaml"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" profile describe confidential-opencode --output json
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" provider list --output json
```

Check the provider name/type and `OPENAI_API_KEY` credential environment. Follow
`next_page_token` with `--page-token` when listing providers. If the provider is
absent, the administrator imports the profile and creates it from the credential
already in their private environment:

```bash
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" profile import --file "$CONFIG_DIR/profile.yaml"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" provider create \
  --name "$PROVIDER" --type confidential-opencode --from-existing
```

Keep `{env:OPENAI_API_KEY}` in `opencode.json`. OpenShell puts a placeholder in the
workload and resolves it at supervisor egress. The profile permits OpenCode's
executable at the configured endpoint; credentials stay out of configs and images.

## 3. Create and attach

```bash
timeout 930s openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox create \
  --name "$SANDBOX" --from "$AGENT_IMAGE" --provider "$PROVIDER" --no-auto-providers --tty --detach \
  --env "OPENCODE_CONFIG_CONTENT=$(jq -c . "$CONFIG_DIR/opencode.json")" \
  -- /usr/local/bin/opencode -m "$AGENT_MODEL"
STATE=$(openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox get "$SANDBOX" --output json)
jq -e '.phase == "Ready" and .configuration_admission.state == "accepted"' <<< "$STATE"
SANDBOX_ID=$(jq -er .id <<< "$STATE")
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox provider status "$SANDBOX" "$PROVIDER" \
  --wait --timeout 30 --output json
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox connect "$SANDBOX"
```

Require provider target `ready` and `wait_outcome=complete`, with matching installed
epochs/revisions. `--no-auto-providers` can skip a missing provider; creation alone
does not prove attachment. A timeout can leave resources allocated, so delete
before retrying. Ctrl-P then Ctrl-Q detaches without stopping the main process.

## 4. Work with files

Upload after creation: `create --upload` cannot accompany an explicit main command.
A directory upload nests its basename. This example uses the repository's coding
fixture, placed at `/sandbox/project`:

```bash
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox upload \
  "$SANDBOX" tests/e2e/fixtures/project /sandbox
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox connect "$SANDBOX"
```

Give OpenCode `/sandbox/project/TASK.txt`, inspect its changes, then detach and
read back the result:

```bash
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox exec --name "$SANDBOX" \
  --workdir /sandbox/project --no-tty --no-login-shell -- python3 test_clamp.py
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox download \
  "$SANDBOX" /sandbox/project/result.json "$CONFIG_DIR/result.json"
```

For a scripted task and independent result checks, see
[the agent fixture](../tests/e2e/README.md).

## 5. Stop/start and delete

Persistent workspace mode preserves the original sandbox's files across restart.
Check the same ID and read back your files; ephemeral mode has no retained workspace.

```bash
timeout 930s openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox stop "$SANDBOX"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox get "$SANDBOX" --output json | \
  jq -e '.phase == "Stopped"'
timeout 930s openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox start "$SANDBOX"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox get "$SANDBOX" --output json | \
  jq -e --arg id "$SANDBOX_ID" '.id == $id and .phase == "Ready" and .configuration_admission.state == "accepted"'
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox provider status "$SANDBOX" "$PROVIDER" \
  --wait --timeout 30 --output json
timeout 330s openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox delete "$SANDBOX"
openshell --gateway "$GATEWAY" --workspace "$WORKSPACE" sandbox get "$SANDBOX" --output json
```

The final get must return explicit NotFound; an authentication or transport error
does not prove deletion. The administrator confirms controller/cloud cleanup of
the original owner IDs as described in the [deployment checks](deployment.md#10-verify-both-confidential-roles).
Normal delete withdraws serving copies and authorization while retaining private
workspace recovery keys/journals on T; see [upgrade and retention](upgrade.md).
