# Use Bailian for inference

Run this setup on trusted host **T**, after selecting the Gateway in
[first agent](first-agent.md#connect-to-the-deployed-gateway). OpenShell uses
ordinary provider profiles; the harnesses use their own config files.

## 1. Select the service and model

Choose the OpenAI-compatible Base URL that matches your API key:

| Beijing service | `BASE_URL` |
| --- | --- |
| Pay-as-you-go | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| Coding Plan | `https://coding.dashscope.aliyuncs.com/v1` |

The key must match the plan and region. Workspace-specific or other-region URLs
from your console can also be used. See [Bailian endpoints](https://help.aliyun.com/zh/model-studio/base-url)
and [Coding Plan credentials](https://help.aliyun.com/zh/model-studio/coding-plan).

Set the URL once below; for Coding Plan, replace only the `BASE_URL` value.
Enter a model ID enabled in your Bailian account. Codex needs a model supporting
[Responses](https://help.aliyun.com/zh/model-studio/codex); OpenCode uses Chat
Completions and Claude Code uses Messages.

```bash
cd /opt/confidential-openshell
CONFIG_DIR=/var/lib/openshell-confidential/operator/harness
install -d -m 0700 "$CONFIG_DIR"
BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
read -r -p 'Bailian model ID: ' MODEL
BAILIAN_HOST=${BASE_URL#https://}
BAILIAN_HOST=${BAILIAN_HOST%%/*}
ANTHROPIC_BASE_URL="https://${BAILIAN_HOST}/apps/anthropic"
```

## 2. Save native client configurations

These files contain no API key. The model and endpoint above populate all three
clients; no second endpoint entry is needed when starting a harness.

**OpenCode** — generate its native JSON config:

```bash
jq --arg base "$BASE_URL" --arg model "$MODEL" '
  .model = ("bailian/" + $model) |
  .provider.bailian.options.baseURL = $base |
  .provider.bailian.models = {($model): {name: $model}}
' deployment/harness/opencode.example.json > "$CONFIG_DIR/opencode.json"
```

**Codex** — save a native custom-provider config:

```bash
cat > "$CONFIG_DIR/codex.toml" <<EOF_CONFIG
model = "$MODEL"
model_provider = "bailian"

[model_providers.bailian]
name = "Bailian"
base_url = "$BASE_URL"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
EOF_CONFIG
```

This uses Codex's [native custom-provider settings](https://developers.openai.com/codex/config-advanced/#custom-model-providers).

**Claude Code** — save native settings for the
[Bailian Messages endpoint](https://help.aliyun.com/zh/model-studio/anthropic-api-messages):

```bash
jq -n --arg base "$ANTHROPIC_BASE_URL" --arg model "$MODEL" '
  {model: $model, env: {
    ANTHROPIC_BASE_URL: $base,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
  }}
' > "$CONFIG_DIR/claude.json"
```

## 3. Create the provider you need

Read the matching Bailian API key into this terminal, without echoing it or
writing it to a file:

```bash
read -r -s -p 'Bailian API key: ' BAILIAN_API_KEY
printf '\n'
```

For **OpenCode or Codex**, import the profile and create the provider:

```bash
sed "s/dashscope.aliyuncs.com/${BAILIAN_HOST}/" deployment/harness/bailian-openai.yaml > "$CONFIG_DIR/bailian-openai.yaml"
openshell profile lint --file "$CONFIG_DIR/bailian-openai.yaml"
openshell profile import --file "$CONFIG_DIR/bailian-openai.yaml"
OPENAI_API_KEY="$BAILIAN_API_KEY" openshell provider create \
  --name bailian-openai --type bailian-openai --from-existing
```

For **Claude Code**, use its Anthropic-compatible profile instead:

```bash
sed "s/dashscope.aliyuncs.com/${BAILIAN_HOST}/" deployment/harness/bailian-anthropic.yaml > "$CONFIG_DIR/bailian-anthropic.yaml"
openshell profile lint --file "$CONFIG_DIR/bailian-anthropic.yaml"
openshell profile import --file "$CONFIG_DIR/bailian-anthropic.yaml"
ANTHROPIC_API_KEY="$BAILIAN_API_KEY" openshell provider create \
  --name bailian-anthropic --type bailian-anthropic --from-existing
```

Create both when using all three harnesses. Then clear the temporary shell value
and check the provider names:

```bash
unset BAILIAN_API_KEY
openshell provider list
```

Return to [first agent](first-agent.md#opencode) and run your chosen harness.
Other inference services follow the same native flow: select their API protocol,
set the profile's host and client Base URL together, and use their model ID.
