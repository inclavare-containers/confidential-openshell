package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeBinding(t *testing.T, dir, role, generation, sandbox, key, initdata string) string {
	t.Helper()
	attempt := strings.Repeat("d", 64)
	identity := sha256.Sum256([]byte("openshell-bootstrap-identity-v1\x00" + role + "\x00" + generation + "\x00" + sandbox + "\x00" + attempt))
	opaque := sha256.Sum256([]byte("openshell-bootstrap-file-v1\x00" + hex.EncodeToString(identity[:]) + "\x00" + key))
	name := hex.EncodeToString(opaque[:])
	path := "resource/default/bootstrap/" + name
	record := map[string]string{
		"resource_path":   path,
		"identity_sha256": hex.EncodeToString(identity[:]),
		"initdata_sha384": initdata,
		"role":            role,
		"generation":      generation,
		"sandbox_id":      sandbox,
		"sandbox_cr_uid":  "123e4567-e89b-12d3-a456-426614174000",
		"attempt_id":      attempt,
		"key":             key,
		"resource_sha256": strings.Repeat("e", 64),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func renderSealedPolicies(t *testing.T, dir string) (string, string) {
	t.Helper()
	policy := filepath.Join(t.TempDir(), "policy.rego")
	asPolicy := filepath.Join(t.TempDir(), "as.rego")
	command := exec.Command("python3", "../../deployment/trustee/render-kbs-policy.py", "--bindings-dir", dir,
		"--as-policy-output", asPolicy, "--output", policy)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("render KBS policy: %v: %s", err, output)
	}
	return policy, asPolicy
}

func sealedToken(t *testing.T, claims, references map[string]any) map[string]any {
	t.Helper()
	vector := map[string]any{}
	for _, claim := range []string{"hardware", "configuration", "executables", "file_system"} {
		value := evaluate(t, "tdx-podvm.rego", "data.policy."+claim, claims, map[string]any{"reference": references})
		if claim == "file_system" {
			vector["file-system"] = value
		} else {
			vector[claim] = value
		}
	}
	return map[string]any{"submods": map[string]any{"cpu0": map[string]any{
		"ear.appraisal-policy-id":         "openshell-tdx",
		"ear.status":                      "affirming",
		"ear.trustworthiness-vector":      vector,
		"ear.veraison.annotated-evidence": claims,
	}}}
}

func TestRenderedKBSSealedPolicy(t *testing.T) {
	bindings := t.TempDir()
	claims, references := approvedEvidence()
	approved := writeBinding(t, bindings, "workload", "g000000000000002a", "sandbox-1", "API_KEY", digest("6"))
	otherRole := writeBinding(t, bindings, "supervisor", strings.Repeat("a", 64), "sandbox-1", "API_KEY", digest("7"))
	stale := writeBinding(t, bindings, "workload", strings.Repeat("b", 64), "sandbox-1", "API_KEY", digest("8"))
	policy, _ := renderSealedPolicies(t, bindings)

	check := func(name, resource string, claims, refs map[string]any, allowed bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			token := sealedToken(t, claims, refs)
			got := evaluateBool(t, policy, "data.policy.allow", token, resourceData(resource))
			if got != allowed {
				t.Fatalf("allow = %t, want %t", got, allowed)
			}
		})
	}
	check("approved workload", approved, claims, references, true)
	check("wrong role", otherRole, claims, references, false)
	check("stale generation", stale, claims, references, false)
	check("unknown resource", "resource/default/bootstrap/"+strings.Repeat("f", 64), claims, references, false)
	check("signer JWK for approved TDX", "resource/default/bootstrap-signer/key", claims, references, true)

	outOfDate := cloneJSON(t, claims)
	outOfDate["tdx"].(map[string]any)["tcb_status"] = "OutOfDate"
	check("OutOfDate with approved measurements", approved, outOfDate, references, true)
	revoked := cloneJSON(t, claims)
	revoked["tdx"].(map[string]any)["tcb_status"] = "Revoked"
	check("Revoked", approved, revoked, references, false)
	check("signer JWK denies Revoked", "resource/default/bootstrap-signer/key", revoked, references, false)
	debug := cloneJSON(t, claims)
	debug["tdx"].(map[string]any)["quote"].(map[string]any)["body"].(map[string]any)["td_attributes"] = "0100001000000000"
	check("debug TD", approved, debug, references, false)
	altered := cloneJSON(t, claims)
	aaelEvent(altered)["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("9")
	check("altered initdata", approved, altered, references, false)
	duplicate := cloneJSON(t, claims)
	events := duplicate["tdx"].(map[string]any)["uefi_event_logs"].([]any)
	duplicate["tdx"].(map[string]any)["uefi_event_logs"] = append(events, aaelEvent(duplicate))
	check("duplicate AAEL", approved, duplicate, references, false)

	for _, resource := range []string{approved, otherRole, stale} {
		if !strings.HasPrefix(resource, "resource/default/bootstrap/") {
			t.Fatal(resource)
		}
	}
}

func TestRenderedASPolicyRequiresActiveMeasuredInitdata(t *testing.T) {
	bindings := t.TempDir()
	path := writeBinding(t, bindings, "workload", strings.Repeat("a", 64), "sandbox-1", "API_KEY", digest("6"))
	_, asPolicy := renderSealedPolicies(t, bindings)
	claims, refs := approvedEvidence()
	if got := evaluate(t, asPolicy, "data.policy.configuration", claims, map[string]any{"reference": refs}); fmt.Sprint(got) != "2" {
		t.Fatalf("approved dynamic initdata configuration = %v", got)
	}
	claims["tdx"].(map[string]any)["tcb_status"] = "OutOfDate"
	if got := evaluate(t, asPolicy, "data.policy.hardware", claims, map[string]any{"reference": refs}); fmt.Sprint(got) != "2" {
		t.Fatalf("OutOfDate hardware = %v", got)
	}
	other := cloneJSON(t, claims)
	aaelEvent(other)["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("7")
	if got := evaluate(t, asPolicy, "data.policy.configuration", other, map[string]any{"reference": refs}); fmt.Sprint(got) != "36" {
		t.Fatalf("unregistered initdata configuration = %v", got)
	}
	noLog := cloneJSON(t, claims)
	noLog["tdx"].(map[string]any)["uefi_event_logs"] = []any{}
	if got := evaluate(t, asPolicy, "data.policy.configuration", noLog, map[string]any{"reference": refs}); fmt.Sprint(got) != "36" {
		t.Fatalf("missing AAEL configuration = %v", got)
	}
	id := strings.TrimPrefix(path, "resource/default/bootstrap/")
	if err := os.Remove(filepath.Join(bindings, id+".json")); err != nil {
		t.Fatal(err)
	}
	_, asPolicy = renderSealedPolicies(t, bindings)
	if got := evaluate(t, asPolicy, "data.policy.configuration", claims, map[string]any{"reference": refs}); fmt.Sprint(got) != "36" {
		t.Fatalf("revoked initdata configuration = %v", got)
	}
}

func TestKBSNativeResourceMetadata(t *testing.T) {
	bindings := t.TempDir()
	resource := writeBinding(t, bindings, "workload", "generation-1", "sandbox-1", "KEY", digest("6"))
	policy, _ := renderSealedPolicies(t, bindings)
	claims, references := approvedEvidence()
	token := sealedToken(t, claims, references)
	parts := strings.Split(strings.TrimPrefix(resource, "resource/"), "/")
	for _, data := range []map[string]any{
		{"plugin": "other", "resource-path": parts},
		{"resource-path": parts},
		{"plugin": "resource", "resource-path": resource},
		{"plugin": "resource", "resource-path": parts[:2]},
		{"plugin": "resource", "resource-path": append(append([]string{}, parts...), "extra")},
		{"plugin": "resource", "resource-path": []any{"default/bootstrap", "bootstrap", parts[2]}},
		{"plugin": "resource", "resource-path": []any{"default", 7, parts[2]}},
	} {
		if evaluateBool(t, policy, "data.policy.allow", token, data) {
			t.Fatalf("invalid native resource metadata authorized: %#v", data)
		}
	}
}

func TestBindingRendererRejectsForgedIdentity(t *testing.T) {
	dir := t.TempDir()
	path := writeBinding(t, dir, "workload", strings.Repeat("a", 64), "sandbox-1", "API_KEY", digest("6"))
	name := strings.TrimPrefix(path, "resource/default/bootstrap/")
	file := filepath.Join(dir, name+".json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]string
	if err := json.Unmarshal(data, &binding); err != nil {
		t.Fatal(err)
	}
	binding["identity_sha256"] = strings.Repeat("0", 64)
	data, err = json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.rego")
	asPolicy := filepath.Join(t.TempDir(), "as.rego")
	command := exec.Command("python3", "../../deployment/trustee/render-kbs-policy.py", "--bindings-dir", dir,
		"--as-policy-output", asPolicy, "--output", policy)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatal("renderer accepted forged identity")
	} else if !strings.Contains(string(output), "identity or resource path") {
		t.Fatalf("wrong render failure: %s: %v", output, err)
	}
	if _, err := os.Stat(policy); !os.IsNotExist(err) {
		t.Fatal(fmt.Sprintf("forged binding left active policy: %v", err))
	}
}

func TestBindingRendererRejectsInvalidCRUID(t *testing.T) {
	dir := t.TempDir()
	resource := writeBinding(t, dir, "workload", "g000000000000002a", "sandbox-1", "API_KEY", digest("6"))
	filename := filepath.Join(dir, strings.TrimPrefix(resource, "resource/default/bootstrap/")+".json")
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, uid, errorText string
		missing              bool
	}{
		{name: "missing", missing: true, errorText: "binding schema mismatch"},
		{name: "empty", uid: "", errorText: "invalid Sandbox CR UID"},
		{name: "unsafe", uid: "../replacement", errorText: "invalid Sandbox CR UID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var binding map[string]string
			if err := json.Unmarshal(original, &binding); err != nil {
				t.Fatal(err)
			}
			if tc.missing {
				delete(binding, "sandbox_cr_uid")
			} else {
				binding["sandbox_cr_uid"] = tc.uid
			}
			encoded, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			outputDir := t.TempDir()
			policy := filepath.Join(outputDir, "kbs.rego")
			command := exec.Command("python3", "../../deployment/trustee/render-kbs-policy.py", "--bindings-dir", dir,
				"--as-policy-output", filepath.Join(outputDir, "as.rego"), "--output", policy)
			if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), tc.errorText) {
				t.Fatalf("renderer accepted invalid CR UID: err=%v output=%s", err, output)
			}
			if _, err := os.Stat(policy); !os.IsNotExist(err) {
				t.Fatal("invalid binding left active policy")
			}
		})
	}
}

func TestRendererScalesPastTrusteeLineLimit(t *testing.T) {
	bindings := t.TempDir()
	var approved string
	for i := 0; i < 15; i++ {
		measurement := fmt.Sprintf("%096x", i%12+1)
		if i == 0 {
			measurement = digest("6")
		}
		resource := writeBinding(t, bindings, "workload", fmt.Sprintf("g%016x", i+1),
			fmt.Sprintf("sandbox-%d", i), fmt.Sprintf("KEY_%d", i), measurement)
		if i == 0 {
			approved = resource
		}
	}
	policy, asPolicy := renderSealedPolicies(t, bindings)
	for _, path := range []string{policy, asPolicy} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, text := range strings.Split(string(content), "\n") {
			if len(text) >= 1024 {
				t.Fatalf("%s line %d exceeds released Trustee's Regorus limit", path, line+1)
			}
		}
	}
	claims, refs := approvedEvidence()
	token := sealedToken(t, claims, refs)
	if !evaluateBool(t, policy, "data.policy.allow", token, resourceData(approved)) {
		t.Fatal("approved resource was denied after multiline rendering")
	}
	if got := evaluate(t, asPolicy, "data.policy.configuration", claims,
		map[string]any{"reference": refs}); fmt.Sprint(got) != "2" {
		t.Fatalf("approved dynamic AS policy configuration = %v", got)
	}
}

func TestWorkspaceBindingTracksCurrentWorkload(t *testing.T) {
	bindings := t.TempDir()
	workspaceBindings := t.TempDir()
	namespace, sandboxUID := "openshell", "a9b8c7d6-1234-4567-89ab-fedcba987654"
	identity := sha256.Sum256([]byte("openshell-workspace-v1\x00" + namespace + "\x00" + sandboxUID))
	id := hex.EncodeToString(identity[:])
	resource := "resource/default/workspace/" + id
	record := map[string]string{
		"resource_path": resource, "initdata_sha384": digest("6"),
		"namespace": namespace, "sandbox_cr_uid": sandboxUID,
		"resource_sha256": strings.Repeat("e", 64), "identity_sha256": id,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspaceBindings, id+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.rego")
	asPolicy := filepath.Join(t.TempDir(), "as.rego")
	command := exec.Command("python3", "../../deployment/trustee/render-kbs-policy.py", "--bindings-dir", bindings,
		"--workspace-bindings-dir", workspaceBindings, "--as-policy-output", asPolicy, "--output", policy)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("render workspace policy: %v: %s", err, output)
	}
	claims, refs := approvedEvidence()
	token := sealedToken(t, claims, refs)
	if !evaluateBool(t, policy, "data.policy.allow", token, resourceData(resource)) {
		t.Fatal("current measured workload cannot access its stable workspace key")
	}
	changed := cloneJSON(t, claims)
	aaelEvent(changed)["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("7")
	if evaluateBool(t, policy, "data.policy.allow", sealedToken(t, changed, refs), resourceData(resource)) {
		t.Fatal("old or other workload initdata accessed current workspace key")
	}
}
