package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func TestWorkspaceMountsUseReleasedKataRules(t *testing.T) {
	stock, err := os.ReadFile("../../artifacts/cache/kata-policy/rules.rego")
	if err != nil {
		t.Fatal(err)
	}
	extension, err := os.ReadFile("../../deployment/policy/agent-policy-workload.rego")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"common": map[string]any{"sfprefix": "/shared/", "cpath": "/run/kata-containers"},
		"workspace_mounts": map[string]any{"agent": map[string]any{"/sandbox": "d-workspace"}, "workspace-init": map[string]any{"/init": "d-workspace"}}}
	ctx := context.Background()
	query, err := rego.New(rego.Query(`data.agent_policy.allow_anno_key_value("io.confidentialcontainers.org.cloud_volumes",input.annotation,input.container); data.agent_policy.check_mount(input.expected,input.mount,"bundle","sandbox")`),
		rego.Module("policy.rego", string(stock)+"\n"+string(extension)+"\npolicy_data := data.generated"), rego.Store(inmem.NewFromObject(map[string]any{"generated": data}))).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, container, destination, disk, source, mode string
		allowed                                          bool
	}{
		{"workload", "agent", "/sandbox", "d-workspace", "/run/cloud-volumes/d-workspace", "rw", true},
		{"init container", "workspace-init", "/init", "d-workspace", "/run/cloud-volumes/d-workspace", "rw", true},
		{"other disk", "agent", "/sandbox", "d-other", "/run/cloud-volumes/d-other", "rw", false},
		{"other source", "agent", "/sandbox", "d-workspace", "/shared/sandbox", "rw", false},
		{"other destination", "agent", "/elsewhere", "d-workspace", "/run/cloud-volumes/d-workspace", "rw", false},
		{"other container", "other", "/sandbox", "d-workspace", "/run/cloud-volumes/d-workspace", "rw", false},
		{"mount options", "agent", "/sandbox", "d-workspace", "/run/cloud-volumes/d-workspace", "ro", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(map[string]any{"vol-0": map[string]string{"mount_point": tc.destination, "disk_id": tc.disk}})
			if err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"annotation": string(encoded), "container": map[string]any{"OCI": map[string]any{"Annotations": map[string]string{"io.kubernetes.cri.container-name": tc.container}}},
				"expected": map[string]any{"source": "^/run/cloud-volumes/d-workspace$", "destination": tc.destination, "type_": "bind", "options": []string{"rbind", "rprivate", "rw"}},
				"mount":    map[string]any{"source": tc.source, "destination": tc.destination, "type_": "bind", "options": []string{"rbind", "rprivate", tc.mode}}}
			result, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil || (len(result) > 0) != tc.allowed {
				t.Fatalf("result=%v want allowed=%v error=%v", result, tc.allowed, err)
			}
		})
	}
}
