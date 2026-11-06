package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

func TestWorkspaceCloudVolumeMetadata(t *testing.T) {
	module, err := os.ReadFile("../../deployment/policy/agent-policy-workload.rego")
	if err != nil {
		t.Fatal(err)
	}
	resolved := strings.ReplaceAll(string(module), "__WORKSPACE_MOUNTS__", `{"agent":["/sandbox"],"workspace-init":["/mnt/openshell-workspace"]}`)
	base := map[string]any{
		"mount_point": "/sandbox", "fs_type": "ext4", "lun": "0",
		"disk_id": "d-123ABC", "readonly": false, "fs_group": "1000",
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		allow  bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"readonly", func(v map[string]any) { v["readonly"] = true }, true},
		{"wrong target", func(v map[string]any) { v["mount_point"] = "/etc" }, false},
		{"extra key", func(v map[string]any) { v["key_uri"] = "kbs:///other" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volume := make(map[string]any, len(base))
			for key, value := range base {
				volume[key] = value
			}
			tc.change(volume)
			encoded, err := json.Marshal(map[string]any{"vol-0": volume})
			if err != nil {
				t.Fatal(err)
			}
			result, err := rego.New(
				rego.Query(`data.agent_policy.workspace_cloud_volume(input.encoded, "/sandbox")`),
				rego.Module("agent-policy-workload.rego", "package agent_policy\n"+resolved),
				rego.Input(map[string]any{"encoded": string(encoded)}),
			).Eval(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (len(result) != 0) != tc.allow {
				t.Fatalf("allow=%t, result=%v", tc.allow, result)
			}
		})
	}
}

func TestWorkspaceCloudMountSubstitution(t *testing.T) {
	module, err := os.ReadFile("../../deployment/policy/agent-policy-workload.rego")
	if err != nil {
		t.Fatal(err)
	}
	resolved := strings.ReplaceAll(string(module), "__WORKSPACE_MOUNTS__", `{"agent":["/sandbox"],"workspace-init":["/mnt/openshell-workspace"]}`)
	encoded := `{"vol-0":{"mount_point":"/sandbox","fs_type":"ext4","lun":"0","disk_id":"d-123ABC","readonly":false,"fs_group":"1000"}}`
	pMount := map[string]any{"destination": "/sandbox", "source": "$(sfprefix)sandbox$", "type_": "bind", "options": []string{"rbind", "rprivate", "rw"}}
	for _, tc := range []struct {
		name   string
		source string
		data   string
		allow  bool
	}{
		{"expected guest mount", "/run/cloud-volumes/d-123ABC", encoded, true},
		{"unexpected source", "/etc", encoded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iMount := map[string]any{"destination": "/sandbox", "source": tc.source, "type_": "bind", "options": []string{"rbind", "rprivate", "rw"}}
			input := map[string]any{
				"OCI":     map[string]any{"Annotations": map[string]any{"io.kubernetes.cri.container-name": "agent", "io.confidentialcontainers.org.cloud_volumes": tc.data}},
				"p_mount": pMount, "i_mount": iMount,
			}
			result, err := rego.New(
				rego.Query(`data.agent_policy.check_mount(input.p_mount, input.i_mount, "", "")`),
				rego.Module("agent-policy-workload.rego", "package agent_policy\n"+resolved),
				rego.Input(input),
			).Eval(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (len(result) != 0) != tc.allow {
				t.Fatalf("allow=%t, result=%v", tc.allow, result)
			}
		})
	}
}

func TestWorkspaceInitCloudVolumeBinding(t *testing.T) {
	module, err := os.ReadFile("../../deployment/policy/agent-policy-workload.rego")
	if err != nil {
		t.Fatal(err)
	}
	resolved := strings.ReplaceAll(string(module), "__WORKSPACE_MOUNTS__", `{"agent":["/sandbox"],"workspace-init":["/mnt/openshell-workspace"]}`)
	type binding struct {
		container string
		volume    map[string]any
		policy    map[string]any
		guest     map[string]any
		extra     bool
	}
	newBinding := func() binding {
		return binding{
			container: "workspace-init",
			volume: map[string]any{
				"mount_point": "/mnt/openshell-workspace", "fs_type": "ext4", "lun": "0",
				"disk_id": "d-123ABC", "readonly": false, "fs_group": "1000",
			},
			policy: map[string]any{
				"destination": "/mnt/openshell-workspace",
				"source":      `$(sfprefix)openshell\-workspace$`,
				"type_":       "bind",
				"options":     []string{"rbind", "rprivate", "rw"},
			},
			guest: map[string]any{
				"destination": "/mnt/openshell-workspace",
				"source":      "/run/cloud-volumes/d-123ABC",
				"type_":       "bind",
				"options":     []string{"rbind", "rprivate", "rw"},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*binding)
		allow  bool
	}{
		{"exact workspace-init mount", func(*binding) {}, true},
		{"wrong container", func(b *binding) { b.container = "agent" }, false},
		{"wrong policy destination", func(b *binding) { b.policy["destination"] = "/sandbox" }, false},
		{"wrong policy options", func(b *binding) { b.policy["options"] = []string{"rbind", "rw"} }, false},
		{"wrong guest destination", func(b *binding) { b.guest["destination"] = "/sandbox" }, false},
		{"wrong guest source", func(b *binding) { b.guest["source"] = "/run/cloud-volumes/d-other" }, false},
		{"wrong guest options", func(b *binding) { b.guest["options"] = []string{"rbind", "rw"} }, false},
		{"extra disk", func(b *binding) { b.extra = true }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBinding()
			tc.change(&b)
			volumes := map[string]any{"vol-0": b.volume}
			if b.extra {
				volumes["vol-1"] = b.volume
			}
			encoded, err := json.Marshal(volumes)
			if err != nil {
				t.Fatal(err)
			}
			annotations := map[string]any{
				"io.kubernetes.cri.container-name":            b.container,
				"io.confidentialcontainers.org.cloud_volumes": string(encoded),
			}
			input := map[string]any{
				"OCI": map[string]any{"Annotations": annotations},
				"key": "io.confidentialcontainers.org.cloud_volumes", "encoded": string(encoded),
				"p_container": map[string]any{"OCI": map[string]any{
					"Annotations": annotations, "Mounts": []any{b.policy},
				}},
				"p_mount": b.policy, "i_mount": b.guest,
			}
			result, err := rego.New(
				rego.Query(`data.agent_policy.allow_anno_key_value(input.key, input.encoded, input.p_container); data.agent_policy.check_mount(input.p_mount, input.i_mount, "", "")`),
				rego.Module("agent-policy-workload.rego", "package agent_policy\n"+resolved),
				rego.Input(input),
			).Eval(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got := len(result) != 0; got != tc.allow {
				t.Fatalf("allowed=%t, want %t", got, tc.allow)
			}
		})
	}
}
