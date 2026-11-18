package policy_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

func TestReleasedGuestPullPolicy(t *testing.T) {
	rules, err := os.ReadFile("../../artifacts/cache/kata-policy/rules.rego")
	if err != nil {
		t.Fatal(err)
	}
	image := "registry.example/workload@sha256:" + strings.Repeat("a", 64)
	ctx := context.Background()
	query, err := rego.New(
		rego.Query(`data.agent_policy.allow_storages(input.container, input.storages, "bundle", "sandbox")`),
		rego.Module("rules.rego", string(rules)+"\npolicy_data := data.generated"),
		rego.Store(inmem.NewFromObject(map[string]any{"generated": map[string]any{"common": map[string]any{"root_path": "/bundle/rootfs"}, "cluster_config": map[string]any{"guest_pull": true}}})),
	).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, role, source string
		options            []string
		count              int
		allowed            bool
	}{
		{"pinned workload", "container", image, []string{}, 1, true},
		{"mirrored digest", "container", strings.Replace(image, "registry.example", "mirror.example", 1), []string{}, 1, true},
		{"wrong digest", "container", image[:len(image)-1] + "b", []string{}, 1, false},
		{"legacy metadata", "container", image, []string{"image_guest_pull={}"}, 1, false},
		{"missing storage", "container", image, []string{}, 0, false},
		{"extra storage", "container", image, []string{}, 2, false},
		{"bundled pause", "sandbox", "pause", []string{}, 1, true},
		{"wrong pause", "sandbox", image, []string{}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			container := map[string]any{"image": image, "storages": []any{}, "OCI": map[string]any{"Annotations": map[string]string{
				"io.kubernetes.cri.container-type": tc.role, "io.katacontainers.pkg.oci.container_type": "pod_" + tc.role,
			}}}
			storages := []any{}
			for range tc.count {
				storages = append(storages, map[string]any{"driver": "image_guest_pull", "fstype": "overlay", "fs_group": nil, "shared": false, "mount_point": "/bundle/rootfs", "options": []string{}, "source": tc.source, "driver_options": tc.options})
			}
			results, err := query.Eval(ctx, rego.EvalInput(map[string]any{"container": container, "storages": storages}))
			if err != nil || results.Allowed() != tc.allowed {
				t.Fatalf("allowed=%v, want %v, error=%v", results.Allowed(), tc.allowed, err)
			}
		})
	}
}
