package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

func TestGuestPullBindsSourceAndMetadataToMeasuredImage(t *testing.T) {
	module, err := os.ReadFile("../../deployment/policy/agent-policy-guest-pull.rego")
	if err != nil {
		t.Fatal(err)
	}
	image := "registry.example/openshell/supervisor@sha256:" +
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	annotations := map[string]any{
		"io.kubernetes.cri.container-type":         "container",
		"io.katacontainers.pkg.oci.container_type": "pod_container",
		"io.kubernetes.cri.image-name":             image,
	}
	metadata, err := json.Marshal(map[string]any{"metadata": annotations})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, option string
		storage              bool
		duplicate            bool
		allowed              bool
	}{
		{"pinned image", image, "image_guest_pull=" + string(metadata), true, false, true},
		{"different image", "registry.example/openshell/attacker@sha256:" +
			"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "image_guest_pull=" + string(metadata), true, false, false},
		{"different digest", "registry.example/openshell/supervisor@sha256:" +
			"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "image_guest_pull=" + string(metadata), true, false, false},
		{"tagged image", "registry.example/openshell/supervisor:latest", "image_guest_pull=" + string(metadata), true, false, false},
		{"missing metadata", image, "image_guest_pull={\"metadata\":{}}", true, false, false},
		{"spoof sandbox metadata", image, "image_guest_pull={\"metadata\":{\"io.kubernetes.cri.container-type\":\"sandbox\",\"io.katacontainers.pkg.oci.container_type\":\"pod_sandbox\",\"io.kubernetes.cri.image-name\":\"" + image + "\"}}", true, false, false},
		{"wrong driver option", image, "other={\"metadata\":{}}", true, false, false},
		{"duplicate guest pull", image, "image_guest_pull=" + string(metadata), true, true, false},
		{"host rootfs fallback", "", "", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var storages []any
			if tc.storage {
				storages = []any{map[string]any{"driver": "image_guest_pull", "source": tc.source,
					"driver_options": []string{tc.option}}}
				if tc.duplicate {
					storages = append(storages, storages[0])
				}
			}
			input := map[string]any{
				"oci":      map[string]any{"Annotations": annotations},
				"storages": storages,
			}
			result, err := rego.New(
				rego.Query("data.agent_policy.openshell_guest_pull(input.oci, input.storages)"),
				rego.Module("agent-policy-guest-pull.rego", "package agent_policy\n"+string(module)),
				rego.Input(input),
			).Eval(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (len(result) != 0) != tc.allowed {
				t.Fatalf("allowed=%t, result=%v", tc.allowed, result)
			}
		})
	}
}

func TestGuestPullPauseUsesBundledImage(t *testing.T) {
	module, err := os.ReadFile("../../deployment/policy/agent-policy-guest-pull.rego")
	if err != nil {
		t.Fatal(err)
	}
	annotations := map[string]any{
		"io.kubernetes.cri.container-type":         "sandbox",
		"io.katacontainers.pkg.oci.container_type": "pod_sandbox",
	}
	metadata, err := json.Marshal(map[string]any{"metadata": annotations})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source  string
		allowed bool
	}{{"pause", true}, {"registry.example/attacker:latest", false}} {
		input := map[string]any{"oci": map[string]any{"Annotations": annotations},
			"storages": []any{map[string]any{"driver": "image_guest_pull", "source": tc.source,
				"driver_options": []string{"image_guest_pull=" + string(metadata)}}}}
		result, err := rego.New(
			rego.Query("data.agent_policy.openshell_guest_pull(input.oci, input.storages)"),
			rego.Module("agent-policy-guest-pull.rego", "package agent_policy\n"+string(module)),
			rego.Input(input),
		).Eval(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if (len(result) != 0) != tc.allowed {
			t.Fatalf("source=%q allowed=%t, result=%v", tc.source, tc.allowed, result)
		}
	}
}
