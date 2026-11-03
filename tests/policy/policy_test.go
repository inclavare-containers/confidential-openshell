package policy_test

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/types"
)

func TestTDXPolicy(t *testing.T) {
	positive := map[string]any{"executables": 3, "hardware": 2, "configuration": 2, "file_system": 2}
	rejectBoot := map[string]any{"executables": 33, "hardware": 2, "configuration": 36, "file_system": 35}
	claims, refs := approvedEvidence()
	assertClaims(t, claims, refs, positive)
	for _, status := range []any{"OutOfDate", "Revoked", "ConfigurationNeeded", "SWHardeningNeeded", nil} {
		t.Run(fmt.Sprintf("TCB %v", status), func(t *testing.T) {
			claims, refs := approvedEvidence()
			claims["tdx"].(map[string]any)["tcb_status"] = status
			want := 97
			if status == "OutOfDate" {
				want = 2
			}
			assertClaims(t, claims, refs, map[string]any{"hardware": want})
		})
	}
	for _, field := range []string{"mr_td", "rtmr_1"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("platform %s missing=%v", field, missing), func(t *testing.T) {
				claims, refs := approvedEvidence()
				if missing {
					delete(refs, "measurement.ecs."+field+".sha384")
				} else {
					quoteBody(claims)[field] = digest("f")
				}
				assertClaims(t, claims, refs, map[string]any{"hardware": 97})
			})
		}
	}
	for _, field := range []string{"tee_type", "vendor_id"} {
		t.Run("wrong "+field, func(t *testing.T) {
			claims, refs := approvedEvidence()
			claims["tdx"].(map[string]any)["quote"].(map[string]any)["header"].(map[string]any)[field] = "wrong"
			assertClaims(t, claims, refs, map[string]any{"hardware": 97})
		})
	}
	for _, attributes := range []any{"0100001000000000", "invalid", nil} {
		t.Run(fmt.Sprintf("unsafe attributes %v", attributes), func(t *testing.T) {
			claims, refs := approvedEvidence()
			quoteBody(claims)["td_attributes"] = attributes
			assertClaims(t, claims, refs, map[string]any{"configuration": 36})
		})
	}
	t.Run("other nondebug flags", func(t *testing.T) {
		claims, refs := approvedEvidence()
		quoteBody(claims)["td_attributes"] = "0200001000000000"
		assertClaims(t, claims, refs, positive)
	})
	for i := 0; i < len(evidenceEvents(claims))-1; i++ {
		if evidenceEvents(claims)[i].(map[string]any)["index"] == 1 {
			continue
		}
		t.Run(fmt.Sprintf("boot digest %d", i), func(t *testing.T) {
			claims, refs := approvedEvidence()
			evidenceEvents(claims)[i].(map[string]any)["digests"].([]any)[0].(map[string]any)["digest"] = digest("f")
			assertClaims(t, claims, refs, rejectBoot)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any, map[string]any)
	}{
		{"full RTMR2 includes Linux events", func(c, r map[string]any) { quoteBody(c)["rtmr_2"] = digest("f") }},
		{"no CCEL", func(c, r map[string]any) { c["tdx"].(map[string]any)["uefi_event_logs"] = []any{} }},
		{"missing required linux", func(c, r map[string]any) { delete(r, "measurement.uki.section.linux.name.sha384") }},
		{"missing derived Linux initrd", func(c, r map[string]any) { delete(r, "measurement.uki.linux.initrd.sha384") }},
		{"missing full RTMR2", func(c, r map[string]any) { delete(r, "measurement.uki.rtmr2.sha384") }},
		{"swapped section pair", func(c, r map[string]any) { e := evidenceEvents(c); e[1], e[2] = e[2], e[1] }},
		{"extra RTMR2 event", func(c, r map[string]any) {
			c["tdx"].(map[string]any)["uefi_event_logs"] = append(evidenceEvents(c), evidenceEvents(c)[1])
		}},
		{"missing UKI", func(c, r map[string]any) { c["tdx"].(map[string]any)["uefi_event_logs"] = evidenceEvents(c)[1:] }},
		{"unrecognized section", func(c, r map[string]any) {
			evidenceEvents(c)[1].(map[string]any)["details"].(map[string]any)["string"] = "unknown"
		}},
		{"wrong register", func(c, r map[string]any) { evidenceEvents(c)[1].(map[string]any)["index"] = 2 }},
		{"wrong algorithm", func(c, r map[string]any) {
			evidenceEvents(c)[1].(map[string]any)["digests"].([]any)[0].(map[string]any)["alg"] = "SHA-256"
		}},
		{"ambiguous digests", func(c, r map[string]any) {
			e := evidenceEvents(c)[1].(map[string]any)
			e["digests"] = append(e["digests"].([]any), map[string]any{"alg": "SHA-384", "digest": digest("f")})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, refs := approvedEvidence()
			tc.change(claims, refs)
			want := rejectBoot
			if tc.name == "no CCEL" {
				want = map[string]any{"executables": 33, "hardware": 97, "configuration": 36, "file_system": 35}
			}
			assertClaims(t, claims, refs, want)
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unapproved initdata", func(c map[string]any) {
			aaelEvent(c)["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("f")
		}},
		{"unprotected AAEL", func(c map[string]any) { aaelEvent(c)["digest_matches_event"] = false }},
		{"missing AAEL protection", func(c map[string]any) { delete(aaelEvent(c), "digest_matches_event") }},
		{"duplicate initdata", func(c map[string]any) {
			c["tdx"].(map[string]any)["uefi_event_logs"] = append(evidenceEvents(c), aaelEvent(c))
		}},
		{"wrong domain", func(c map[string]any) {
			aaelEvent(c)["details"].(map[string]any)["data"].(map[string]any)["domain"] = "untrusted.example"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, refs := approvedEvidence()
			tc.change(claims)
			assertClaims(t, claims, refs, map[string]any{"configuration": 36})
		})
	}
	t.Run("no other TEE", func(t *testing.T) {
		_, refs := approvedEvidence()
		assertClaims(t, map[string]any{"tpm": map[string]any{}}, refs, map[string]any{"hardware": 97, "executables": 33, "configuration": 36, "file_system": 35})
	})
	t.Run("native EAR trust_claims", func(t *testing.T) {
		claims, refs := approvedEvidence()
		got := evaluate(t, "tdx-podvm.rego", "data.policy.trust_claims", claims, map[string]any{"reference": refs}).(map[string]any)
		for k, v := range map[string]string{"hardware": "2", "configuration": "2", "executables": "3", "file-system": "2"} {
			if fmt.Sprint(got[k]) != v {
				t.Fatalf("%s=%v", k, got[k])
			}
		}
	})
}

func TestPortablePlatformEvents(t *testing.T) {
	platform := func(c map[string]any) []map[string]any {
		out := []map[string]any{}
		for _, e := range evidenceEvents(c) {
			v := e.(map[string]any)
			if v["index"] == 1 {
				out = append(out, v)
			}
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		want   int
	}{
		{"dynamic ACPI contents", func(c, r map[string]any) {
			for _, e := range platform(c)[3:] {
				e["digests"].([]any)[0].(map[string]any)["digest"] = digest("b")
			}
		}, 2},
		{"changed static digest", func(c, r map[string]any) {
			platform(c)[0]["digests"].([]any)[0].(map[string]any)["digest"] = digest("f")
		}, 97},
		{"missing static reference", func(c, r map[string]any) { delete(r, "measurement.ecs.rtmr_0.event.1.sha384") }, 97},
		{"wrong static description", func(c, r map[string]any) { platform(c)[0]["details"].(map[string]any)["string"] = "OTHER" }, 97},
		{"wrong dynamic name", func(c, r map[string]any) { platform(c)[3]["details"].(map[string]any)["string"] = "bootorder" }, 97},
		{"swapped dynamic order", func(c, r map[string]any) {
			a := platform(c)[3]["details"].(map[string]any)
			b := platform(c)[4]["details"].(map[string]any)
			a["string"], b["string"] = b["string"], a["string"]
		}, 97},
		{"wrong dynamic type", func(c, r map[string]any) { platform(c)[4]["type_name"] = "EV_IPL" }, 97},
		{"wrong dynamic algorithm", func(c, r map[string]any) { platform(c)[4]["digests"].([]any)[0].(map[string]any)["alg"] = "SHA-256" }, 97},
		{"extra platform event", func(c, r map[string]any) {
			c["tdx"].(map[string]any)["uefi_event_logs"] = append(evidenceEvents(c), platform(c)[0])
		}, 97},
		{"multiple dynamic digests", func(c, r map[string]any) {
			e := platform(c)[5]
			e["digests"] = append(e["digests"].([]any), map[string]any{"alg": "SHA-384", "digest": digest("c")})
		}, 97},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := approvedEvidence()
			tc.mutate(c, r)
			assertClaims(t, c, r, map[string]any{"hardware": tc.want})
		})
	}
}

func TestStaticTDXTemplateDeniesInitdata(t *testing.T) {
	claims, refs := approvedEvidence()
	content, err := os.ReadFile(policySource("tdx-podvm.rego"))
	if err != nil {
		t.Fatal(err)
	}
	got := evaluateContent(t, "template.rego", string(content), "data.policy.configuration", claims, map[string]any{"reference": refs})
	if fmt.Sprint(got) != "36" {
		t.Fatalf("unrendered initdata=%v", got)
	}
}

func approvedEvidence() (map[string]any, map[string]any) {
	refs := map[string]any{}
	counter := 1
	measure := func(name string) string {
		value := fmt.Sprintf("%096x", counter)
		counter++
		refs[name] = []any{value}
		return value
	}
	event := func(index int, kind, description, value string) map[string]any {
		return map[string]any{"index": index, "type_name": kind, "digest_matches_event": false, "details": map[string]any{"string": description}, "digests": []any{map[string]any{"alg": "SHA-384", "digest": value}}}
	}
	events := []any{event(2, "EV_EFI_BOOT_SERVICES_APPLICATION", "Ubuntu UKI", measure("measurement.uki.sha384"))}
	for _, section := range []string{"linux", "osrel", "cmdline", "initrd", "uname", "sbat"} {
		for _, kind := range []string{"name", "data"} {
			events = append(events, event(3, "EV_IPL", section, measure("measurement.uki.section."+section+"."+kind+".sha384")))
		}
	}
	events = append(events, event(3, "EV_EVENT_TAG", "LOADED_IMAGE::LoadOptions", measure("measurement.uki.linux.load_options.sha384")), event(3, "EV_EVENT_TAG", "Linux initrd", measure("measurement.uki.linux.initrd.sha384")))
	body := map[string]any{"td_attributes": "0000001000000000", "rtmr_2": measure("measurement.uki.rtmr2.sha384")}
	for _, field := range []string{"mr_td", "rtmr_1"} {
		body[field] = measure("measurement.ecs." + field + ".sha384")
	}
	for i, pair := range [][2]string{{"EV_EFI_HANDOFF_TABLES2", "TdxTable"}, {"EV_EFI_PLATFORM_FIRMWARE_BLOB2", "Fv(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"}, {"EV_POST_CODE", "ACPI DATA"}} {
		events = append(events, event(1, pair[0], pair[1], measure(fmt.Sprintf("measurement.ecs.rtmr_0.event.%d.sha384", i))))
	}
	for _, name := range []string{"etc/table-loader", "etc/acpi/rsdp", "etc/acpi/tables"} {
		events = append(events, event(1, "EV_PLATFORM_CONFIG_FLAGS", name, digest("a")))
	}
	body["rtmr_0"] = digest("9") // Native verifier owns full CCEL replay, including dynamic ACPI.
	events = append(events, map[string]any{"index": 4, "type_name": "EV_EVENT_TAG", "digest_matches_event": true, "details": map[string]any{"unicode_name": "AAEL", "data": map[string]any{"domain": "github.com/confidential-containers", "operation": "InitData", "content": map[string]any{"digest": "sha384:" + digest("6")}}}, "digests": []any{map[string]any{"alg": "SHA-384", "digest": initdataEventDigest(digest("6"))}}})
	refs["AA.eventlog.InitData"] = []any{digest("6")}
	refs["AA.eventlog.InitData.sha384"] = map[string]any{digest("6"): initdataEventDigest(digest("6"))}
	return map[string]any{"tdx": map[string]any{"tcb_status": "UpToDate", "quote": map[string]any{"header": map[string]any{"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": body}, "uefi_event_logs": events}}, refs
}
func evidenceEvents(claims map[string]any) []any {
	return claims["tdx"].(map[string]any)["uefi_event_logs"].([]any)
}
func quoteBody(claims map[string]any) map[string]any {
	return claims["tdx"].(map[string]any)["quote"].(map[string]any)["body"].(map[string]any)
}
func aaelEvent(claims map[string]any) map[string]any {
	for _, raw := range evidenceEvents(claims) {
		event := raw.(map[string]any)
		if event["details"].(map[string]any)["unicode_name"] == "AAEL" {
			return event
		}
	}
	panic("no AAEL in fixture")
}
func resourceData(path string) map[string]any {
	return map[string]any{"plugin": "resource", "resource-path": strings.Split(strings.TrimPrefix(path, "resource/"), "/")}
}
func cloneJSON(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy map[string]any
	if err := json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}
func digest(value string) string { return strings.Repeat(value, 96) }
func initdataEventDigest(value string) string {
	text := []byte(`github.com/confidential-containers InitData {"digest":"sha384:` + value + `"}`)
	event := make([]byte, 8+len(text))
	binary.LittleEndian.PutUint32(event, 0x4141454c)
	binary.LittleEndian.PutUint32(event[4:], uint32(len(text)))
	copy(event[8:], text)
	sum := sha512.Sum384(event)
	return hex.EncodeToString(sum[:])
}
func assertClaims(t *testing.T, input, references, want map[string]any) {
	t.Helper()
	for claim, expected := range want {
		got := evaluate(t, "tdx-podvm.rego", "data.policy."+claim, input, map[string]any{"reference": references})
		if fmt.Sprint(got) != fmt.Sprint(expected) {
			t.Fatalf("%s=%v want %v", claim, got, expected)
		}
	}
}
func evaluateBool(t *testing.T, module, query string, input, data map[string]any) bool {
	t.Helper()
	value := evaluate(t, module, query, input, data)
	result, ok := value.(bool)
	if !ok {
		t.Fatalf("%s returned %T", query, value)
	}
	return result
}
func evaluate(t *testing.T, module, query string, input, data map[string]any) any {
	t.Helper()
	content, err := os.ReadFile(policySource(module))
	if err != nil {
		t.Fatal(err)
	}
	// Only positive test fixtures substitute test-owned initdata bindings. The
	// checked-in template is separately evaluated unchanged and remains closed.
	if module == "tdx-podvm.rego" {
		refs := data["reference"].(map[string]any)
		allowed, _ := json.Marshal(refs["AA.eventlog.InitData"])
		events, _ := json.Marshal(refs["AA.eventlog.InitData.sha384"])
		content = []byte(strings.ReplaceAll(strings.ReplaceAll(string(content), "approved_initdata := []", "approved_initdata := "+string(allowed)), "approved_initdata_events := {}", "approved_initdata_events := "+string(events)))
	}
	return evaluateContent(t, module, string(content), query, input, data)
}
func evaluateContent(t *testing.T, module, content, query string, input, data map[string]any) any {
	t.Helper()
	queryReference := rego.Function1(&rego.Function{Name: "query_reference_value", Decl: types.NewFunction(types.Args(types.S), types.A)}, func(_ rego.BuiltinContext, operand *ast.Term) (*ast.Term, error) {
		refs, _ := data["reference"].(map[string]any)
		name, ok := operand.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid reference ID")
		}
		converted, err := ast.InterfaceToValue(refs[string(name)])
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(converted), nil
	})
	result, err := rego.New(rego.Query(query), rego.Module(module, content), rego.Input(input), rego.Store(inmem.NewFromObject(data)), queryReference).Eval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || len(result[0].Expressions) != 1 {
		t.Fatalf("unexpected result %#v", result)
	}
	return result[0].Expressions[0].Value
}
func policySource(module string) string {
	if filepath.IsAbs(module) {
		return filepath.Clean(module)
	}
	return filepath.Join("../../deployment/policy", module)
}
