package policy_test

import (
	"fmt"
	"testing"
)

// An event description can be changed without changing the replayed digest.
// Both services must bind that description to the canonical measured AAEL.
func TestInitdataEventDigestBinding(t *testing.T) {
	dir := t.TempDir()
	first := writeBinding(t, dir, "workload", "generation-1", "sandbox-1", "KEY", digest("6"))
	second := writeBinding(t, dir, "supervisor", "generation-2", "sandbox-2", "KEY", digest("7"))
	kbs, as := renderSealedPolicies(t, dir)
	claims, refs := approvedEvidence()
	refs["AA.eventlog.confidentialcontainers.org.initdata"] = []any{digest("6"), digest("7")}
	refs["AA.eventlog.confidentialcontainers.org.initdata.sha384"] = map[string]any{
		digest("6"): initdataEventDigest(digest("6")), digest("7"): initdataEventDigest(digest("7")),
	}
	for _, tc := range []struct {
		name     string
		mutate   func(map[string]any)
		resource string
		allowed  bool
	}{
		{"original canonical event", func(map[string]any) {}, first, true},
		{"second canonical event", func(event map[string]any) {
			event["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("7")
			event["digests"].([]any)[0].(map[string]any)["digest"] = initdataEventDigest(digest("7"))
		}, second, true},
		{"approved text replaced but original digest retained", func(event map[string]any) {
			event["details"].(map[string]any)["data"].(map[string]any)["content"] = digest("7")
		}, second, false},
		{"wrong measurement register", func(event map[string]any) { event["index"] = 3 }, first, false},
		{"missing register", func(event map[string]any) { delete(event, "index") }, first, false},
		{"unprotected description", func(event map[string]any) { event["digest_matches_event"] = false }, first, false},
		{"missing protection claim", func(event map[string]any) { delete(event, "digest_matches_event") }, first, false},
		{"empty digests", func(event map[string]any) { event["digests"] = []any{} }, first, false},
		{"wrong algorithm", func(event map[string]any) {
			event["digests"].([]any)[0].(map[string]any)["alg"] = "SHA-256"
		}, first, false},
		{"wrong event digest", func(event map[string]any) {
			event["digests"].([]any)[0].(map[string]any)["digest"] = digest("d")
		}, first, false},
		{"ambiguous digests", func(event map[string]any) {
			event["digests"] = append(event["digests"].([]any), map[string]any{"alg": "SHA-384", "digest": digest("d")})
		}, first, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := cloneJSON(t, claims)
			// Preserve an affirming EAR vector when mutating its annotated log,
			// so KBS's own check is exercised independently of AS's denial.
			token := sealedToken(t, input, refs)
			event := aaelEvent(input)
			tc.mutate(event)
			want := "36"
			if tc.allowed {
				want = "2"
			}
			if got := evaluate(t, as, "data.policy.configuration", input, map[string]any{"reference": refs}); fmt.Sprint(got) != want {
				t.Fatalf("AS configuration = %v, want %s", got, want)
			}
			for _, resource := range []string{tc.resource, "resource/default/bootstrap-signer/key"} {
				if got := evaluateBool(t, kbs, "data.policy.allow", token, resourceData(resource)); got != tc.allowed {
					t.Fatalf("KBS allow(%s) = %t, want %t", resource, got, tc.allowed)
				}
			}
		})
	}
}
