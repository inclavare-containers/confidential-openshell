package policy

import rego.v1

# The renderer replaces this object with validated, deployment-specific
# bindings. The checked-in template denies private resources by itself.
bindings := {}
approved_initdata_events := {}

default allow := false

approved_tdx(appraisal) if {
	appraisal["ear.appraisal-policy-id"] == "default"
	appraisal["ear.status"] == "affirming"
	vector := appraisal["ear.trustworthiness-vector"]
	vector.hardware == 2
	vector.configuration == 2
	vector.executables == 3
	vector["file-system"] == 2
	evidence := appraisal["ear.veraison.annotated-evidence"].tdx
	evidence.tcb_status in {"UpToDate", "OutOfDate"}
	regex.match("^[0-9a-f][02468ace][0-9a-f]{14}$", evidence.quote.body.td_attributes)
}

measured_initdata(appraisal) := digest if {
	logs := appraisal["ear.veraison.annotated-evidence"].tdx.uefi_event_logs
	is_array(logs)
	matches := [event |
		some event in logs
		event.type_name == "EV_EVENT_TAG"
		event.details.unicode_name == "AAEL"
		event.details.data.operation == "InitData"
	]
	count(matches) == 1
	only := matches[0]
	only.index == 4
	only.digest_matches_event == true
	only.details.data.domain == "github.com/confidential-containers"
	encoded_digest := only.details.data.content.digest
	regex.match("^sha384:[0-9a-f]{96}$", encoded_digest)
	digest := trim_prefix(encoded_digest, "sha384:")
	count(only.digests) == 1
	only.digests[0].alg == "SHA-384"
	only.digests[0].digest == approved_initdata_events[digest]
}

# Upstream KBS passes the plugin separately from three native path segments.
# Keep the trusted binding journal's logical resource/default/... keys.
resource_path := concat("/", array.concat(["resource"], segments)) if {
	data.plugin == "resource"
	segments := data["resource-path"]
	is_array(segments)
	count(segments) == 3
	every segment in segments {
		is_string(segment)
		regex.match("^[A-Za-z0-9_.-]+$", segment)
	}
}

allow if {
	appraisal := input.submods.cpu0
	approved_tdx(appraisal)
	digest := measured_initdata(appraisal)
	binding := bindings[resource_path]
	binding.kind == "bootstrap"
	binding.initdata_sha384 == digest
	binding.role in {"workload", "supervisor"}
}

allow if {
	appraisal := input.submods.cpu0
	approved_tdx(appraisal)
	digest := measured_initdata(appraisal)
	binding := bindings[resource_path]
	binding.kind == "workspace"
	binding.role == "workload"
	binding.initdata_sha384 == digest
}

# The signer verification key is public, but serve it only over an approved
# attested channel. Its URI is separate from private per-key resources.
allow if {
	resource_path == "resource/default/bootstrap-signer/key"
	appraisal := input.submods.cpu0
	approved_tdx(appraisal)
	measured_initdata(appraisal)
}
