package policy

import rego.v1

# The renderer appends rules for validated, deployment-specific
# bindings. The checked-in template denies private resources by itself.
default bindings := {}
default approved_initdata_events := {}
default native_kata := false

default allow := false

approved_tdx(appraisal) if {
	appraisal["ear_appraisal_policy_ids"] == ["openshell-tdx"]
	appraisal["ear_status"] == "affirming"
	vector := appraisal["ear_trustworthiness_vector"]
	vector.hardware == 2
	vector.configuration == 2
	vector.executables == 3
	vector["file-system"] == 2
	appraisal.ear_attester_claims.tee == "tdx"
	evidence := appraisal.ear_attester_claims.claims
	evidence.tcb_status in {"UpToDate", "OutOfDate"}
	regex.match("^[0-9a-f][02468ace][0-9a-f]{14}$", evidence.quote.body.td_attributes)
}

measured_initdata(appraisal) := digest if {
	not native_kata
	logs := appraisal.ear_attester_claims.claims.uefi_event_logs
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

measured_initdata(appraisal) := digest if {
	native_kata
	digest := appraisal.ear_attester_claims.claims.quote.body.mr_config_id
	regex.match("^[0-9a-f]{96}$", digest)
	not regex.match("^0{96}$", digest)
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
