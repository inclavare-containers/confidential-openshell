package policy

import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 35

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": file_system,
}

default approved_initdata := []

matches(name, digest) if {
	regex.match("^[0-9a-f]{96}$", digest)
	digest in query_reference_value(concat("", ["measurement.kata.", name, ".sha384"]))
}

# Trustee replays the CCEL into the quoted registers. The approved RTMR1
# covers the UKI PE digest and firmware handoff. RTMR2 covers the UKI
# sections, both external command-line measurements and the Linux initrd.
approved_boot if {
	matches("rtmr_1", input.tdx.quote.body.rtmr_1)
	matches("rtmr_2", input.tdx.quote.body.rtmr_2)
}

# TDVF consumes the VMM-provided TD HOB, ACPI tables and handoff table.
# The remaining boot events have independently reviewed reference digests.
approved_platform if {
	events := [e | some e in input.tdx.uefi_event_logs; e.index == 1]
	count(events) == 16
	every i, event in events {
		count(event.digests) == 1
		event.digests[0].alg == "SHA-384"
		platform_event(i, event)
	}
}

platform_event(i, event) if {
	i in {1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15}
	matches(sprintf("rtmr_0.event.%d", [i]), event.digests[0].digest)
}

platform_event(i, event) if {
	i in {10, 11, 12}
	event.type_name == "EV_PLATFORM_CONFIG_FLAGS"
	event.details.string == "ACPI DATA"
}

platform_event(0, event) if {
	event.type_name == "EV_EFI_HANDOFF_TABLES2"
	event.details.string == "TdxTable"
}

platform_event(13, event) if {
	event.type_name == "EV_EFI_HANDOFF_TABLES"
}

hardware := 2 if {
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	input.tdx.tcb_status in {"UpToDate", "OutOfDate"}
	matches("mr_td", input.tdx.quote.body.mr_td)
	approved_platform
}

executables := 3 if approved_boot

configuration := 2 if {
	approved_boot
	regex.match("^[0-9a-f][02468ace][0-9a-f]{14}$", input.tdx.quote.body.td_attributes)
	# Trustee replays the dynamic RTMR3 log, including guest image pulls.
	input.tdx.quote.body.mr_config_id in approved_initdata
}

file_system := 2 if approved_boot
