package policy

import rego.v1

# Upstream Trustee CPU appraisal for the official Ubuntu UKI boot flow.
# The verifier checks the quote, REPORTDATA and replay of all four RTMRs.
# This policy binds that verified evidence to independently derived image
# measurements, a reviewed ECS firmware profile and the current initdata.
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

# Replaced only by the trusted binding renderer. Static templates deny release.
default approved_initdata := []
default approved_initdata_events := {}

reference_matches(name, digest) if {
	regex.match("^[0-9a-f]{96}$", digest)
	values := query_reference_value(name)
	is_array(values)
	digest in values
}

event_matches(event, name) if {
	count(event.digests) == 1
	event.digests[0].alg == "SHA-384"
	reference_matches(name, event.digests[0].digest)
}

# systemd-stub measures present UKI sections in this fixed order, name then
# contents. Missing required sections and extra RTMR2 events fail closed.
uki_sections := ["linux", "osrel", "cmdline", "initrd", "ucode", "splash", "dtb", "uname", "sbat", "pcrpkey"]

measured_sections := [section |
	some section in uki_sections
	values := query_reference_value(sprintf("measurement.uki.section.%s.name.sha384", [section]))
	is_array(values)
	count(values) > 0
]

uki_boot_measurements_match(events) if {
	every required in {"linux", "osrel", "cmdline", "initrd"} {
		required in measured_sections
	}
	applications := [event |
		some event in events
		event.index == 2
		event.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	]
	count(applications) == 1
	event_matches(applications[0], "measurement.uki.sha384")
	rtmr2_events := [event | some event in events; event.index == 3]
	count(rtmr2_events) == 2 * count(measured_sections) + 2
	every i, section in measured_sections {
		name_event := rtmr2_events[2 * i]
		data_event := rtmr2_events[2 * i + 1]
		name_event.type_name == "EV_IPL"
		data_event.type_name == "EV_IPL"
		name_event.details.string == section
		data_event.details.string == section
		event_matches(name_event, sprintf("measurement.uki.section.%s.name.sha384", [section]))
		event_matches(data_event, sprintf("measurement.uki.section.%s.data.sha384", [section]))
	}
	load_options := rtmr2_events[2 * count(measured_sections)]
	load_options.type_name == "EV_EVENT_TAG"
	load_options.details.string == "LOADED_IMAGE::LoadOptions"
	event_matches(load_options, "measurement.uki.linux.load_options.sha384")
	initrd := rtmr2_events[2 * count(measured_sections) + 1]
	initrd.type_name == "EV_EVENT_TAG"
	initrd.details.string == "Linux initrd"
	event_matches(initrd, "measurement.uki.linux.initrd.sha384")
	# Includes section measurements plus Linux's UTF-16 LoadOptions and its
	# concatenated initrd (including systemd's deterministic .extra/os-release).
	reference_matches("measurement.uki.rtmr2.sha384", input.tdx.quote.body.rtmr_2)
}

initdata_measurement_matches(events) if {
	matches := [event |
		some event in events
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
	digest in approved_initdata
	count(only.digests) == 1
	only.digests[0].alg == "SHA-384"
	only.digests[0].digest == approved_initdata_events[digest]
}

td_is_non_debug if {
	# DEBUG is bit 0 of the first byte of little-endian TD_ATTRIBUTES.
	regex.match("^[0-9a-f][02468ace][0-9a-f]{14}$", input.tdx.quote.body.td_attributes)
}

# Firmware code is pinned by MRTD. RTMR0 also measures VMM-supplied ACPI
# configuration, whose contents vary between VMs. Pin the reviewed static
# prefix and the exact event layout; the native verifier replays all six
# digests into the quoted RTMR0. ACPI contents are accepted VMM input, not
# individually approved reference values.
platform_boot_measurements_match(events) if {
	platform_events := [event | some event in events; event.index == 1]
	count(platform_events) == 6
	static_events := [
		["EV_EFI_HANDOFF_TABLES2", "TdxTable"],
		["EV_EFI_PLATFORM_FIRMWARE_BLOB2", "Fv(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)"],
		["EV_POST_CODE", "ACPI DATA"],
	]
	every i, expected in static_events {
		event := platform_events[i]
		event.type_name == expected[0]
		event.details.string == expected[1]
		event_matches(event, sprintf("measurement.ecs.rtmr_0.event.%d.sha384", [i]))
	}
	every i, name in ["etc/table-loader", "etc/acpi/rsdp", "etc/acpi/tables"] {
		event := platform_events[3 + i]
		event.type_name == "EV_PLATFORM_CONFIG_FLAGS"
		event.details.string == name
		count(event.digests) == 1
		event.digests[0].alg == "SHA-384"
		regex.match("^[0-9a-f]{96}$", event.digests[0].digest)
	}
}

executables := 3 if {
	uki_boot_measurements_match(input.tdx.uefi_event_logs)
}

hardware := 2 if {
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	input.tdx.tcb_status in {"UpToDate", "OutOfDate"}
	reference_matches("measurement.ecs.mr_td.sha384", input.tdx.quote.body.mr_td)
	platform_boot_measurements_match(input.tdx.uefi_event_logs)
	reference_matches("measurement.ecs.rtmr_1.sha384", input.tdx.quote.body.rtmr_1)
}

configuration := 2 if {
	uki_boot_measurements_match(input.tdx.uefi_event_logs)
	initdata_measurement_matches(input.tdx.uefi_event_logs)
	td_is_non_debug
}

file_system := 2 if {
	# The approved UKI's measured cmdline embeds the verified root's roothash.
	uki_boot_measurements_match(input.tdx.uefi_event_logs)
}
