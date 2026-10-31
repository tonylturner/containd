// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids

import "strings"

// normalizeField maps source names to the actual event contract, not to an
// assumed attribute with the same spelling. Unknown fields stay non-evaluable.
// In particular, raw decoders expose ports but not source/destination IPs.
func normalizeField(field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	switch field {
	case "proto", "kind", "flowid":
		return field
	}
	field = strings.TrimPrefix(field, "attr.")
	switch field {
	case "http_uri":
		field = "path"
	case "http_method":
		field = "method"
	case "http_host":
		field = "host"
	case "http_user_agent":
		field = "user_agent"
	case "dns_query":
		field = "qname"
	case "tls_sni":
		field = "sni"
	case "srcport":
		field = "src_port"
	case "dstport":
		field = "dst_port"
	}
	if decoderAttribute(field) {
		return "attr." + field
	}
	return ""
}

// decoderAttribute is the supported scalar Sigma attribute vocabulary. Keep
// additions tied to an emitting decoder; a log field or arbitrary attr.* name
// is not evidence of an executable network predicate. Array-valued attributes
// such as cipher_suites/extensions/requested_protocols need evaluator support.
func decoderAttribute(field string) bool {
	switch field {
	// pkg/dp/itdpi/{http,dns,tls}.go
	case "method", "path", "host", "target", "scheme", "user_agent", "status",
		"id", "qr", "opcode", "rcode", "questions", "answers",
		"qname", "qtype", "qclass", "sni", "alpn", "tls_version", "ja3", "ja3_hash":
		return true
	// Common IT metadata and itdpi/{detect,ics_marker,ntp,rdp,smb,snmp,ssh}.go.
	case "src_port", "dst_port", "transport", "detected", "ics",
		"dangerous", "leap_indicator", "mode", "mode_name", "poll", "precision",
		"reference_id", "risk", "root_delay", "root_dispersion", "stratum",
		"stratum_name", "version", "cookie",
		"security_concern", "security_level", "selected_protocol", "stage",
		"command", "session_id", "share", "community_auth", "community_length",
		"error_status", "first_oid", "msg_security_model", "pdu_type", "request_id",
		"write_operation", "comments", "encryption", "kex_algorithm", "software":
		return true
	// Shared ICS keys emitted by modbus, dnp3 and iec104, including the
	// information-object fields in iec104/asdu.go.
	case "function_code", "unit_id", "is_write", "direction", "error",
		"object_groups", "apci_type", "class", "send_sequence", "receive_sequence",
		"u_function", "type_id", "vsq", "object_count", "cause", "originator", "sq",
		"cot_test", "cot_negative", "ca", "ioa", "object_index", "select",
		"qualifier", "quality", "value", "value_invalid", "source_time",
		"time_valid", "time_summer", "apdu_id", "raw_hex", "transient":
		return true
	// Modbus data-access keys emitted per function code and direction in
	// pkg/dp/ics/modbus/pdu.go (address, quantity and value are listed with
	// the other protocols' keys).
	case "byte_count", "register_count", "values", "and_mask", "or_mask", "read_address",
		"read_quantity", "write_address", "write_quantity":
		return true
	// Other keys emitted by the retained industrial decoders.
	case "service_code", "address", "attribute_id",
		"cip_path", "enip_command", "enip_command_code", "cpf_item_types", "instance_id", "is_control", "msp",
		"enip_status", "enip_sender_context", "enip_options", "connection_id", "connected_sequence",
		"response_reserved", "general_status", "additional_status_count", "cpf_item_count", "cpf_item_index", "cpf_data_item_type",
		"multi_service_decoded_count", "msp_index", "connection_point", "io_context_known", "io_data_hex", "io_data_truncated", "sequence", "data_length",
		"multi_service_count", "object_class", "object_class_name", "service_name",
		"enip_session_handle", "destination_address", "function_name", "iin_flags",
		"source_address",
		"transaction_id", "exception_code", "exception_description", "mei_type",
		"mei_type_name", "quantity", "sub_function", "sub_function_name":
		return true
	default:
		return false
	}
}
