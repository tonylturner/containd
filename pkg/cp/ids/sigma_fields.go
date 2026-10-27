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
		"preview", "hash", "id", "qr", "opcode", "rcode", "questions", "answers",
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
	case "byte_count", "register_count", "and_mask", "or_mask", "read_address",
		"read_quantity", "write_address", "write_quantity":
		return true
	// Other protocol-specific keys emitted in pkg/dp/ics/*/decoder.go
	// (and iec61850/mms.go).
	case "bvlc_function", "is_critical", "object_instance", "object_type",
		"property_id", "service", "service_code", "address", "attribute_id",
		"cip_path", "command_code", "instance_id", "is_control", "msp",
		"multi_service_count", "object_class", "object_class_name", "service_name",
		"session_handle", "destination_address", "function_name", "iin_flags",
		"source_address", "pdu_tag", "service_tag", "variable_name",
		"transaction_id", "exception_code", "exception_description", "mei_type",
		"mei_type_name", "quantity", "sub_function", "sub_function_name",
		"chunk_type", "message_type", "area", "cotp_pdu_type", "db_number",
		"error_class", "error_code", "item_count", "pdu_reference", "safety_critical":
		return true
	default:
		return false
	}
}
