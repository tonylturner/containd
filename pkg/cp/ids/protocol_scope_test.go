// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"fmt"
	"strings"
	"testing"
)

func TestRemovedProtocolImports(t *testing.T) {
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose"} {
		for _, prefix := range []string{"proto.", "containd.proto."} {
			source := fmt.Sprintf("id: bad\ntitle: rejected\ntags: [%s%s, proto.modbus]\ndetection:\n  selection:\n    function_code: 3\n  condition: selection\n", prefix, name)
			if _, err := ConvertSigmaFile([]byte(source)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Sigma %s: %v", name, err)
			}
		}
		for _, format := range []string{"suricata", "snort"} {
			source := fmt.Sprintf(`alert %s any any -> any any (msg:"rejected"; sid:1; rev:1;)`, name)
			if _, err := ImportRules([]byte(source), format); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s %s: %v", format, name, err)
			}
		}
	}
	for _, port := range []string{"102", "4840", "47808", "18245"} {
		for _, proto := range []string{"tcp", "udp"} {
			source := fmt.Sprintf(`alert %s any any -> any %s (msg:"generic"; sid:1; rev:1;)`, proto, port)
			got, err := ParseSuricataLine(source)
			if err != nil || got.Proto != proto {
				t.Fatalf("numeric %s/%s became industrial: %+v %v", proto, port, got, err)
			}
		}
	}
}

func TestProtocolScopeSigmaFields(t *testing.T) {
	for _, key := range []string{"bvlc_function", "is_critical", "object_instance", "object_type", "property_id",
		"service", "pdu_tag", "service_tag", "variable_name", "chunk_type", "message_type", "area",
		"cotp_pdu_type", "db_number", "error_class", "error_code", "item_count", "pdu_reference", "safety_critical"} {
		if decoderAttribute(key) {
			t.Errorf("unemitted attribute %s retained", key)
		}
	}
	for _, key := range []string{"service_code", "address", "is_control", "cip_path", "object_class",
		"function_code", "unit_id", "ca", "ioa", "type_id", "raw_hex", "error", "direction"} {
		if !decoderAttribute(key) {
			t.Errorf("retained attribute %s removed", key)
		}
	}
}
