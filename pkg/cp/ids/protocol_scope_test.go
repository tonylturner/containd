// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestRemovedProtocolImports(t *testing.T) {
	for _, name := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip"} {
		for _, prefix := range []string{"proto.", "containd.proto."} {
			source := fmt.Sprintf("id: bad\ntitle: rejected\ntags: [%s%s, proto.modbus]\ndetection:\n  selection:\n    function_code: 3\n  condition: selection\n", prefix, name)
			if _, err := ConvertSigmaFile([]byte(source)); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Sigma %s: %v", name, err)
			}
		}
		for _, format := range []string{"suricata", "snort"} {
			source := fmt.Sprintf(`alert %s any any -> any any (msg:"rejected"; sid:1; rev:1;)`, name)
			got, err := ImportRules([]byte(source), format)
			if name == "enip" {
				// External rules-file vocabulary is translated at the format
				// boundary; native IDS/Sigma names still reject enip.
				if err != nil || len(got) != 1 || got[0].Proto != "cip" {
					t.Fatalf("%s enip keyword: %+v %v", format, got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), name) {
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

func TestProtocolScopeCIPPortEnrichment(t *testing.T) {
	for _, endpoint := range []struct{ transport, port string }{{"tcp", "44818"}, {"udp", "2222"}} {
		line := fmt.Sprintf(`alert %s any any -> any %s (msg:"CIP"; sid:8; rev:1;)`, endpoint.transport, endpoint.port)
		rule, err := ParseSuricataLine(line)
		if err != nil || rule.Proto != "cip" {
			t.Fatalf("%s/%s enrichment: %+v %v", endpoint.transport, endpoint.port, rule, err)
		}
	}
}

func TestProtocolScopeCIPSuricataExport(t *testing.T) {
	rule := config.IDSRule{ID: "CIP", Proto: "cip", Title: "CIP"}
	out, err := ExportSuricataRule(rule)
	if err != nil || !strings.HasPrefix(out, "alert enip ") {
		t.Fatalf("CIP exported as generic IP: %q %v", out, err)
	}
	got, err := ParseSuricataLine(out)
	if err != nil || got.Proto != "cip" {
		t.Fatalf("CIP roundtrip: %+v %v", got, err)
	}
}

func TestProtocolScopeObsoleteNativeExport(t *testing.T) {
	for _, proto := range []string{"s7comm", "s7", "bacnet", "opcua", "mms", "iec61850", "goose", "enip"} {
		rule := config.IDSRule{ID: "saved", Proto: proto}
		for _, export := range []func(config.IDSRule) (string, error){ExportSuricataRule, ExportSnortRule} {
			if out, err := export(rule); !errors.Is(err, ErrUnexportableProto) || out != "" {
				t.Fatalf("obsolete native %s broadened: %q %v", proto, out, err)
			}
		}
	}
}
