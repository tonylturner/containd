// SPDX-License-Identifier: Apache-2.0
package pcap

import (
	"bytes"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Exercise the analyzer's event-to-policy boundary independently of which
// packet parser emitted the event.
type policyScopeDecoder struct{ protocols []string }

func (policyScopeDecoder) Supports(*flow.State) bool { return true }
func (d policyScopeDecoder) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	var events []dpi.Event
	for _, protocol := range d.protocols {
		// Enough identity for every learnable protocol: Modbus unit, FC and
		// span, DNP3 function code, CIP service identity and access category.
		events = append(events, dpi.Event{Proto: protocol, Kind: "request", Attributes: map[string]any{
			"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(0), "quantity": uint16(1),
			"service_code": uint8(0x0e), "service_name": "Get_Attribute_Single",
			"is_write": false, "is_control": false,
		}})
	}
	return events, nil
}
func (policyScopeDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }

func TestAnalysisRetainsProtocolTelemetry(t *testing.T) {
	protocols := []string{"modbus", "dnp3", "iec104", "cip", "http", "dns", "tls", "ssh", "smb", "ntp", "snmp", "rdp",
		"ics", "tcp", "udp", "s7comm", "s7", "mms", "iec61850", "bacnet", "opcua", "goose"}
	result, err := Analyze(bytes.NewReader(buildPCAP([][]byte{buildModbusEthernetFrame(100)})),
		policyScopeDecoder{protocols: protocols})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range protocols {
		if result.Protocols[protocol] != 1 {
			t.Fatalf("scope filter hid telemetry for %s: %v", protocol, result.Protocols)
		}
	}
}
