// SPDX-License-Identifier: Apache-2.0
package pcap

import (
	"bytes"
	"reflect"
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
		// span, DNP3 function code, CIP service code.
		events = append(events, dpi.Event{Proto: protocol, Kind: "request", Attributes: map[string]any{
			"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(0), "quantity": uint16(1),
			"service_code": uint8(0x0e),
		}})
	}
	return events, nil
}
func (policyScopeDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }

func TestAnalyzeForPolicyIndustrialScope(t *testing.T) {
	protocols := []string{"modbus", "dnp3", "iec104", "cip", "http", "dns", "tls", "ssh", "smb", "ntp", "snmp", "rdp",
		"ics", "tcp", "udp", "s7comm", "s7", "mms", "iec61850", "bacnet", "opcua", "goose"}
	result, err := AnalyzeForPolicy(bytes.NewReader(buildPCAP([][]byte{buildModbusEthernetFrame(100)})),
		policyScopeDecoder{protocols: protocols})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range protocols {
		if result.EventSummary[protocol] != 1 {
			t.Fatalf("scope filter hid telemetry for %s: %v", protocol, result.EventSummary)
		}
	}
	got := map[string]bool{}
	for _, rule := range result.Rules {
		got[rule.ICS.Protocol] = true
	}
	// IEC104 remains visible in analysis but is never auto-learned into
	// permissive rules.
	want := map[string]bool{"modbus": true, "dnp3": true, "cip": true}
	if !reflect.DeepEqual(got, want) || len(result.Profiles) != len(want) {
		t.Fatalf("non-learnable events produced policy: rules=%v profiles=%+v", got, result.Profiles)
	}
}
