// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDefaultInspectionTransportScope(t *testing.T) {
	for _, tc := range []struct {
		protocol  string
		transport uint8
		port      uint16
		want      bool
	}{
		{"cip", ics.TCP, 2222, false},
		{"cip", ics.UDP, 2222, true},
		{"cip", ics.UDP, 44818, true},
		{"CIP", ics.TCP, 44818, true},
		{"modbus", ics.TCP, 502, true},
		{"modbus", ics.UDP, 502, false},
		{"dnp3", ics.TCP, 20000, true},
		{"dnp3", ics.UDP, 20000, false},
		{"iec104", ics.TCP, 2404, true},
		{"iec104", ics.UDP, 2404, false},
	} {
		t.Run(fmt.Sprintf("%s/%d/%d", tc.protocol, tc.transport, tc.port), func(t *testing.T) {
			entry := rules.Entry{ICS: rules.ICSPredicate{Protocol: tc.protocol}}
			state := conformanceState()
			state.Key.Proto, state.Key.DstPort = tc.transport, tc.port
			transport := "tcp"
			if tc.transport == ics.UDP {
				transport = "udp"
			}
			pkt := &dpi.ParsedPacket{Proto: transport, SrcPort: state.Key.SrcPort, DstPort: tc.port}
			if got := shouldInspectFirewallEntry(entry, state, pkt); got != tc.want {
				t.Fatalf("forward inspect = %v, want %v", got, tc.want)
			}
			state.Key = state.Key.Reversed()
			pkt.SrcPort, pkt.DstPort = pkt.DstPort, pkt.SrcPort
			if got := shouldInspectFirewallEntry(entry, state, pkt); got != tc.want {
				t.Fatalf("reverse inspect = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProtocolScopeDecoders(t *testing.T) {
	want := map[string]bool{"modbus": true, "dnp3": true, "iec104": true, "cip": true}
	for _, toggles := range []map[string]bool{nil, {"cip": true}, {"cip": false}} {
		got := map[string]bool{}
		for _, decoder := range FilterDecoders(nil, toggles) {
			if proto := icsDecoderProto[fmt.Sprintf("%T", decoder)]; proto != "" {
				got[proto] = true
			}
		}
		expected := map[string]bool{}
		for proto := range want {
			if enabled, exists := toggles[proto]; !exists || enabled {
				expected[proto] = true
			}
		}
		if !reflect.DeepEqual(expected, got) {
			t.Fatalf("toggles=%v decoders=%v expected=%v", toggles, got, expected)
		}
	}
	if len(DefaultDecoders()) != 14 || len(icsDecoderProto) != 4 || len(itDecoderProto) != 8 {
		t.Fatal("expected four industrial, eight IT, two utility decoders")
	}
	for _, tc := range []struct {
		proto uint8
		port  uint16
	}{{6, 102}, {6, 4840}, {17, 47808}, {17, 18245}} {
		if _, known := icsServiceDirection(capture.Packet{Proto: tc.proto, SrcPort: tc.port, DstPort: 41000}); known {
			t.Fatalf("unsupported service port %d oriented flow", tc.port)
		}
	}
}

func TestRemovedProtocolSnapshotAtomic(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Version: "before", Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	before := e.CurrentRules()
	for _, name := range []string{"s7", "s7comm", "mms", "iec61850", "goose", "bacnet", "opcua"} {
		for _, snap := range []rules.Snapshot{
			{Firewall: []rules.Entry{{ID: "bad", ICS: rules.ICSPredicate{Protocol: name}}}},
			{IDS: rules.IDSConfig{Rules: []rules.IDSRule{{ID: "bad", Proto: name}}}},
		} {
			if err := e.ApplyRules(context.Background(), snap); err == nil {
				t.Fatalf("accepted %s", name)
			}
			if !reflect.DeepEqual(before, e.CurrentRules()) {
				t.Fatal("rejected snapshot changed runtime state")
			}
		}
		if isICSEvent(name, "request") || isRuleEvaluableICSEvent(name) || ics.IsProtocolPortOn(name, ics.TCP, 102) || ics.Supported(name) {
			t.Fatalf("retired protocol classified as industrial: %s", name)
		}
	}
}
