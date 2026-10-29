// SPDX-License-Identifier: Apache-2.0

package dpi_test

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestObservationDispatchValidation(t *testing.T) {
	m, err := dpi.NewObservationManager(modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	s := flow.NewState(flow.Key{Proto: 6, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), SrcPort: 50000, DstPort: 1502}, time.Now())
	p := &dpi.ParsedPacket{Proto: "tcp", HasOffset: true, Session: "s", Dir: dpi.ClientToServer, Payload: []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}}
	if got := m.InspectProtocol("modbus", s, p); got.Err != nil || len(got.Events) != 1 {
		t.Fatal(got)
	}
	if got := m.Inspect(s, p); got.Err != nil || len(got.Events) != 0 {
		t.Fatal("observation registered a legacy decoder", got)
	}
	for _, protocol := range []string{"unknown", "iec104"} {
		if got := m.InspectProtocol(protocol, s, p); got.Err == nil || len(got.Events) != 0 {
			t.Fatal(got)
		}
	}
	for _, bad := range []*dpi.ParsedPacket{nil, {Proto: "tcp"}, {Proto: "tcp", HasOffset: true, Session: "s", Dir: dpi.DirUnknown}, {Proto: "udp"}, {Proto: "tcp", HasOffset: true, Session: "s", Dir: dpi.ClientToServer, Offset: -1}} {
		if got := m.InspectProtocol("modbus", s, bad); got.Err == nil {
			t.Fatal("invalid annotation accepted", bad)
		}
	}
	if _, err := dpi.NewObservationManager(modbus.NewDecoder(), modbus.NewDecoder()); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := dpi.NewObservationManager(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

func TestObservationCIPUDPSelectsExplicitLayer(t *testing.T) {
	s := flow.NewState(flow.Key{Proto: 17, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), SrcPort: 50000, DstPort: 2222}, time.Now())
	p := &dpi.ParsedPacket{Proto: "udp", Payload: append([]byte{4}, make([]byte, 23)...)}
	m, err := dpi.NewObservationManager(cip.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	observed := m.InspectProtocol("cip", s, p)
	legacy := dpi.NewManager(cip.NewDecoder()).Inspect(s, p)
	if observed.Err != nil || len(observed.Events) != 1 || observed.Events[0].Attributes["enip_command"] == nil {
		t.Fatal(observed)
	}
	if legacy.Err != nil || len(legacy.Events) != 1 || legacy.Events[0].Attributes["enip_command"] != nil {
		t.Fatal("legacy implicit dispatch changed", legacy)
	}
}
