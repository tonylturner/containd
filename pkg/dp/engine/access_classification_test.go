// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestModbusDNP3ReadOnlyFromWire(t *testing.T) {
	modbusWire := func(fc byte, pdu []byte) []byte {
		wire := []byte{0, 1, 0, 0, 0, 0, 1, fc}
		binary.BigEndian.PutUint16(wire[4:], uint16(2+len(pdu)))
		return append(wire, pdu...)
	}
	for _, tc := range []struct {
		name, protocol string
		port           uint16
		decoder        dpi.StreamDecoder
		wire           []byte
		read, write    bool
	}{
		{"holding registers", "modbus", 502, modbus.NewDecoder(), modbusADU(1, 3, 0, 2), true, false},
		{"write file record", "modbus", 502, modbus.NewDecoder(),
			modbusWire(21, []byte{9, 6, 0, 1, 0, 0, 0, 1, 0, 42}), false, true},
		{"UMAS", "modbus", 502, modbus.NewDecoder(), modbusWire(90, []byte{1}), false, false},
		{"unknown diagnostic", "modbus", 502, modbus.NewDecoder(), modbusWire(8, []byte{0, 21, 0, 0}), false, false},
		{"CANopen MEI", "modbus", 502, modbus.NewDecoder(), modbusWire(43, []byte{13}), false, false},
		{"device identification", "modbus", 502, modbus.NewDecoder(), modbusWire(43, []byte{14, 1, 0}), true, false},
		{"read", "dnp3", 20000, dnp3.NewDecoder(), dnp3Request(1, 0, []byte{60, 1, 6}), true, false},
		{"freeze", "dnp3", 20000, dnp3.NewDecoder(), dnp3Request(7, 0, []byte{20, 0, 6}), false, true},
		{"assign class", "dnp3", 20000, dnp3.NewDecoder(), dnp3Request(22, 0, []byte{60, 2, 6, 30, 0, 6}), false, true},
		{"unknown request", "dnp3", 20000, dnp3.NewDecoder(), dnp3Request(34, 0, nil), false, false},
	} {
		t.Run(tc.protocol+"/"+tc.name, func(t *testing.T) {
			state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"),
				SrcPort: 40000, DstPort: tc.port, Proto: 6}, time.Unix(0, 0))
			snapshot := rules.Snapshot{DPIMode: "enforce", Default: rules.ActionDeny, Firewall: []rules.Entry{
				{ID: "read-only", Action: rules.ActionAllow,
					Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(int(tc.port))}},
					ICS:       rules.ICSPredicate{Protocol: tc.protocol, ReadOnly: true}},
			}}
			res, err := tc.decoder.ParseStream(state, dpi.StreamView{Bytes: tc.wire})
			if err != nil || len(res.Frames) != 1 || len(res.Frames[0].Events) != 1 {
				t.Fatalf("decode=%+v err=%v", res, err)
			}
			ev := res.Frames[0].Events[0]
			for form, attrs := range decodertest.Forms(t, ev.Attributes) {
				ev.Attributes = attrs
				contexts := evalContextsFromDPIEvent(&snapshot, state, &dpi.ParsedPacket{
					Proto: "tcp", SrcPort: 40000, DstPort: tc.port,
				}, ev, "", "")
				if len(contexts) == 0 {
					t.Fatal("missing evaluation context")
				}
				for _, ctx := range contexts {
					action, matched := rules.NewEvaluator(&snapshot).EvaluateMatch(ctx)
					if (action == rules.ActionAllow) != tc.read || (matched != nil) != tc.read ||
						ctx.ICS.ReadOnly != tc.read || ctx.ICS.WriteOnly != tc.write {
						t.Fatalf("%s action=%s matched=%v ctx=%+v", form, action, matched, ctx.ICS)
					}
					if rules.PreviewMatch(snapshot.Firewall[0], ctx) != tc.read {
						t.Fatalf("%s preview differs from production", form)
					}
				}
			}
		})
	}
}
