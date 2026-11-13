// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDPIProtocolsRespectMasterOff(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			for _, protocol := range []struct {
				name    string
				port    uint16
				payload []byte
			}{
				{name: "modbus", port: 502, payload: modbusADU(1, 3, 0, 2)},
				{name: "dnp3", port: dnp3Port, payload: dnp3Read},
			} {
				t.Run(protocol.name, func(t *testing.T) {
					e, err := New(Config{DPIEnabled: false, DPIMode: mode})
					if err != nil {
						t.Fatal(err)
					}
					e.LoadRules(rules.Snapshot{DPIMode: mode, Default: rules.ActionAllow, Firewall: []rules.Entry{{
						ID: protocol.name, Action: rules.ActionDeny,
						Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(int(protocol.port))}},
						ICS:       rules.ICSPredicate{Protocol: protocol.name, Mode: mode},
					}}})
					handshake(e, 41000, protocol.port)
					packet := connSegment(false, 41000, protocol.port, 100, ackPsh, protocol.payload)
					if got := e.handlePacket(packet); got.Action != capture.Accept {
						t.Fatalf("DPI-off %s packet = %+v, want Accept", protocol.name, got)
					}
					if got := protoEvents(e, protocol.name); got != 0 {
						t.Fatalf("DPI-off %s emitted %d decoder events", protocol.name, got)
					}
				})
			}

			t.Run("iec104", func(t *testing.T) {
				h := newIECHarnessWithDPI(t, mode, false)
				h.e.dpiMode = mode
				h.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
				h.e.iec.dpi = h.e.dpiMgr
				h.e.iec.newPolicy = newRulesPolicy
				h.e.LoadRules(rules.Snapshot{DPIMode: mode, Default: rules.ActionAllow, Firewall: []rules.Entry{{
					ID: "iec104", Action: rules.ActionDeny,
					ICS: rules.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, Mode: mode},
				}}})
				h.handshake()
				_, got := h.send(true, apdu(46, 6, 1, 2001, 1))
				if got.Action != capture.Repeat {
					t.Fatalf("DPI-off IEC 104 packet = %+v, want pass through", got)
				}
				if count := protoEvents(h.e, "iec104"); count != 0 {
					t.Fatalf("DPI-off IEC 104 emitted %d decoder events", count)
				}
			})
		})
	}
}
