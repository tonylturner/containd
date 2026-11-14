// SPDX-License-Identifier: Apache-2.0
package project

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"testing"
)

func TestPairingUnitProjection(t *testing.T) {
	t.Run("modbus", func(t *testing.T) {
		u := &modbus.Unit{PairShape: modbus.PairShape{TransactionID: 1, UnitID: 2, FunctionCode: 3, Quantity: 2, Spans: []modbus.Span{{First: 10, Last: 11}}}}
		got, err := UnitObjects(u, rules.ClassRequest, dpi.ClientToServer)
		if err != nil || len(got) != 1 {
			t.Fatal(got, err)
		}
		if got[0].MessageClass != rules.ClassRequest || got[0].Direction != "request" || !got[0].ReadOnly || got[0].FunctionCode != 3 || *got[0].UnitID != 2 || got[0].Spans[0].High != 11 {
			t.Fatal(got)
		}
	})
	t.Run("dnp3-link-control", func(t *testing.T) {
		u := &dnp3.Unit{PairShape: dnp3.PairShape{LinkOnly: true, LinkFunction: 0, Link: dnp3.LinkProvenance{Source: 2, Destination: 1}}}
		got, err := UnitObjects(u, rules.ClassSession, dpi.ServerToClient)
		if err != nil || len(got) != 1 {
			t.Fatal(got, err)
		}
		if *got[0].Master != 1 || *got[0].Outstation != 2 || got[0].HasFunctionCode || got[0].Direction != "response" || got[0].MessageClass != rules.ClassSession {
			t.Fatal(got)
		}
	})
	t.Run("iec104-every-child", func(t *testing.T) {
		u := &iec104.Unit{PairShape: iec104.PairShape{Format: "I", TypeID: 1, Cause: 3, CA: 12, Objects: []iec104.Object{{IOA: 7}, {IOA: 9}}}}
		got, err := UnitObjects(u, rules.ClassAutonomous, dpi.ServerToClient)
		if err != nil || len(got) != 2 {
			t.Fatal(got, err)
		}
		if *got[0].IEC104.IOA != 7 || *got[1].IEC104.IOA != 9 || *got[0].IEC104.CA != 12 || !got[0].IEC104.SafeRead || got[1].MessageClass != rules.ClassAutonomous {
			t.Fatal(got)
		}
	})
	t.Run("no-unit-no-authority", func(t *testing.T) {
		if _, err := UnitObjects(nil, rules.ClassRequest, dpi.ClientToServer); err == nil {
			t.Fatal("missing unit projected")
		}
	})
}
