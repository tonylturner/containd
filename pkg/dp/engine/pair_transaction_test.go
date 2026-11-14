// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestDS34LedgerTransaction(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, occupied := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "occupied"}[occupied], func(t *testing.T) {
			resources := pairResources()
			total := 0
			b := newPairing("modbus", resources, false, &total).(*pairLedger[modbusPairKey, modbus.PairShape])
			defer b.close()
			if occupied {
				b.apply(pairMB(pairRead(99)), dpi.ClientToServer, requestPermit{}, now)
			}
			before := resources.Budget.Status().InUse
			oldGrants, oldMarkers := b.grants, b.markers
			q := pairRead(1)
			ops := []pairOperation{{frame: pairMB(q), dir: dpi.ClientToServer}, {frame: pairMB(pairMBReply(q)), dir: dpi.ServerToClient}, {frame: pairMB(pairMBReply(q)), dir: dpi.ServerToClient}}
			if why := b.transact(ops, now); why != pairUnpaired {
				t.Fatal(why)
			}
			if resources.Budget.Status().InUse != before || total != len(oldGrants) {
				t.Fatal("rollback accounting", total, resources.Budget.Status())
			}
			if cap(b.grants) != cap(oldGrants) || cap(b.markers) != cap(oldMarkers) {
				t.Fatal("published temporary capacity")
			}
			if why := b.transact(ops[:2], now); why != pairOK {
				t.Fatal(why)
			}
			if total != len(oldGrants) {
				t.Fatal(total)
			}
			b.close()
			if resources.Budget.Status().InUse != 0 {
				t.Fatal(resources.Budget.Status())
			}
		})
	}
}
