// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestFirstCommandKernelReplySteering uses the real decoder, evaluator and
// NFQUEUE source, with endpoint reads as the oracle. The server emits each
// complete reply in one write; this does not claim atomic split-ADU protection.
func TestFirstCommandKernelReplySteering(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		for _, zones := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/zones=%v", mode, zones), func(t *testing.T) {
				ctx := newFirstCommandLab(t)
				srv := startModbusRecorder(t)
				unit := uint8(1)
				scope := func(id, direction string, action rules.Action) rules.Entry {
					entry := rules.Entry{
						ID: id, Action: action, Log: true,
						Sources: []string{"198.18.50.0/24"}, Destinations: []string{fcServerIP + "/32"},
						Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
						ICS: rules.ICSPredicate{Mode: mode, Protocol: "modbus",
							FunctionCode: []uint8{3}, Direction: direction},
					}
					if zones {
						entry.SourceZones, entry.DestZones = []string{"client"}, []string{"server"}
					}
					return entry
				}
				deny := scope("deny-unit-one-response", "response", rules.ActionDeny)
				deny.ICS.UnitID = &unit
				snap := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
					deny, scope("allow-read-request", "request", rules.ActionAllow),
				}}
				if zones {
					snap.ZoneIfaces = map[string][]string{"client": {"fc0"}, "server": {"fc1"}}
				}
				if mode == "monitor" {
					// Monitor rules cannot grant transport permission.
					snap.Firewall = append(snap.Firewall, rules.Entry{ID: "transport", Action: rules.ActionAllow})
				}
				e := startKernelEngine(t, ctx, snap)

				for i, unitID := range []byte{2, 1, 2} {
					c := dialFirstCommand(ctx, t, fmt.Sprintf("198.18.50.%d", 70+i))
					request := c.next(3, 0, 2)
					request[6] = unitID
					c.write(request)
					if mode == "enforce" && unitID == 1 {
						// Requires ECONNRESET and zero payload bytes at the client,
						// not just a missing final ADU or unchanged server registers.
						c.expectReset()
					} else {
						// Unit 2 has no response ALLOW: existing reply default-deny
						// suppression must remain intact. Monitor DENY cannot block.
						c.expectReadReply()
					}
					if n := srv.received(c.src); n != len(request) {
						t.Fatalf("server received %d request bytes, want %d", n, len(request))
					}
				}
				if mode == "enforce" {
					if n := ruleHits(e, deny.ID); n != 1 {
						t.Fatalf("response DENY hits = %d, want 1", n)
					}
				} else {
					hits := 0
					for _, ev := range e.Events().List(0) {
						if ev.Kind == "ics.decision" && ev.Attributes["ruleId"] == deny.ID &&
							ev.Attributes["mode"] == "monitor" && ev.Attributes["decision"] == "would_drop" {
							hits++
						}
					}
					if hits != 1 {
						t.Fatalf("response monitor would-drop hits = %d, want 1", hits)
					}
				}
			})
		}
	}
}
