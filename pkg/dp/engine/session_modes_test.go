// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestPairingModes(t *testing.T) {
	t.Run("explicit-classes", testPairingExplicitClasses)
	for _, p := range runtimePairCases() {
		t.Run(p.protocol, func(t *testing.T) {
			for _, global := range []string{"enforce", "monitor"} {
				for _, mode := range []string{"", "enforce", "monitor"} {
					for _, overlap := range []bool{false, true} {
						for _, def := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
							t.Run(fmt.Sprintf("%s/rule=%s/overlap=%t/%s", global, mode, overlap, def), func(t *testing.T) {
								entries := []rules.Entry{runtimePairRule(p, mode)}
								if overlap {
									shadow := runtimePairRule(p, "monitor")
									shadow.ID = "observe-overlap"
									entries = append([]rules.Entry{shadow}, entries...)
								}
								snap := rules.Snapshot{Default: def, DPIMode: global, Firewall: entries}
								e := runtimePairEngine(t, snap, true)
								inlineHandshake(t, e, 41000, p.port)
								wantMode := mode
								if wantMode == "" {
									wantMode = global
								}
								s := runtimePairOwner(t, e, p)
								if s.mode != wantMode || s.pairing.(interface{ mode() string }).mode() != wantMode {
									t.Fatalf("effective session/ledger mode=%s/%s want %s", s.mode, s.pairing.(interface{ mode() string }).mode(), wantMode)
								}
								req := runtimePairPacket(p, false, 100, p.request)
								if d := e.HandlePacket(req); d.Action != capture.Repeat {
									t.Fatalf("request=%+v", d)
								}
								if e.sessions.pairingTotal+e.sessions.pairingObserve != 1 || len(e.sessions.held) != 0 {
									t.Fatal("request not recorded by the single ledger, or monitor held a token")
								}
								rep := runtimePairPacket(p, true, 500, p.reply)
								if d := e.HandlePacket(rep); d.Action != capture.Repeat {
									t.Fatalf("reply=%+v", d)
								}
								stamped := false
								for _, ev := range e.Events().List(0) {
									if ev.Proto == p.protocol && ev.Attributes["message_class"] == "solicited" {
										if ev.Attributes["pairing_outcome"] != "paired" || ev.Attributes["pairing_reason"] != string(pairOK) {
											t.Fatalf("incorrect observe/enforce pairing stamp: %+v", ev)
										}
										stamped = true
									}
								}
								if !stamped {
									t.Fatal("reply lacks decoded class and pairing outcome")
								}
							})
						}
					}
				}
			}
			t.Run("master-disabled", func(t *testing.T) {
				for _, mode := range []string{"monitor", "enforce"} {
					t.Run(mode, func(t *testing.T) {
						snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, mode)}}
						e := runtimePairEngine(t, snap, false)
						want := capture.Repeat
						if mode == "enforce" {
							// Preserve the existing unavailable-inspection
							// transport-scope drop, not a pairing decision.
							want = capture.Drop
						} else {
							inlineHandshake(t, e, 41000, p.port)
						}
						if d := e.HandlePacket(runtimePairPacket(p, true, 500, p.reply)); d.Action != want ||
							mode == "enforce" && d.Reason != "ics_uninspectable_master" {
							t.Fatalf("disabled DPI changed ordinary transport verdict: %+v", d)
						}
						if len(e.sessions.sessions) != 0 || e.sessions.pairingTotal != 0 {
							t.Fatal("disabled master created pairing state")
						}
						for _, ev := range e.Events().List(0) {
							if ev.Proto == p.protocol {
								t.Fatal("disabled master entered protocol inspection")
							}
						}
					})
				}
			})
			t.Run("observe-refusal", func(t *testing.T) {
				snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "monitor", Firewall: []rules.Entry{runtimePairRule(p, "monitor")}}
				e := runtimePairEngine(t, snap, true)
				// Force the actual Observe admission owner to refuse, without
				// replacing a decoder or bypassing the packet path.
				e.sessions.resources = limits.NewResources(limits.NewBudget(1), e.ledger)
				inlineHandshake(t, e, 41000, p.port)
				for _, pkt := range []capture.Packet{runtimePairPacket(p, false, 100, p.request[:3]), runtimePairPacket(p, true, 500, p.reply)} {
					if d := e.HandlePacket(pkt); d.Action != capture.Repeat || len(d.Resolved) != 0 {
						t.Fatalf("observe refusal changed verdict/held tokens: %+v", d)
					}
				}
				if e.sessions.pairingTotal != 0 || len(e.sessions.settlements) != 0 || len(e.sessions.sessions) != 0 {
					t.Fatal("refused Observe admission retained authority")
				}
				if e.sessions.resources.Budget.Status().InUse != 0 {
					t.Fatal("refused Observe admission leaked credit")
				}
			})
		})
	}
}

func testPairingExplicitClasses(t *testing.T) {
	for _, p := range runtimePairCases()[1:] {
		for _, class := range []string{"autonomous", "session"} {
			for _, def := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
				for _, explicit := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/explicit=%t", p.protocol, class, def, explicit), func(t *testing.T) {
						base := runtimePairRule(p, "enforce")
						entries := []rules.Entry{base}
						if explicit {
							permit := base
							permit.ID, permit.ICS.MessageClass = "explicit-class", class
							permit.ICS.Direction = "response"
							if class == "session" {
								permit.ICS.Direction = "request"
							}
							entries = append([]rules.Entry{permit}, entries...)
						}
						e := runtimePairEngine(t, rules.Snapshot{Default: def, DPIMode: "enforce", Firewall: entries}, true)
						inlineHandshake(t, e, 41000, p.port)
						var wire []byte
						reply, seq := class == "autonomous", uint32(100)
						if reply {
							seq = 500
						}
						switch {
						case p.protocol == "dnp3" && reply:
							wire = append([]byte(nil), dnp3Unsolicited...)
							wire[11] &^= 0x20 // no application Confirm requested
							binary.LittleEndian.PutUint16(wire[15:], dnp3CRC(wire[10:15]))
						case p.protocol == "dnp3":
							wire = []byte{5, 0x64, 5, 0xc0, 10, 0, 1, 0, 0, 0}
							binary.LittleEndian.PutUint16(wire[8:], dnp3CRC(wire[:8]))
						case reply:
							wire = apdu(1, 3, 1, 101, 1)
						default:
							wire = startdtAct
						}
						d := e.HandlePacket(runtimePairPacket(p, reply, seq, wire))
						want, reason := capture.Drop, autonomousRequired
						if class == "session" {
							reason = sessionRequired
						}
						if explicit {
							want = capture.Repeat
						}
						if d.Action != want || !explicit && d.Reason != string(reason) {
							t.Fatalf("class decision=%+v", d)
						}
						if e.sessions.pairingTotal != 0 {
							t.Fatal("autonomous/session control created a request grant")
						}
					})
				}
			}
		}
	}
}
