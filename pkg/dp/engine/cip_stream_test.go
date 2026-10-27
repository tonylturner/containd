// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// cipStreamRead is a SendRRData Read_Tag with a null address item and an
// unconnected data item, addressed to object class 4.
func cipStreamRead() []byte {
	raw := make([]byte, 44)
	binary.LittleEndian.PutUint16(raw[0:2], 0x6f)
	binary.LittleEndian.PutUint16(raw[2:4], 20)
	binary.LittleEndian.PutUint32(raw[4:8], 1)
	binary.LittleEndian.PutUint16(raw[30:32], 2)
	binary.LittleEndian.PutUint16(raw[36:38], 0xb2)
	binary.LittleEndian.PutUint16(raw[38:40], 4)
	copy(raw[40:], []byte{0x4c, 1, 0x20, 4})
	return raw
}

// CIP must take the same fail-closed pickup path as other framed ICS
// protocols, even if its first segment is only an encapsulation fragment.
func TestCIPStreamMidStreamPickupDropped(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "whole encapsulation"
		if partial {
			name = "encapsulation fragment"
		}
		t.Run(name, func(t *testing.T) {
			f := newModeFlow(t, "enforce", 44818)
			f.e.LoadRules(rules.Snapshot{
				Default: rules.ActionDeny,
				Firewall: []rules.Entry{
					clientToServer("cip-read", "44818", rules.ActionAllow,
						rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{0x4c}, ReadOnly: true, Mode: "enforce"}),
				},
			})
			raw := cipStreamRead()
			pickup := raw
			if partial {
				pickup = raw[5:11]
			}
			f.pickedUp("CIP without a handshake", f.decide(0, ackPsh, pickup), "cip-read", 0)
			if ev := failClosedEvents(f.e)[0]; ev.Proto != "cip" {
				t.Fatalf("decision protocol = %q, want cip", ev.Proto)
			}
			f.dropCachedAt(0, "CIP retransmission after pickup", pickup)
			f.e.verdictCache = NewVerdictCache(time.Minute, 16)
			f.pickedUp("CIP past cached denial", f.decide(0, ackPsh, pickup), "cip-read", 1)

			// An observed new handshake on the tuple restores inspection,
			// including reassembly across an encapsulation-header split.
			f.isn, f.next = 800000, 0
			f.syn()
			hits := ruleHits(f.e, "cip-read")
			f.accept("CIP read header fragment", raw[:7])
			if got := ruleHits(f.e, "cip-read"); got != hits {
				t.Fatalf("partial header decoded: hits %d -> %d", hits, got)
			}
			f.accept("rest of CIP read", raw[7:])
			if got := ruleHits(f.e, "cip-read"); got != hits+1 {
				t.Fatalf("read hits %d -> %d, want one decoded read", hits, got)
			}
			if got := len(failClosedEvents(f.e)); got != 1 {
				t.Fatalf("fail-closed events = %d, want only the original pickup", got)
			}
			select {
			case got := <-f.up.calls:
				t.Fatalf("dynamic block %q on the new CIP connection", got)
			default:
			}
		})
	}
}
