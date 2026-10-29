// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestCIPReadOnlyFromWireThroughPolicyAndConsumers(t *testing.T) {
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"),
		SrcPort: 40000, DstPort: 44818, Proto: 6}, time.Now())
	snapshot := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
		{ID: "read-only", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "44818"}},
			ICS: rules.ICSPredicate{Protocol: "cip", ReadOnly: true}},
	}}
	evaluator := rules.NewEvaluator(&snapshot)
	for _, tc := range []struct {
		name, wire  string
		read, write bool
	}{
		{"apply attributes", "0d0220012401", false, true},
		{"set member", "1903200424012801", false, true},
		{"CM close", "4e0220062401", false, true},
		{"CM large open", "5b0220062401", false, true},
		{"file download", "4c0220372401", false, true},
		{"Logix RMW", "4e0291025447", false, true},
		{"get attribute", "0e03200124013001", true, false},
		{"symbolic read", "4c02910254470100", true, false},
		{"symbolic fragmented read", "520291025447010000000000", true, false},
		{"template read", "4c02206c2401000000001000", true, false},
		{"unlisted target", "4c02209924010100", false, false},
		{"malformed read body", "4c0291025447010000", false, false},
		{"opaque unconnected send", "520220062401010000000000", false, false},
		{"reserved", "0b0220012401", false, false},
		{"response", "8e000000", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			// One SendRRData with a null address item and unconnected data
			// item. Service, target and body bytes above are independent
			// of the production classification table.
			wire := make([]byte, 40+len(message))
			binary.LittleEndian.PutUint16(wire, 0x6f)
			binary.LittleEndian.PutUint16(wire[2:], uint16(len(wire)-24))
			binary.LittleEndian.PutUint16(wire[30:], 2)
			binary.LittleEndian.PutUint16(wire[36:], 0xb2)
			binary.LittleEndian.PutUint16(wire[38:], uint16(len(message)))
			copy(wire[40:], message)
			result, err := cip.NewDecoder().ParseStream(state, dpi.StreamView{Bytes: wire})
			if err != nil || len(result.Frames) != 1 || len(result.Frames[0].Events) != 1 {
				t.Fatalf("decode=%+v err=%v", result, err)
			}
			event := result.Frames[0].Events[0]
			for form, attrs := range decodertest.Forms(t, event.Attributes) {
				ev := event
				ev.Attributes = attrs
				ctx := singleEvalContext(t, &snapshot, state, &dpi.ParsedPacket{
					Proto: "tcp", SrcPort: 40000, DstPort: 44818,
				}, ev, "", "")
				action, matched := evaluator.EvaluateMatch(ctx)
				if (action == rules.ActionAllow) != tc.read || (matched != nil) != tc.read ||
					ctx.ICS.ReadOnly != tc.read || ctx.ICS.WriteOnly != tc.write {
					t.Fatalf("%s action=%s matched=%v ctx=%+v", form, action, matched, ctx.ICS)
				}
				if rules.PreviewMatch(snapshot.Firewall[0], ctx) != tc.read {
					t.Fatalf("%s preview differs from production", form)
				}
				counter := stats.New()
				counter.RecordEvent(ev)
				ps := counter.Stats()[0]
				if ps.EventCount != 1 || (ps.ReadCount == 1) != tc.read || (ps.WriteCount == 1) != tc.write {
					t.Fatalf("%s stats=%+v", form, ps)
				}
				learner := learn.New()
				learner.RecordEvent("192.0.2.1", "192.0.2.2", ev)
				generated := learner.GenerateRules()
				if tc.read || tc.write {
					if len(generated) != 1 || generated[0].ICS.ReadOnly != tc.read || generated[0].ICS.WriteOnly != tc.write {
						t.Fatalf("%s learned rules=%+v", form, generated)
					}
				} else if len(generated) != 0 {
					t.Fatalf("%s unknown operation learned: %+v", form, generated)
				}
			}
		})
	}
}
