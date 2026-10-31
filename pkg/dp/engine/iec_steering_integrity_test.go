// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestMonitorCannotMaskInvalidEnforceEnvelope(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		mid, eid := "a-monitor", "z-enforce"
		if reverse {
			mid, eid = "z-monitor", "a-enforce"
		}
		snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "monitor", Firewall: []rules.Entry{
			{ID: mid, Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104"}},
			{ID: eid, Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		}}
		c := enforce.NewCompiler()
		c.QueueID = 101
		c.IEC104EnvelopeOpen = true
		text, err := c.CompileFirewall(&snap)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "tcp dport 2404") {
				lines = append(lines, line)
			}
		}
		if len(lines) != 2 || !strings.Contains(lines[0], "jump iec104_envelope") || !strings.Contains(lines[1], "jump iec104_monitor_queue") {
			t.Fatalf("reverse=%t: enforce steering must precede monitor steering: %v", reverse, lines)
		}
		e, err := New(Config{DPIEnabled: true})
		if err != nil {
			t.Fatal(err)
		}
		e.LoadRules(snap)
		// The first compiled jump determines the packet's queue mark. Its tuple
		// is untrusted, so only this mark can retain fail-closed ownership.
		d := e.HandlePacket(capture.Packet{Token: capture.NewToken(1, 1), Invalid: capture.InvalidIPv6, HasMark: true, Mark: enforce.EnvelopeMark})
		if d.Action != capture.Drop {
			t.Fatalf("reverse=%t invalid envelope packet: %+v", reverse, d)
		}
	}
}
