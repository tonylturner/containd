// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestICSQueueChainMarksHandshakes pins the chain every generic ICS queue
// line jumps to: a packet conntrack tracks in a connection it has not seen
// complete its handshake is queued with HandshakeMark, any other with
// containd's mark bits cleared.
// The chain is declared once, before the forward chain, and only for a
// ruleset that queues a generic ICS rule.
func TestICSQueueChainMarksHandshakes(t *testing.T) {
	modbus := rules.Entry{ID: "modbus", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}, Action: rules.ActionAllow}
	iec := rules.Entry{ID: "iec", Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
		ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "iec104"}, Action: rules.ActionAllow}
	const chain = "  chain ics_queue {\n" +
		"    ct status assured meta mark set meta mark and 0xf0ffffff queue num 100;\n" +
		"    ct state != { invalid, untracked } meta mark set meta mark and 0xf0ffffff or 0x02000000 queue num 100;\n" +
		"    meta mark set meta mark and 0xf0ffffff queue num 100;\n" +
		"  }\n"
	for _, tc := range []struct {
		name    string
		queueID int
		entries []rules.Entry
		want    bool
	}{
		{"generic ICS rule", 100, []rules.Entry{modbus, iec}, true},
		{"IEC104 rules only", 100, []rules.Entry{iec}, false},
		{"no queue", 0, []rules.Entry{modbus}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompiler()
			c.QueueID = tc.queueID
			text, err := compileWithoutCounters(c, &rules.Snapshot{Default: rules.ActionDeny, Firewall: tc.entries})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(text, "chain "+ICSQueueChain); got != map[bool]int{true: 1, false: 0}[tc.want] {
				t.Fatalf("%d %s chains:\n%s", got, ICSQueueChain, text)
			}
			if !tc.want {
				if strings.Contains(text, ICSQueueChain) {
					t.Fatalf("a line jumps to the undeclared %s:\n%s", ICSQueueChain, text)
				}
				return
			}
			if i := strings.Index(text, chain); i < 0 || i > strings.Index(text, "chain forward") {
				t.Fatalf("chain missing or after forward, want:\n%s\nin:\n%s", chain, text)
			}
			if !strings.Contains(text, "    meta mark & 0x04000000 == 0 tcp dport 502 jump ics_queue;\n") {
				t.Fatalf("the modbus line does not jump to %s:\n%s", ICSQueueChain, text)
			}
		})
	}
}

func TestQueueMarks(t *testing.T) {
	for _, tc := range []struct {
		mark                uint32
		envelope, handshake bool
	}{
		{0, false, false},
		{EnvelopeMark, true, false},
		{HandshakeMark, false, true},
		{HandshakeMark | 0x5, false, true},
		{EnvelopeMark | HandshakeMark, true, true},
		{EnvelopeMark | HandshakeMark | 0x5, true, true},
		{0x00ffffff, false, false},
	} {
		if EnvelopeMarked(tc.mark) != tc.envelope || HandshakeMarked(tc.mark) != tc.handshake {
			t.Fatalf("mark %#x: envelope %v, handshake %v; want %v, %v", tc.mark, EnvelopeMarked(tc.mark), HandshakeMarked(tc.mark), tc.envelope, tc.handshake)
		}
	}
}
