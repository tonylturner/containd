// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"bytes"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestAdoptMoveRemaps(t *testing.T) {
	table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
	observe(t, table, Arrival{Sequence: 100, Payload: fixtures()[0].request})
	result, ok := table.Adopt(testKey, "to", Remap{1, 0})
	if !ok || result.Conflict {
		t.Fatal(result, ok)
	}
	if _, ok := table.Poll(testKey); ok {
		t.Fatal("source survived")
	}
	d, _ := table.Observe("to", Arrival{Sequence: 200, Payload: fixtures()[0].reply})
	if d.State != Confirmed || d.Expected[0] != Modbus {
		t.Fatal(d)
	}
	_, r, _ := table.Take("to")
	if !bytes.Equal(r.Bytes[1], fixtures()[0].request) || r.Sequence != [2]uint32{200, 100} {
		t.Fatal(r)
	}
}

func TestAdoptPendingMerge(t *testing.T) {
	for _, remap := range []Remap{{0, 1}, {1, 0}} {
		table, err := NewTable(DefaultBudgets(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		table.Open(testKey, Meta{Transport: ics.TCP})
		table.Observe(testKey, Arrival{Direction: remap[0], SYN: true, Sequence: 99})
		table.Observe(testKey, Arrival{Direction: remap[1], SYN: true, Sequence: 199})
		table.Open("to", Meta{Transport: ics.TCP, Ports: [2]uint16{50000, 502}})
		table.Observe("to", Arrival{SYN: true, Sequence: 99})
		table.Observe("to", Arrival{Direction: 1, SYN: true, Sequence: 199})
		dir := uint8(0)
		seq := uint32(100)
		if remap[0] == 1 {
			dir, seq = 1, 200
		}
		table.Observe("to", Arrival{Direction: dir, Sequence: seq, Payload: fixtures()[0].request[:6]})
		// Source evidence has the same remapped origin, but only a pending suffix.
		sourceDir := remap[dir]
		table.Observe(testKey, Arrival{Direction: sourceDir, Sequence: seq + 6, Payload: fixtures()[0].request[6:]})
		result, ok := table.Adopt(testKey, "to", remap)
		if !ok || result.Conflict {
			t.Fatal(result, ok)
		}
		if !bytes.Equal(table.entries["to"].prefixes[dir].data[:12], fixtures()[0].request) {
			t.Fatal("merge lost evidence")
		}
	}
}

func TestAdoptPendingConflicts(t *testing.T) {
	for _, synConflict := range []bool{false, true} {
		table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
		table.Open("to", Meta{Transport: ics.TCP})
		seq := uint32(99)
		if synConflict {
			seq++
		}
		table.Observe("to", Arrival{SYN: true, Sequence: seq, Payload: []byte{0}})
		observe(t, table, Arrival{Sequence: 100, Payload: []byte{1}})
		result, ok := table.Adopt(testKey, "to", Remap{0, 1})
		if !ok || !result.Conflict {
			t.Fatal(result, ok)
		}
		for _, key := range []Key{testKey, "to"} {
			d, _, ok := table.Take(key)
			if !ok || d.State != Incomplete || d.Coverage != Conflict {
				t.Fatal(d, ok)
			}
		}
	}
}

func TestAdoptEarlierTerminal(t *testing.T) {
	for _, sourceFirst := range []bool{false, true} {
		table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
		table.Open("to", Meta{Transport: ics.TCP})
		if sourceFirst {
			complete(t, table, fixtures()[0])
			table.Finish("to")
		} else {
			table.Finish("to")
			complete(t, table, fixtures()[0])
		}
		table.Adopt(testKey, "to", Remap{0, 1})
		d, _ := table.Poll("to")
		want := Incomplete
		if sourceFirst {
			want = Confirmed
		}
		if d.State != want {
			t.Fatal(d)
		}
		if n, _ := table.Usage(); n != 1 {
			t.Fatal(n)
		}
	}
}

func TestEnabledProfilesAndFinish(t *testing.T) {
	b := DefaultBudgets()
	b.Protocols = []Protocol{IEC104}
	table, _ := newTestTable(t, b, ics.TCP, 502)
	d := complete(t, table, fixtures()[0])
	if d.State != Reject || d.Expected[1] != Modbus || d.Results[0] != (Result{}) {
		t.Fatal(d)
	}
	bad := DefaultBudgets()
	bad.Protocols = []Protocol{"unknown"}
	if _, err := NewTable(bad, time.Now); err == nil {
		t.Fatal("unknown enabled")
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.TCP, 502)
	observe(t, table, Arrival{Sequence: 100, Payload: fixtures()[0].request})
	observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: fixtures()[1].request})
	if _, _, ok := table.Take(testKey); ok {
		t.Fatal("provisional ambiguity taken")
	}
	d, _ = table.Finish(testKey)
	if d.State != Incomplete || d.Coverage != Closed || d.Results[0].State != Candidate || d.Results[1].State != Candidate {
		t.Fatal(d)
	}
}

func TestAmbiguityResolvesWithLaterEvidence(t *testing.T) {
	// Two private-FC MBAP messages also form a valid UnregisterSession ENIP
	// encapsulation. The next encapsulation rejects MBAP and confirms ENIP.
	poly := make([]byte, 24)
	poly[0], poly[5], poly[6], poly[7] = 0x66, 2, 1, 100
	poly[13], poly[14], poly[15] = 10, 1, 100
	table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 12345)
	d := observe(t, table, Arrival{Sequence: 100, Payload: poly})
	if d.State != Ambiguous {
		t.Fatal(d)
	}
	body := append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...)
	d = observe(t, table, Arrival{Sequence: 124, Payload: encapsulate(4, 0, body)})
	if d.State != Confirmed || d.Protocol != ENIP {
		t.Fatal(d)
	}
}

func TestTriggerAdmissionContract(t *testing.T) {
	for _, mode := range []string{"timeout", "truncated", "oversized", "midstream"} {
		table, now := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
		a := Arrival{Sequence: 100, Payload: fixtures()[0].request}
		switch mode {
		case "timeout":
			*now = now.Add(6 * time.Second)
		case "truncated":
			a.Truncated = true
		case "oversized":
			a.Payload = make([]byte, 2048)
		case "midstream":
			table.Release(testKey)
			table.Open(testKey, Meta{Transport: ics.TCP})
		}
		observe(t, table, a)
		_, r, ok := table.Take(testKey)
		if !ok || r.TriggerRetained {
			t.Fatal(mode, r)
		}
	}
}

func TestEnabledProfileConfiguration(t *testing.T) {
	b := DefaultBudgets()
	b.Protocols = []Protocol{Modbus, Modbus}
	if _, err := NewTable(b, time.Now); err == nil {
		t.Fatal("duplicate protocol")
	}
	b.Protocols = []Protocol{}
	table, _ := newTestTable(t, b, ics.TCP, 502)
	d := observe(t, table, Arrival{Sequence: 100, Payload: fixtures()[0].request})
	if d.State != Reject || d.Results != [4]Result{} || d.Expected[1] != Modbus {
		t.Fatal(d)
	}
	b.Protocols = []Protocol{Modbus}
	table, _ = newTestTable(t, b, ics.TCP, 502)
	b.Protocols[0] = IEC104
	d = complete(t, table, fixtures()[0])
	if d.State != Confirmed || d.Protocol != Modbus {
		t.Fatal("caller mutated enabled registry", d)
	}
}
