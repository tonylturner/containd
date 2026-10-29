// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"bytes"
	"testing"
	"time"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

var testKey = Key{1, 1}

func newTestTable(t *testing.T, b Budgets, transport uint8, port uint16) (*Table, *time.Time) {
	t.Helper()
	now := time.Unix(0, 0)
	table, err := NewTable(b, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !table.Open(testKey, Meta{Transport: transport, Ports: [2]uint16{50000, port}}) {
		t.Fatal("open")
	}
	if transport == ics.TCP {
		observe(t, table, Arrival{Direction: 0, Sequence: 99, SYN: true})
		observe(t, table, Arrival{Direction: 1, Sequence: 199, SYN: true})
	}
	return table, &now
}

func observe(t *testing.T, table *Table, a Arrival) Decision {
	t.Helper()
	d, ok := table.Observe(testKey, a)
	if !ok {
		t.Fatal("unknown key or direction")
	}
	entries, charged := table.Usage()
	if entries > table.budgets.Entries || charged > table.budgets.ChargedBytes {
		t.Fatalf("caps exceeded: %d/%d", entries, charged)
	}
	return d
}

func complete(t *testing.T, table *Table, f fixture) Decision {
	t.Helper()
	d := observe(t, table, Arrival{Sequence: 100, Payload: f.request})
	if len(f.reply) > 0 {
		d = observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
	}
	return d
}

func TestPortsAndReplay(t *testing.T) {
	for _, f := range fixtures() {
		for _, port := range []uint16{f.port, 12345, 502} {
			table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, port)
			d := complete(t, table, f)
			if d.State != Confirmed || d.Protocol != f.protocol {
				t.Fatalf("port %d: %+v", port, d)
			}
			if port == f.port && d.Expected[1] != f.protocol ||
				port == 12345 && d.Expected[1] != "" ||
				port == 502 && d.Expected[1] != Modbus {
				t.Fatal(d)
			}
			_, replay, ok := table.Take(testKey)
			if !ok || !bytes.Equal(replay.Bytes[0], f.request) || !bytes.Equal(replay.Bytes[1], f.reply) {
				t.Fatalf("replay: %+v", replay)
			}
			if _, _, ok := table.Take(testKey); ok {
				t.Fatal("duplicate handoff")
			}
			if _, n := table.Usage(); n != EntryCharge {
				t.Fatalf("prefix storage still charged: %d", n)
			}
			if table.Open(testKey, Meta{}) {
				t.Fatal("silently replaced confirmed entry")
			}
			before := table.Counters()
			d = observe(t, table, Arrival{Payload: []byte("wrong application")})
			if d.State != Confirmed || table.Counters() != before {
				t.Fatal("reprobed terminal decision")
			}
			table.Release(testKey)
			if n, charge := table.Usage(); n != 0 || charge != 0 {
				t.Fatal(n, charge)
			}
			if !table.Open(testKey, Meta{Transport: ics.TCP}) {
				t.Fatal("released incarnation cannot be reused")
			}
		}
	}
}

func TestHeaderSegmentation(t *testing.T) {
	for _, f := range fixtures() {
		for split := 1; split < f.header; split++ {
			table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, f.port)
			observe(t, table, Arrival{Sequence: 100, Payload: f.request[:split]})
			d := observe(t, table, Arrival{Sequence: 100 + uint32(split), Payload: f.request[split:]})
			if len(f.reply) > 0 {
				d = observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
			}
			if d.State != Confirmed {
				t.Fatalf("%s split %d: %+v", f.protocol, split, d)
			}
		}
		for _, raised := range []bool{false, true} {
			b := DefaultBudgets()
			if raised {
				b.Arrivals = 256
			}
			table, _ := newTestTable(t, b, ics.TCP, f.port)
			var d Decision
			for i := range f.request {
				d = observe(t, table, Arrival{Sequence: 100 + uint32(i), Payload: f.request[i : i+1]})
			}
			if len(f.reply) > 0 {
				d = observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
			}
			if !raised && f.protocol == ENIP {
				if d.State != Incomplete || d.Coverage != Budget {
					t.Fatal(d)
				}
			} else if d.State != Confirmed {
				t.Fatalf("%s one-byte raised=%v: %+v", f.protocol, raised, d)
			}
		}
	}
}

func TestPrefixOrderingAndOverlap(t *testing.T) {
	f := fixtures()[0]
	for _, tc := range []struct {
		name     string
		arrivals []Arrival
		want     State
		coverage Coverage
	}{
		{"out of order", []Arrival{
			{Sequence: 106, Payload: f.request[6:]}, {Sequence: 100, Payload: f.request[:6]},
		}, Confirmed, ""},
		{"equal overlap", []Arrival{
			{Sequence: 100, Payload: f.request[:9]}, {Sequence: 106, Payload: f.request[6:]},
		}, Confirmed, ""},
		{"duplicate", []Arrival{
			{Sequence: 100, Payload: f.request[:9]}, {Sequence: 100, Payload: f.request[:9]},
			{Sequence: 109, Payload: f.request[9:]},
		}, Confirmed, ""},
		{"conflict", []Arrival{
			{Sequence: 100, Payload: f.request[:9]}, {Sequence: 100, Payload: []byte{99}},
		}, Incomplete, Conflict},
		{"pending conflict", []Arrival{
			{Sequence: 109, Payload: f.request[9:]}, {Sequence: 109, Payload: []byte{99}},
		}, Incomplete, Conflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, f.port)
			for _, a := range tc.arrivals {
				observe(t, table, a)
			}
			d := observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
			if d.State != tc.want || d.Coverage != tc.coverage {
				t.Fatal(d)
			}
			if d.State == Confirmed {
				_, r, _ := table.Take(testKey)
				if !bytes.Equal(r.Bytes[0], f.request) {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestCoverageBudgets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Budgets)
		arrivals  []Arrival
		reason    Coverage
	}{
		{"ranges", func(b *Budgets) { b.PendingRanges = 1 }, []Arrival{
			{Sequence: 110, Payload: []byte{1}}, {Sequence: 112, Payload: []byte{1}},
		}, Budget},
		{"bytes", func(b *Budgets) { b.BytesPerDirection = 4 }, []Arrival{
			{Sequence: 100, Payload: []byte{0, 1, 0, 0}},
		}, Budget},
		{"beyond bytes", func(b *Budgets) { b.BytesPerDirection = 4 }, []Arrival{
			{Sequence: 100, Payload: make([]byte, 5)},
		}, Budget},
		{"duplicate work", func(b *Budgets) { b.Arrivals = 2 }, []Arrival{
			{Sequence: 100, Payload: []byte{0}}, {Sequence: 100, Payload: []byte{0}},
		}, Budget},
		{"truncated", func(_ *Budgets) {}, []Arrival{{Truncated: true}}, Truncated},
		{"conflicting SYN", func(_ *Budgets) {}, []Arrival{{Sequence: 300, SYN: true}}, Conflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := DefaultBudgets()
			tc.configure(&b)
			table, _ := newTestTable(t, b, ics.TCP, 12345)
			var d Decision
			for _, a := range tc.arrivals {
				d = observe(t, table, a)
			}
			if d.State != Incomplete || d.Coverage != tc.reason {
				t.Fatal(d)
			}
		})
	}
	table, now := newTestTable(t, DefaultBudgets(), ics.TCP, 12345)
	*now = now.Add(time.Hour) // SYN-only entries have no payload deadline.
	if d, _ := table.Poll(testKey); d.State != NeedMore {
		t.Fatal(d)
	}
	observe(t, table, Arrival{Sequence: 100, Payload: []byte{0}})
	*now = now.Add(5 * time.Second)
	if d, _ := table.Poll(testKey); d.State != Incomplete || d.Coverage != Timeout {
		t.Fatal(d)
	}
	if table.Counters().Incomplete[1] != 1 {
		t.Fatal(table.Counters())
	}
	table.Release(testKey)
	table.Open(testKey, Meta{Transport: ics.TCP})
	if d := observe(t, table, Arrival{Payload: []byte{0}}); d.Coverage != Midstream {
		t.Fatal(d)
	}
}

func TestMemoryAndEntryCaps(t *testing.T) {
	t.Logf("EntryCharge=%d bytes", EntryCharge)
	b := DefaultBudgets()
	b.Entries = 1
	table, _ := newTestTable(t, b, ics.TCP, 12345)
	if n, charge := table.Usage(); n != 1 || charge != EntryCharge {
		t.Fatal("SYN allocated payload", n, charge)
	}
	if table.Open(Key{2, 1}, Meta{Transport: ics.TCP}) || table.Counters().Overflow != 1 {
		t.Fatal("entry cap")
	}
	observe(t, table, Arrival{Sequence: 100, Payload: []byte{0}})
	e := table.entries[testKey]
	expected := EntryCharge
	for _, p := range e.prefixes {
		expected += cap(p.data) + cap(p.ranges)*int(unsafe.Sizeof(span{}))
	}
	if _, charge := table.Usage(); charge != expected {
		t.Fatal("not charging capacities", charge, expected)
	}
	b = DefaultBudgets()
	b.ChargedBytes = EntryCharge + b.BytesPerDirection
	table, _ = newTestTable(t, b, ics.TCP, 12345)
	d := observe(t, table, Arrival{Sequence: 100, Payload: []byte{0}})
	if d.Coverage != Budget || table.Counters().Overflow != 1 {
		t.Fatal(d, table.Counters())
	}
	if _, charge := table.Usage(); charge != EntryCharge {
		t.Fatal("allocated over cap", charge)
	}
	table.Release(testKey)
	if _, charge := table.Usage(); charge != 0 {
		t.Fatal(charge)
	}
}

func TestInvalidInputs(t *testing.T) {
	b := DefaultBudgets()
	for _, mutate := range []func(*Budgets){
		func(b *Budgets) { b.BytesPerDirection = 0 },
		func(b *Budgets) { b.PendingRanges = -1 },
		func(b *Budgets) { b.Arrivals = 0 },
		func(b *Budgets) { b.Duration = 0 },
		func(b *Budgets) { b.UDPDatagrams = 0 },
		func(b *Budgets) { b.Entries = 0 },
		func(b *Budgets) { b.ChargedBytes = EntryCharge - 1 },
		func(b *Budgets) { b.BytesPerDirection = b.ChargedBytes + 1 },
		func(b *Budgets) { b.PendingRanges = int(^uint(0) >> 1) },
		func(b *Budgets) { b.UDPDatagrams = int(^uint(0) >> 1) },
	} {
		bad := b
		mutate(&bad)
		if _, err := NewTable(bad, time.Now); err == nil {
			t.Fatal("invalid budgets accepted", bad)
		}
	}
	if _, err := NewTable(b, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	table, _ := newTestTable(t, b, ics.TCP, 502)
	if table.Open(Key{2, 1}, Meta{Transport: 99}) {
		t.Fatal("invalid transport admitted")
	}
	if _, ok := table.Observe(testKey, Arrival{Direction: 2}); ok {
		t.Fatal("invalid direction")
	}
	if _, ok := table.Observe(Key{99, 99}, Arrival{}); ok {
		t.Fatal("unknown key")
	}
	if _, ok := table.Poll(Key{99, 99}); ok {
		t.Fatal("unknown poll")
	}
	if _, _, ok := table.Take(Key{99, 99}); ok {
		t.Fatal("unknown take")
	}
}

func TestAmbiguityAndNegativeCache(t *testing.T) {
	table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
	observe(t, table, Arrival{Sequence: 100, Payload: fixtures()[0].request})
	d := observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: fixtures()[1].request})
	if d.State != Ambiguous || d.Protocol != "" || table.Counters().Ambiguity != 1 {
		t.Fatal(d, table.Counters())
	}
	for _, port := range []uint16{502, 20000, 2404, 44818, 12345} {
		for _, b := range negativeCorpus() {
			table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, port)
			d = observe(t, table, Arrival{Sequence: 100, Payload: b})
			if d.State == Confirmed {
				t.Fatal(port, d)
			}
			before := table.Counters()
			next := observe(t, table, Arrival{Sequence: 100 + uint32(len(b)), Payload: fixtures()[1].request})
			if terminal(d.State) && (d != next || table.Counters() != before) {
				t.Fatal("terminal cache changed")
			}
		}
	}
}

func TestUDPDatagrams(t *testing.T) {
	f := fixtures()[3]
	table, _ := newTestTable(t, DefaultBudgets(), ics.UDP, 44818)
	observe(t, table, Arrival{Payload: f.request})
	d := observe(t, table, Arrival{Direction: 1, Payload: f.reply})
	if d.State != Confirmed || d.Protocol != ENIP || d.Expected[1] != ENIP {
		t.Fatal(d)
	}
	_, r, ok := table.Take(testKey)
	if !ok || len(r.Datagrams) != 2 || !bytes.Equal(r.Bytes[0], f.request) || !bytes.Equal(r.Bytes[1], f.reply) {
		t.Fatal(r)
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.UDP, 12345)
	// Two partial datagrams must never be stitched into a RegisterSession.
	d = observe(t, table, Arrival{Payload: f.request[:24]})
	d = observe(t, table, Arrival{Payload: f.request[24:]})
	if d.State != Reject {
		t.Fatal(d)
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.UDP, 12345)
	for range 4 {
		d = observe(t, table, Arrival{Payload: f.request})
	}
	if d.State != Incomplete || d.Coverage != Budget || len(table.entries[testKey].datagrams) != 4 {
		t.Fatal(d)
	}
	e := table.entries[testKey]
	if _, charge := table.Usage(); charge != EntryCharge+retainedCharge(e) {
		t.Fatal("UDP accounting", charge)
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.UDP, 12345)
	observe(t, table, Arrival{Payload: f.request})
	observe(t, table, Arrival{Payload: f.request})
	_, r, ok = table.Take(testKey)
	if ok {
		t.Fatal("candidate must not hand off", r)
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.UDP, 12345)
	if d := observe(t, table, Arrival{}); d.State != Reject {
		t.Fatal("empty UDP datagram", d)
	}
	if _, charged := table.Usage(); charged != EntryCharge {
		t.Fatal("empty datagram allocated prefix", charged)
	}
	table, _ = newTestTable(t, DefaultBudgets(), ics.UDP, 12345)
	observe(t, table, Arrival{Payload: f.request})
	for range 3 {
		d = observe(t, table, Arrival{Direction: 1})
	}
	if d.State != Incomplete || d.Coverage != Budget {
		t.Fatal("empty datagrams bypassed datagram cap", d)
	}
}

func TestSYNCarriedPayloadAndWrap(t *testing.T) {
	f := fixtures()[0]
	table, err := NewTable(DefaultBudgets(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	table.Open(testKey, Meta{Transport: ics.TCP})
	observe(t, table, Arrival{SYN: true, Sequence: ^uint32(0) - 3, Payload: f.request[:6]})
	observe(t, table, Arrival{Sequence: 3, Payload: f.request[6:]})
	observe(t, table, Arrival{Direction: 1, SYN: true, Sequence: 199})
	d := observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
	if d.State != Confirmed {
		t.Fatal(d)
	}
}

func TestReplayPreservesPendingRanges(t *testing.T) {
	f := fixtures()[0]
	table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
	observe(t, table, Arrival{Sequence: 120, Payload: []byte("pending")})
	observe(t, table, Arrival{Sequence: 100, Payload: f.request})
	d := observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: f.reply})
	if d.State != Confirmed {
		t.Fatal(d)
	}
	_, r, ok := table.Take(testKey)
	if !ok || r.Sequence != [2]uint32{100, 200} ||
		len(r.Pending[0]) != 1 || r.Pending[0][0].Sequence != 120 ||
		string(r.Pending[0][0].Bytes) != "pending" || !bytes.Equal(r.Bytes[0], f.request) {
		t.Fatal(r)
	}
}
