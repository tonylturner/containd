// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"bytes"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestOversizedNegativeArrival(t *testing.T) {
	tls := join([]byte{0x16, 3, 1, 5, 0xb4, 1, 0, 5, 0xb0, 3, 3}, make([]byte, 1449))
	for _, n := range []int{1025, 1460} {
		for _, transport := range []uint8{ics.TCP, ics.UDP} {
			table, _ := newTestTable(t, DefaultBudgets(), transport, 502)
			d := observe(t, table, Arrival{Sequence: 100, Payload: tls[:n]})
			if d.State != Reject || d.Coverage != "" || table.Counters().Incomplete[0] != 0 {
				t.Fatal(n, transport, d, table.Counters())
			}
		}
	}
}

func TestClippedArrivalNeverConfirms(t *testing.T) {
	table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 20000)
	b := join(link(nil), make([]byte, 1024))
	d := observe(t, table, Arrival{Sequence: 100, Payload: b})
	if d.State != Incomplete || d.Coverage != Budget || table.Counters().Confirms != 0 {
		t.Fatal(d, table.Counters())
	}
	_, replay, ok := table.Take(testKey)
	if !ok || !bytes.Equal(replay.Bytes[0], b[:1024]) {
		t.Fatal("clipped prefix not retained", replay)
	}
}

func TestFullDirectionCanStillPair(t *testing.T) {
	b := DefaultBudgets()
	b.BytesPerDirection = len(fixtures()[0].request)
	table, _ := newTestTable(t, b, ics.TCP, 502)
	d := observe(t, table, Arrival{Sequence: 100, Payload: fixtures()[0].request})
	if d.State != Candidate {
		t.Fatal("one full direction exhausted the connection", d)
	}
	d = observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: fixtures()[0].reply})
	if d.State != Confirmed {
		t.Fatal(d)
	}
}

func TestUniqueConfirmationWithPartialSibling(t *testing.T) {
	for _, tid := range []uint16{0x6500, 0x0400, 0x682c} {
		table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
		f := fixtures()[0]
		f.request, f.reply = transaction(f.request, tid), transaction(f.reply, tid)
		d := complete(t, table, f)
		if d.State != Confirmed || d.Protocol != Modbus {
			t.Fatal(tid, d)
		}
	}
}

func TestSYNOnlyDeadline(t *testing.T) {
	table, now := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
	*now = now.Add(5 * time.Second)
	d, ok := table.Poll(testKey)
	if !ok || d.State != Incomplete || d.Coverage != Timeout || table.Counters().Incomplete[1] != 1 {
		t.Fatal(d, table.Counters())
	}
	if _, charged := table.Usage(); charged != EntryCharge {
		t.Fatal("SYN-only allocation", charged)
	}
}

func TestReorderedPipelinedSegmentation(t *testing.T) {
	f := fixtures()[0]
	a := join(transaction(f.request, 1), transaction(f.request, 2))
	b := join(transaction(f.reply, 2), transaction(f.reply, 1))
	for split := 1; split < len(b); split++ {
		table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 502)
		observe(t, table, Arrival{Sequence: 100, Payload: a[:7]})
		observe(t, table, Arrival{Sequence: 107, Payload: a[7:]})
		observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: b[:split]})
		d := observe(t, table, Arrival{Direction: 1, Sequence: 200 + uint32(split), Payload: b[split:]})
		if d.State != Confirmed || d.Protocol != Modbus {
			t.Fatal(split, d)
		}
	}
}

func TestIECAdjacentSegmentation(t *testing.T) {
	s := []byte{0x68, 4, 1, 0, 0, 0}
	i := []byte{0x68, 14, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 1, 0, 0, 1}
	for _, tail := range [][]byte{fixtures()[2].request, i} {
		b := join(s, s, tail)
		for split := 1; split < len(b); split++ {
			table, _ := newTestTable(t, DefaultBudgets(), ics.TCP, 2404)
			observe(t, table, Arrival{Sequence: 100, Payload: b[:split]})
			d := observe(t, table, Arrival{Sequence: 100 + uint32(split), Payload: b[split:]})
			if d.State != Confirmed || d.Protocol != IEC104 {
				t.Fatal(split, d)
			}
		}
	}
}

func TestSweepDeadlines(t *testing.T) {
	b := DefaultBudgets()
	b.Entries = 3
	table, now := newTestTable(t, b, ics.TCP, 502)
	pending, confirmed := Key{2, 1}, Key{3, 1}
	for _, key := range []Key{pending, confirmed} {
		if !table.Open(key, Meta{Transport: ics.TCP}) {
			t.Fatal("open")
		}
		table.Observe(key, Arrival{SYN: true, Sequence: 99})
	}
	table.Observe(confirmed, Arrival{Sequence: 100, Payload: link(nil)})
	*now = now.Add(4 * time.Second)
	table.Observe(pending, Arrival{Sequence: 100, Payload: []byte{0}})
	*now = now.Add(time.Second)
	expired := table.Sweep(*now)
	if len(expired) != 1 || expired[0] != testKey || len(table.Sweep(*now)) != 0 {
		t.Fatal("new expirations", expired)
	}
	if table.Counters().Incomplete[1] != 1 {
		t.Fatal(table.Counters())
	}
	d, _ := table.Poll(testKey)
	if d.State != Incomplete || d.Coverage != Timeout {
		t.Fatal(d)
	}
	// Explicit Release preserves the terminal-cache contract and frees admission.
	table.Release(expired[0])
	if !table.Open(Key{4, 1}, Meta{Transport: ics.TCP}) {
		t.Fatal("expired slot could not be reused")
	}
	*now = now.Add(4 * time.Second)
	expired = table.Sweep(*now)
	if len(expired) != 1 || expired[0] != pending {
		t.Fatal(expired)
	}
	if d, _ := table.Poll(confirmed); d.State != Confirmed {
		t.Fatal("Sweep evicted a confirmed decision", d)
	}
}

func TestUDPImplicitNotExpected(t *testing.T) {
	table, _ := newTestTable(t, DefaultBudgets(), ics.UDP, 2222)
	if d, _ := table.Poll(testKey); d.Expected != [2]Protocol{} {
		t.Fatal("no implicit-I/O probe exists", d)
	}
}

func TestClippedUDPStillUsesOriginalBoundary(t *testing.T) {
	b := DefaultBudgets()
	b.BytesPerDirection = 24
	table, _ := newTestTable(t, b, ics.UDP, 44818)
	reply := encapsulate(4, 0, append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...))
	d := observe(t, table, Arrival{Payload: reply})
	if d.State != Incomplete || d.Coverage != Budget {
		t.Fatal("valid long datagram falsely rejected", d)
	}
	_, replay, ok := table.Take(testKey)
	if !ok || len(replay.Datagrams) != 1 || replay.Datagrams[0].Length != len(reply) ||
		!bytes.Equal(replay.Bytes[0], reply[:24]) {
		t.Fatal(replay)
	}
}

func TestUDPDirectionalContradiction(t *testing.T) {
	table, _ := newTestTable(t, DefaultBudgets(), ics.UDP, 44818)
	observe(t, table, Arrival{Payload: encapsulate(4, 0, nil)})
	observe(t, table, Arrival{Payload: []byte("GET / HTTP/1.1\r\n\r\n")})
	reply := encapsulate(4, 0, append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...))
	d := observe(t, table, Arrival{Direction: 1, Payload: reply})
	if d.State != Candidate || d.Results[3].States != [2]State{Reject, Confirmed} {
		t.Fatal("a selected datagram hid contradictory direction evidence", d)
	}
}
