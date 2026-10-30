// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

var request = []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}
var reply = []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 1}
var instant = time.Unix(100, 0)

type byteDecoder struct {
	sessions []string
	ended    int
}

func (*byteDecoder) Supports(*flow.State) bool { panic("observation called Supports") }
func (*byteDecoder) Protocol() string          { return "modbus" }
func (*byteDecoder) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	panic("TCP packet dispatch")
}
func (*byteDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }
func (d *byteDecoder) StreamEnded(string, dpi.StreamDir)        { d.ended++ }
func (d *byteDecoder) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	d.sessions = append(d.sessions, v.Session)
	res := dpi.StreamResult{Consumed: len(v.Bytes)}
	for i, b := range v.Bytes {
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: v.Base + int64(i), End: v.Base + int64(i+1), Events: []dpi.Event{{Proto: "modbus", Kind: "byte", Attributes: map[string]any{"byte": b}}}})
	}
	return res, nil
}

func states(port uint16, transport uint8) [2]*flow.State {
	return [2]*flow.State{{Key: flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 50000, DstPort: port, Proto: transport, Dir: flow.DirForward}},
		{Key: flow.Key{SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.1"), SrcPort: port, DstPort: 50000, Proto: transport, Dir: flow.DirReverse}}}
}

func newObserver(t *testing.T, change func(*Options)) (*Observer, *byteDecoder) {
	t.Helper()
	d := &byteDecoder{}
	m, err := dpi.NewObservationManager(d)
	if err != nil {
		t.Fatal(err)
	}
	b := identify.DefaultBudgets()
	b.Protocols = []identify.Protocol{identify.Modbus}
	opts := Options{Budgets: b, Markers: 32, Manager: m, Now: func() time.Time { return instant }}
	if change != nil {
		change(&opts)
	}
	o, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return o, d
}
func openTCP(t *testing.T, o *Observer, key identify.Key) [2]*flow.State {
	t.Helper()
	s := states(1502, 6)
	if !o.Open(key, identify.Meta{Transport: 6, Ports: [2]uint16{50000, 1502}}) {
		t.Fatal("open")
	}
	o.Observe(key, Packet{Arrival: identify.Arrival{SYN: true, Sequence: 99}, State: s[0], At: instant})
	o.Observe(key, Packet{Arrival: identify.Arrival{Direction: 1, SYN: true, Sequence: 199}, SYNACK: true, State: s[1], At: instant})
	return s
}
func payload(o *Observer, key identify.Key, s [2]*flow.State, dir uint8, seq uint32, b []byte) Output {
	return o.Observe(key, Packet{Arrival: identify.Arrival{Direction: dir, Sequence: seq, Payload: b}, State: s[dir], At: instant.Add(time.Duration(dir) * time.Second)})
}
func decoded(t *testing.T, out Output) [2][]byte {
	t.Helper()
	var b [2][]byte
	for _, batch := range out.Batches {
		if batch.Err != nil {
			t.Fatal(batch.Err)
		}
		for _, ev := range batch.Events {
			if ev.Attributes[eventfields.KeyObservationOnly] != true || ev.Attributes[eventfields.KeyBindingSource] != "observation" || ev.Timestamp != batch.At {
				t.Fatal(ev)
			}
			b[batch.Dir] = append(b[batch.Dir], ev.Attributes["byte"].(byte))
		}
	}
	return b
}

func TestReplayAndContinuation(t *testing.T) {
	for _, mode := range []string{"plain", "syn data", "out of order", "overlap", "pending beyond prefix", "wrap"} {
		t.Run(mode, func(t *testing.T) {
			o, _ := newObserver(t, nil)
			s := states(1502, 6)
			var out Output
			base := uint32(100)
			if mode == "wrap" {
				base = ^uint32(0) - 3
			}
			o.Open("k", identify.Meta{Transport: 6, Ports: [2]uint16{50000, 1502}})
			syn := Packet{Arrival: identify.Arrival{SYN: true, Sequence: base - 1}, State: s[0], At: instant}
			if mode == "syn data" {
				syn.Payload = request
			}
			out.append(o.Observe("k", syn))
			out.append(o.Observe("k", Packet{Arrival: identify.Arrival{Direction: 1, SYN: true, Sequence: 199}, SYNACK: true, State: s[1], At: instant}))
			switch mode {
			case "syn data":
			case "out of order":
				out.append(payload(o, "k", s, 0, base+6, request[6:]))
				out.append(payload(o, "k", s, 0, base, request[:6]))
			case "overlap":
				out.append(payload(o, "k", s, 0, base, request[:9]))
				out.append(payload(o, "k", s, 0, base+6, request[6:]))
			case "pending beyond prefix":
				out.append(payload(o, "k", s, 0, base+uint32(len(request))+3, []byte("def")))
				out.append(payload(o, "k", s, 0, base, request))
			default:
				out.append(payload(o, "k", s, 0, base, request))
			}
			out.append(payload(o, "k", s, 1, 200, reply))
			if len(out.Identifications) != 1 || out.Identifications[0].Binding != Observation {
				t.Fatal(out)
			}
			if mode == "pending beyond prefix" {
				out.append(payload(o, "k", s, 0, base+uint32(len(request)), []byte("abc")))
			} else {
				out.append(payload(o, "k", s, 0, base+uint32(len(request)), []byte("abcdef")))
			}
			got := decoded(t, out)
			if !bytes.Equal(got[0], append(append([]byte{}, request...), []byte("abcdef")...)) || !bytes.Equal(got[1], reply) {
				t.Fatalf("%q %q", got[0], got[1])
			}
			if s := o.Counters(); s.Bindings != 1 || s.Entries != 0 || s.Markers != 1 {
				t.Fatal(s)
			}
		})
	}
}

func TestNoBindingOnCoverageLoss(t *testing.T) {
	for _, mode := range []string{"no SYN", "oversized", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			o, _ := newObserver(t, nil)
			s := states(1502, 6)
			o.Open("k", identify.Meta{Transport: 6})
			if mode != "no SYN" {
				o.Observe("k", Packet{Arrival: identify.Arrival{SYN: true, Sequence: 99}, State: s[0]})
			}
			b := request
			if mode == "oversized" {
				b = make([]byte, 2048)
			}
			p := Packet{Arrival: identify.Arrival{Sequence: 100, Payload: b, Truncated: mode == "truncated"}, State: s[0]}
			out := o.Observe("k", p)
			if len(out.Identifications) != 1 || out.Identifications[0].Binding != None || len(out.Batches) != 0 {
				t.Fatal(out)
			}
		})
	}
}

func TestLegacyPredicateAndMarkerCapacity(t *testing.T) {
	calls := 0
	o, _ := newObserver(t, func(opts *Options) {
		opts.Markers = 1
		opts.LegacyDecodes = func(key identify.Key, p identify.Protocol) bool { calls++; return key == "k" && p == identify.Modbus }
	})
	s := openTCP(t, o, "k")
	payload(o, "k", s, 0, 100, request)
	out := payload(o, "k", s, 1, 200, reply)
	if len(out.Identifications) != 1 || out.Identifications[0].Binding != Legacy || len(out.Batches) != 0 || calls != 1 {
		t.Fatal(out, calls)
	}
	before := o.Counters().Evidence
	for range 3 {
		if o.Open("refused", identify.Meta{Transport: 6}) {
			t.Fatal("capacity")
		}
		payload(o, "refused", s, 0, 100, request)
		payload(o, "k", s, 1, 200, reply)
	}
	if after := o.Counters(); after.Refusals != 3 || after.Evidence != before {
		t.Fatal(after)
	}
}

func TestFINPayloadAndReset(t *testing.T) {
	for _, rst := range []bool{false, true} {
		o, d := newObserver(t, nil)
		s := openTCP(t, o, "k")
		payload(o, "k", s, 0, 100, request)
		out := o.Observe("k", Packet{Arrival: identify.Arrival{Direction: 1, Sequence: 200, Payload: reply}, State: s[1], FIN: !rst, RST: rst, At: instant})
		b := decoded(t, out)
		if !bytes.Equal(b[0], request) || !bytes.Equal(b[1], reply) {
			t.Fatal(b)
		}
		if !rst {
			if o.Counters().Bindings != 1 {
				t.Fatal("first FIN closed peer")
			}
			o.Observe("k", Packet{Arrival: identify.Arrival{Sequence: 112}, State: s[0], FIN: true})
		}
		if o.Counters().Bindings != 0 || d.ended != 2 {
			t.Fatal(o.Counters(), d.ended)
		}
		if got := payload(o, "k", s, 0, 112, request); len(got.Identifications) != 0 || len(got.Batches) != 0 {
			t.Fatal("trailing arrival reopened", got)
		}
	}
}

func TestDrainConcurrent(t *testing.T) {
	o, _ := newObserver(t, nil)
	s := openTCP(t, o, "k")
	var wg sync.WaitGroup
	for worker := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				switch worker {
				case 0:
					payload(o, "k", s, 0, 100, request)
				case 1:
					o.Sweep(instant)
				case 2:
					o.Drain()
				}
			}
		}()
	}
	wg.Wait()
	if got := o.Counters(); got.Markers != 0 || got.Bindings != 0 || got.Entries != 0 || got.ChargedBytes != 0 {
		t.Fatal(got)
	}
	if o.Open("new", identify.Meta{Transport: 6}) {
		t.Fatal("drained instance reopened")
	}
}

func TestAdoptionBindingsAndMarkers(t *testing.T) {
	for _, mode := range []string{"bound absent", "bound pending", "terminal pending", "pending merge", "pending conflict"} {
		t.Run(mode, func(t *testing.T) {
			o, d := newObserver(t, nil)
			s := openTCP(t, o, "from")
			payload(o, "from", s, 0, 100, request)
			if mode == "bound absent" || mode == "bound pending" {
				payload(o, "from", s, 1, 200, reply)
			}
			if mode == "terminal pending" {
				o.Finish("from")
			}
			if mode != "bound absent" {
				openTCP(t, o, "to")
			}
			if mode == "pending merge" {
				payload(o, "to", s, 1, 200, reply)
			}
			if mode == "pending conflict" {
				payload(o, "to", s, 0, 100, []byte{1})
			}
			before := ""
			if len(d.sessions) > 0 {
				before = d.sessions[0]
			}
			out := o.Adopt("from", "to", identify.Remap{0, 1})
			if mode == "pending conflict" {
				if len(out.Identifications) != 2 || o.Counters().AdoptionConflicts != 1 {
					t.Fatal(out, o.Counters())
				}
			} else if mode == "pending merge" {
				if len(out.Identifications) != 1 || out.Identifications[0].Binding != Observation {
					t.Fatal(out)
				}
				b := decoded(t, out)
				if !bytes.Equal(b[0], request) || !bytes.Equal(b[1], reply) {
					t.Fatal(b)
				}
			}
			if mode == "bound absent" || mode == "bound pending" {
				out = payload(o, "to", s, 0, 112, []byte("x"))
				if !bytes.Equal(decoded(t, out)[0], []byte("x")) {
					t.Fatal(out)
				}
				if d.sessions[len(d.sessions)-1] != before {
					t.Fatal("session recomputed")
				}
			}
			if o.Counters().Markers != 1 {
				t.Fatal(o.Counters())
			}
		})
	}
}

func TestValidation(t *testing.T) {
	o, _ := newObserver(t, nil)
	if o.Open("", identify.Meta{Transport: 6}) {
		t.Fatal("empty key")
	}
	if out := o.Adopt("absent", "to", identify.Remap{0, 0}); len(out.Batches) > 0 {
		t.Fatal(out)
	}
	if got := o.Counters().Markers; got != 0 {
		t.Fatal(got)
	}
}

func TestBoundAdoptionReversalPreservesRoles(t *testing.T) {
	o, d := newObserver(t, nil)
	s := openTCP(t, o, "from")
	payload(o, "from", s, 0, 100, request)
	payload(o, "from", s, 1, 200, reply)
	before, _ := o.Lookup("from")
	o.Adopt("from", "to", identify.Remap{1, 0})
	after, _ := o.Lookup("to")
	if before.Session != after.Session {
		t.Fatal(before, after)
	}
	reversed := [2]*flow.State{s[1], s[0]}
	out := payload(o, "to", reversed, 1, 112, []byte("x"))
	if got := decoded(t, out); !bytes.Equal(got[1], []byte("x")) {
		t.Fatal(got)
	}
	if d.sessions[len(d.sessions)-1] != before.Session {
		t.Fatal(d.sessions)
	}
}

func TestPendingAdoptionRoleConflict(t *testing.T) {
	o, _ := newObserver(t, nil)
	s := openTCP(t, o, "from")
	o.Open("to", identify.Meta{Transport: 6})
	o.Observe("to", Packet{Arrival: identify.Arrival{Direction: 1, SYN: true, Sequence: 199}, State: s[1]})
	out := o.Adopt("from", "to", identify.Remap{0, 1})
	if len(out.Identifications) != 2 || o.Counters().AdoptionConflicts != 1 {
		t.Fatal(out)
	}
}

func TestTerminalAdoptionKeepsEarlier(t *testing.T) {
	for _, sourceFirst := range []bool{false, true} {
		o, _ := newObserver(t, nil)
		s := openTCP(t, o, "from")
		openTCP(t, o, "to")
		if sourceFirst {
			o.Finish("from")
		} else {
			o.Finish("to")
		}
		other := identify.Key("to")
		if !sourceFirst {
			other = "from"
		}
		payload(o, other, s, 0, 100, request)
		payload(o, other, s, 1, 200, reply)
		out := o.Adopt("from", "to", identify.Remap{0, 1})
		status, _ := o.Lookup("to")
		if len(out.Identifications) != 0 || status.Binding != None || status.Coverage != identify.Closed || o.Counters().Bindings != 0 {
			t.Fatal(out, status)
		}
	}
}

func TestTruncatedContinuationEndsPassiveBinding(t *testing.T) {
	o, _ := newObserver(t, nil)
	s := openTCP(t, o, "k")
	payload(o, "k", s, 0, 100, request)
	payload(o, "k", s, 1, 200, reply)
	out := o.Observe("k", Packet{Arrival: identify.Arrival{Sequence: 112, Payload: request, Truncated: true}, State: s[0], At: instant})
	status, _ := o.Lookup("k")
	if len(out.Identifications) != 0 || len(out.Batches) != 1 || out.Batches[0].Err == nil || len(out.Batches[0].Events) != 0 || status.Binding != None || !status.Observed || status.Coverage != identify.Truncated {
		t.Fatal(out, status)
	}
}
