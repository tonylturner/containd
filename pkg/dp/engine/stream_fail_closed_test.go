// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The tests in this file drive inline packets through the real Modbus and
// DNP3 decoders under the first-command policy. A stream that cannot be
// inspected must drop the packet and deny the flow when an enforce rule's
// scope holds it, and keep passing when only monitor rules do.

// learnPolicy is the first-command policy with every rule in monitor mode.
func learnPolicy() rules.Snapshot {
	snap := firstCommandPolicy()
	for i := range snap.Firewall {
		snap.Firewall[i].ICS.Mode = "monitor"
	}
	return snap
}

// newModeFlow is a first-command flow under the enforce or monitor policy.
func newModeFlow(t *testing.T, mode string, port uint16) *fcFlow {
	f := newFCFlow(t, "ok", port)
	if mode == "monitor" {
		f.e.LoadRules(learnPolicy())
		f.observeOnly = true
	}
	return f
}

// rewrittenRead is a frame as long as the protocol's first read whose
// function code is prohibited.
func rewrittenRead(p firstCommandProtocol) []byte {
	if p.port == 502 {
		return modbusADU(1, 6, 1, 0x1234)
	}
	return dnp3Request(5, 1, []byte{0x3C, 0x01, 0x06})
}

// malformedRead is the n-th read with bytes no decoder can frame: a Modbus
// MBAP length of 0xFFFF, a DNP3 frame without its start octets.
func malformedRead(p firstCommandProtocol, n uint16) []byte {
	b := p.read(n)
	if p.port == 502 {
		b[4], b[5] = 0xFF, 0xFF
	} else {
		b[0] = 0
	}
	return b
}

// failClosedEvents returns the fail-closed ics.decision events.
func failClosedEvents(e *Engine) []events.Event {
	var out []events.Event
	for _, ev := range e.Events().List(0) {
		reason, _ := eventfields.String(ev.Attributes, eventfields.KeyReason)
		if ev.Kind == eventfields.KindDecision && (reason == failClosedStream || reason == failClosedResync ||
			reason == failClosedMidStream || reason == failClosedPanic) {
			out = append(out, ev)
		}
	}
	return out
}

// failedClosed requires the fail-closed drop, reset evidence, no block and
// the original decision event for the rule and reason.
func (f *fcFlow) failedClosed(what string, d capture.Decision, rule, reason string, before int) {
	f.t.Helper()
	if d.Action != capture.Drop || (before == 0 && d.Reason != reasonStreamFailClosed) {
		f.t.Fatalf("%s: decision = %+v, want Drop by %s", what, d, reasonStreamFailClosed)
	}
	assertResetEvidence(f.t, f.e)
	select {
	case got := <-f.up.calls:
		f.t.Fatalf("%s: DPI installed block %q", what, got)
	default:
	}
	evs := failClosedEvents(f.e)
	if len(evs) != 1 {
		f.t.Fatalf("%s: fail-closed events %d -> %d, want the one original decision", what, before, len(evs))
	}
	ev := evs[0] // newest first
	if ev.Attributes[eventfields.KeyRuleID] != rule || ev.Attributes[eventfields.KeyReason] != reason ||
		ev.Attributes[eventfields.KeyDecision] != decisionDeny || ev.Attributes[eventfields.KeyMode] != "enforce" {
		f.t.Fatalf("%s: event attributes %v, want deny by %s for %s", what, ev.Attributes, rule, reason)
	}
	if msg, _ := eventfields.String(ev.Attributes, eventfields.KeyError); msg == "" {
		f.t.Fatalf("%s: event %v carries no error", what, ev.Attributes)
	}
}

// noBlock requires that no dynamic block was attempted.
func (f *fcFlow) noBlock(what string) {
	f.t.Helper()
	select {
	case got := <-f.up.calls:
		f.t.Fatalf("%s: dynamic block %q", what, got)
	default:
	}
	if evs := failClosedEvents(f.e); len(evs) != 0 {
		f.t.Fatalf("%s: fail-closed events %v", what, evs)
	}
}

// streamErrorCase sends a stream error on a flow after one read and
// returns its decision; f.next is the offset of the following new byte.
type streamErrorCase struct {
	name string
	send func(f *fcFlow, p firstCommandProtocol) capture.Decision
}

func streamErrorCases() []streamErrorCase {
	return []streamErrorCase{
		{"rewritten retransmission of consumed bytes", func(f *fcFlow, p firstCommandProtocol) capture.Decision {
			return f.decide(0, ackPsh, rewrittenRead(p))
		}},
		{"conflicting overlap of held bytes", func(f *fcFlow, p firstCommandProtocol) capture.Decision {
			head := p.read(2)[:8]
			f.accept("read 2 head", head)
			conflict := append([]byte(nil), head...)
			conflict[7] ^= 0xFF
			return f.decide(f.next-8, ackPsh, conflict)
		}},
		{"malformed framing", func(f *fcFlow, p firstCommandProtocol) capture.Decision {
			bad := malformedRead(p, 2)
			at := f.next
			f.next += uint32(len(bad))
			return f.decide(at, ackPsh, bad)
		}},
	}
}

// TestFailClosedOnStreamErrors drops the stream error of an enforce flow
// and denies the flow without resynchronizing its stream; under learn
// rules the same packets pass and later reads are still decoded.
func TestFailClosedOnStreamErrors(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		for _, tc := range streamErrorCases() {
			t.Run(p.name+"/"+tc.name+"/enforce", func(t *testing.T) {
				f := newModeFlow(t, "enforce", p.port)
				f.syn()
				f.accept("read 1", p.read(1))
				f.failedClosed("stream error", tc.send(f, p), p.name+"-read", failClosedStream, 0)
				f.dropCachedAt(f.next, "read after the stream error", p.read(3))
				// Past the cached denial the stream stays failed: an
				// allowed read is not framed from a new start.
				f.e.verdictCache = NewVerdictCache(time.Minute, 16)
				f.failedClosed("read on the failed stream", f.decide(f.next, ackPsh, p.read(3)), p.name+"-read", failClosedStream, 1)
			})
			t.Run(p.name+"/"+tc.name+"/learn", func(t *testing.T) {
				f := newModeFlow(t, "monitor", p.port)
				f.syn()
				f.accept("read 1", p.read(1))
				if d := tc.send(f, p); d.Action != capture.Repeat {
					t.Fatalf("stream error under learn rules = %+v, want Accept", d)
				}
				hits := shadowHits(f.e, p.name+"-read")
				// The aligned read starts the restarted stream.
				f.accept("read after the stream error", p.read(3))
				if got := shadowHits(f.e, p.name+"-read"); got != hits+1 {
					t.Fatalf("read rule hits %d -> %d, want the read decoded", hits, got)
				}
				f.noBlock("monitor")
			})
		}
	}
}

// TestFailClosedIdenticalRetransmissionsPass resends consumed and held
// bytes unchanged on an enforce flow; nothing fails and the flow still
// enforces.
func TestFailClosedIdenticalRetransmissionsPass(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			f.syn()
			r1, r2 := p.read(1), p.read(2)
			f.accept("read 1", r1)
			f.acceptAt(0, "retransmitted read 1", r1)
			f.accept("read 2 head", r2[:5])
			f.acceptAt(f.next-5, "retransmitted read 2 head", r2[:5])
			f.acceptAt(f.next-5, "read 2 head retransmitted with its tail", r2)
			f.next += uint32(len(r2) - 5)
			f.acceptAt(0, "both reads retransmitted", concatFrames(r1, r2))
			f.noBlock("identical retransmissions")
			c := p.denied[0]
			f.deny("denied", c.rule, c.frame)
		})
	}
}

// TestFailClosedOnlyInline keeps today's pass for packets that carry no
// inline verdict (AF_PACKET), even under enforce rules.
func TestFailClosedOnlyInline(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		t.Run(p.name, func(t *testing.T) {
			f := newModeFlow(t, "enforce", p.port)
			send := func(off uint32, flags capture.TCPFlags, payload []byte) capture.Decision {
				return f.e.HandlePacket(connSegment(false, f.client, f.port, f.isn+off, flags, payload))
			}
			if d := send(0, capture.TCPFlagSYN, nil); d.Action != capture.Accept {
				t.Fatalf("SYN = %+v", d)
			}
			r1 := p.read(1)
			if d := send(0, ackPsh, r1); d.Action != capture.Accept {
				t.Fatalf("read = %+v", d)
			}
			if d := send(uint32(len(r1)), ackPsh, malformedRead(p, 2)); d.Action != capture.Accept {
				t.Fatalf("malformed read without an inline verdict = %+v, want Accept", d)
			}
			f.noBlock("not inline")
		})
	}
}

// TestFailClosedOnDecoderPanic drops the packet whose decoder panics on an
// enforce flow and still reports the panic; under learn rules the panic
// takes HandlePacket's recovery and the packet passes.
func TestFailClosedOnDecoderPanic(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			f := newModeFlow(t, mode, 502)
			var mu sync.Mutex
			var logged []string
			f.e.onError = func(err error) {
				mu.Lock()
				defer mu.Unlock()
				logged = append(logged, err.Error())
			}
			f.e.dpiMgr = dpi.NewManager(panicDecoder{})
			d := f.decide(0, ackPsh, modbusADU(1, 3, 0, 2))
			if mode == "enforce" {
				f.failedClosed("decoder panic", d, "modbus-read", failClosedPanic, 0)
				if ev := failClosedEvents(f.e)[0]; ev.Proto != "modbus" {
					t.Fatalf("event proto = %q, want modbus", ev.Proto)
				}
			} else {
				if d.Action != capture.Repeat {
					t.Fatalf("decoder panic under monitor rules = %+v, want Accept", d)
				}
				f.noBlock("monitor")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(logged) != 1 || !strings.Contains(logged[0], "decoder bug") {
				t.Fatalf("logged = %v, want the panic reported once", logged)
			}
			h := f.e.iec.health
			h.mu.Lock()
			_, faulted := h.faults[faultWorker]
			h.mu.Unlock()
			if !faulted {
				t.Fatal("the panic is not recorded as a worker fault")
			}
		})
	}
}

// BenchmarkFailClosedRule is the per-packet scope lookup of an inline
// packet: the last rule of the policy holds the flow.
func BenchmarkFailClosedRule(b *testing.B) {
	e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		b.Fatal(err)
	}
	e.LoadRules(firstCommandPolicy())
	pkt := connSegment(false, 41000, dnp3Port, 1, ackPsh, dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}))
	pkt.Token = capture.NewToken(1, 1)
	state := e.trackFlow(pkt, time.Now())
	parsed := dpi.ParsedPacket{Proto: "tcp", SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	b.ReportAllocs()
	for b.Loop() {
		if e.failClosedRule(pkt, state, &parsed) == nil {
			b.Fatal("flow out of scope")
		}
	}
}

// BenchmarkFailClosedRuleZoned is BenchmarkFailClosedRule with zoned rules,
// whose scope needs the zones of the flow's addresses, while the zone
// cache is subscribed to interface changes, as in a running engine.
func BenchmarkFailClosedRuleZoned(b *testing.B) {
	e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		b.Fatal(err)
	}
	e.zones.subscribed()
	snap := firstCommandPolicy()
	snap.ZoneIfaces = map[string][]string{"control": {loopbackName(b)}}
	for i := range snap.Firewall {
		snap.Firewall[i].SourceZones = []string{""}
	}
	e.LoadRules(snap)
	pkt := connSegment(false, 41000, dnp3Port, 1, ackPsh, dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}))
	pkt.Token = capture.NewToken(1, 1)
	state := e.trackFlow(pkt, time.Now())
	parsed := dpi.ParsedPacket{Proto: "tcp", SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	b.ReportAllocs()
	for b.Loop() {
		if e.failClosedRule(pkt, state, &parsed) == nil {
			b.Fatal("flow out of scope")
		}
	}
}

// loopbackName is the name of the host's loopback interface.
func loopbackName(tb testing.TB) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		tb.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	tb.Skip("no loopback interface")
	return ""
}
