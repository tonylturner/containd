// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// recordFramer frames 4-byte records on TCP port 9999 and emits one event
// per record, carrying the record bytes.
type recordFramer struct{}

func (recordFramer) Supports(s *flow.State) bool {
	return s != nil && s.Key.Proto == 6 && (s.Key.SrcPort == 9999 || s.Key.DstPort == 9999)
}
func (recordFramer) Ports() ([]uint16, []uint16) { return []uint16{9999}, nil }
func (recordFramer) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (recordFramer) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }
func (recordFramer) Protocol() string                           { return "rec" }
func (recordFramer) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	for off := 0; off+4 <= len(v.Bytes); off += 4 {
		start := v.Base + int64(off)
		if string(v.Bytes[off:off+4]) == "BAD!" {
			return res, &dpi.FrameError{Offset: start, Reason: "bad record", Event: dpi.Event{
				Proto: "rec", Kind: "malformed", Attributes: map[string]any{"error": "bad record"},
			}}
		}
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: start, End: start + 4, Events: []dpi.Event{{
			Proto: "rec", Kind: "record", Attributes: map[string]any{"rec": string(v.Bytes[off : off+4])},
		}}})
		res.Consumed = off + 4
	}
	res.NeedMore = len(v.Bytes)%4 != 0
	return res, nil
}

func recordEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{DPIEnabled: true, InspectAll: true})
	if err != nil {
		t.Fatal(err)
	}
	e.dpiMgr = dpi.NewManager(recordFramer{})
	return e
}

func recordPacket(seq uint32, flags capture.TCPFlags, payload string) capture.Packet {
	return capture.Packet{
		Timestamp: time.Now().UTC(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   40000,
		DstPort:   9999,
		Proto:     6,
		Transport: "tcp",
		TCP:       capture.TCPMeta{Valid: true, Seq: seq, Flags: flags | capture.TCPFlagACK},
		Payload:   []byte(payload),
	}
}

func records(e *Engine) []string {
	var out []string
	list := e.Events().List(100)
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Kind == "record" {
			out = append(out, list[i].Attributes["rec"].(string))
		}
	}
	return out
}

// TestFlowPathPassesTCPSequence pins contracts K8: with the sequence number
// filled in, a second message on a persistent connection is parsed and a
// retransmission is not parsed again.
func TestFlowPathPassesTCPSequence(t *testing.T) {
	e := recordEngine(t)
	for _, p := range []capture.Packet{
		recordPacket(0, capture.TCPFlagPSH, "AAAA"), // Seq 0 is a real value
		recordPacket(4, capture.TCPFlagPSH, "BBBB"),
		recordPacket(0, capture.TCPFlagPSH, "AAAA"), // retransmission
		recordPacket(8, capture.TCPFlagPSH, "CC"),
		recordPacket(10, capture.TCPFlagPSH, "CC"),
	} {
		if d := e.handlePacket(p); d.Action != capture.Accept {
			t.Fatalf("decision = %+v", d)
		}
	}
	if got := records(e); len(got) != 3 || got[0] != "AAAA" || got[1] != "BBBB" || got[2] != "CCCC" {
		t.Fatalf("records = %v, want [AAAA BBBB CCCC]", got)
	}
}

func TestFlowPathEndsStreamOnFINAndRST(t *testing.T) {
	for _, flag := range []capture.TCPFlags{capture.TCPFlagFIN, capture.TCPFlagRST} {
		e := recordEngine(t)
		e.handlePacket(recordPacket(100, capture.TCPFlagPSH, "XY"))
		e.handlePacket(recordPacket(102, flag, ""))
		// Without cleanup these bytes would complete "XYZW".
		e.handlePacket(recordPacket(102, capture.TCPFlagPSH, "ZW"))
		if got := records(e); len(got) != 0 {
			t.Fatalf("flag %#x: records = %v, want the buffer dropped at close", flag, got)
		}
	}
}

func TestFlowPathRSTEndsOrientedReverseStream(t *testing.T) {
	e := recordEngine(t)
	e.handlePacket(recordPacket(100, capture.TCPFlagPSH, "AB"))
	reverse := recordPacket(500, capture.TCPFlagPSH, "XY")
	reverse.SrcIP, reverse.DstIP = reverse.DstIP, reverse.SrcIP
	reverse.SrcPort, reverse.DstPort = reverse.DstPort, reverse.SrcPort
	e.handlePacket(reverse)
	e.handlePacket(recordPacket(102, capture.TCPFlagRST, ""))
	reverse.TCP.Seq, reverse.Payload = 502, []byte("ZW")
	e.handlePacket(reverse)
	e.handlePacket(recordPacket(102, capture.TCPFlagPSH, "CD"))
	if got := records(e); len(got) != 0 {
		t.Fatalf("records after reset = %v; both directional tails must be discarded", got)
	}
}

func TestFlowPathSYNDataSequenceWrap(t *testing.T) {
	e := recordEngine(t)
	syn := recordPacket(0xFFFFFFFF, capture.TCPFlagSYN, "AAAA")
	syn.TCP.Flags &^= capture.TCPFlagACK
	e.handlePacket(syn)
	e.handlePacket(recordPacket(4, capture.TCPFlagPSH, "BBBB"))
	// The late second-interface SYN capture must not replay its data.
	e.handlePacket(syn)
	if got := records(e); len(got) != 2 || got[0] != "AAAA" || got[1] != "BBBB" {
		t.Fatalf("records = %v, want [AAAA BBBB]", got)
	}
}

func TestInvalidPacketDecision(t *testing.T) {
	e := recordEngine(t)
	frag := recordPacket(0, 0, "AAAA")
	frag.Invalid = capture.InvalidFragment
	if d := e.handlePacket(frag); d.Action != capture.Accept {
		t.Fatalf("unmarked invalid packet = %+v, want Accept (US unchanged)", d)
	}
	frag.HasMark, frag.Mark = true, 0x01000000|0x5
	if d := e.handlePacket(frag); d.Action != capture.Drop {
		t.Fatalf("envelope-marked invalid packet = %+v, want Drop", d)
	}
	frag.Mark = 0x02000000
	if d := e.handlePacket(frag); d.Action != capture.Accept {
		t.Fatalf("other containd mark = %+v, want Accept", d)
	}
	if got := records(e); len(got) != 0 {
		t.Fatalf("invalid packets must not be inspected: %v", got)
	}
}

func TestFlowPathRecordsEventsBeforeError(t *testing.T) {
	e := recordEngine(t)
	if d := e.handlePacket(recordPacket(0, capture.TCPFlagPSH, "GOODBAD!")); d.Action != capture.Accept {
		t.Fatalf("decision = %+v, want Accept (spec §4.2)", d)
	}
	var kinds []string
	for _, ev := range e.Events().List(10) {
		kinds = append(kinds, ev.Kind)
	}
	if got := records(e); len(got) != 1 || got[0] != "GOOD" {
		t.Fatalf("records = %v (kinds %v), want the frame before the error", got, kinds)
	}
	found := false
	for _, k := range kinds {
		found = found || k == "malformed"
	}
	if !found {
		t.Fatalf("malformed event missing: %v", kinds)
	}
}

func TestFlowPathSweepsExpiredStreams(t *testing.T) {
	for _, hard := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "hard"}[hard], func(t *testing.T) {
			e := recordEngine(t)
			p := recordPacket(100, capture.TCPFlagPSH, "AB")
			e.handlePacket(p)
			for _, st := range e.flows {
				if hard {
					st.HardTimeout = time.Second
				} else {
					st.IdleTimeout = time.Second
				}
			}
			e.sweepFlows(p.Timestamp.Add(2 * time.Second))
			if len(e.flows) != 0 {
				t.Fatal("expired flow retained")
			}
			e.handlePacket(recordPacket(102, capture.TCPFlagPSH, "CD"))
			if got := records(e); len(got) != 0 {
				t.Fatalf("expired stream tail survived sweep: %v", got)
			}
		})
	}
}
