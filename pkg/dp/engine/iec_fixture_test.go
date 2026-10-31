// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// stubIEC is a minimal framed decoder: APDUs are
// 0x68, L, then L octets; an I-frame carries Type ID and a 2-octet CA at
// octets 6 and 10..11. It stands in for the production IEC104 decoder.
type stubIEC struct{}

func (stubIEC) Supports(s *flow.State) bool {
	return s != nil && s.Key.Proto == 6 && (s.Key.SrcPort == iec104Port || s.Key.DstPort == iec104Port)
}
func (stubIEC) Ports() ([]uint16, []uint16) { return []uint16{iec104Port}, nil }
func (stubIEC) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (stubIEC) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }
func (stubIEC) Protocol() string                           { return "iec104" }

func (stubIEC) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	dir, letter := "request", eventfields.DirClient
	if v.Dir == dpi.ServerToClient {
		dir, letter = "response", eventfields.DirServer
	}
	pos := 0
	for pos < len(v.Bytes) {
		start := v.Base + int64(pos)
		b := v.Bytes[pos:]
		id := eventfields.APDUID(v.Session, letter, start)
		if b[0] != 0x68 {
			res.Consumed = pos
			return res, &dpi.FrameError{Offset: start, Reason: "start octet", Event: dpi.Event{Proto: "iec104", Kind: "malformed",
				Attributes: map[string]any{"error": "bad start", "apdu_id": id, "session_id": v.Session, "direction": dir}}}
		}
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			res.NeedMore = true
			break
		}
		n := 2 + int(b[1])
		attrs := map[string]any{"apdu_id": id, "session_id": v.Session, "direction": dir}
		kind := dir
		switch {
		case n == 6 && b[2]&0x03 == 0x03:
			attrs["apci_type"], attrs["class"] = "U", "system"
			kind = "apci"
			if b[2] == 0x0B {
				attrs["u_function"] = "startdt_con"
			}
		default:
			attrs["apci_type"] = "I"
			attrs["type_id"] = b[6]
			attrs["ca"] = uint16(b[10]) | uint16(b[11])<<8
			attrs["class"] = "monitor"
			if b[6] >= 45 && b[6] <= 64 {
				attrs["class"] = "control"
			}
		}
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: start, End: start + int64(n), Events: []dpi.Event{{Proto: "iec104", Kind: kind, Attributes: attrs}}})
		pos += n
	}
	res.Consumed = pos
	return res, nil
}

// iframe builds an I-frame APDU of one object with typeID and CA.
func iframe(typeID byte, ca uint16) []byte {
	return []byte{0x68, 0x0e, 0, 0, 0, 0, typeID, 1, 6, 0, byte(ca), byte(ca >> 8), 1, 0, 0, 0}
}

var startdtCon = []byte{0x68, 0x04, 0x0B, 0, 0, 0}

// fakePolicy matches every session as an envelope of mode, allows
// monitor data, and allows control only for allowType.
type fakePolicy struct {
	matched   bool
	mode      string
	allowType uint8
	denyRule  *rules.Entry // matched for denied control requests, if set
}

func (p *fakePolicy) IEC104Envelope(rules.EvalContext, string) (bool, string) {
	return p.matched, p.mode
}

func (p *fakePolicy) EvaluateIEC104(ctx rules.EvalContext) (rules.Action, *rules.Entry) {
	c := ctx.ICS.IEC104
	if c.APCIType != "I" || c.Class == "monitor" || (c.TypeID != nil && *c.TypeID == p.allowType) {
		return rules.ActionAllow, &rules.Entry{ID: "allow", Action: rules.ActionAllow}
	}
	if p.denyRule != nil && !rules.MonitorICS(*p.denyRule, p.mode) {
		return rules.ActionDeny, p.denyRule
	}
	return rules.ActionDeny, nil
}

// fakeSettler records Settle calls.
type fakeSettler struct {
	mu    sync.Mutex
	calls [][]capture.Resolution
}

func (f *fakeSettler) Settle(res ...capture.Resolution) []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]capture.Resolution(nil), res...))
	return make([]error, len(res))
}

type iecHarness struct {
	t       *testing.T
	e       *Engine
	policy  *fakePolicy
	inj     *session.Fake
	settler *fakeSettler
	clock   time.Time
	nextTok uint32
	deletes chan conntrack.DeleteRequest

	clientISN, serverISN uint32
	cSeq, sSeq           uint32 // next sequence number per direction
	client, server       net.IP
	cport                uint16
}

const (
	testClientISN = 0xfffffff0 // the client stream wraps 2^32 early
	testServerISN = 5000
)

func newIECHarness(t *testing.T, mode string) *iecHarness {
	t.Helper()
	h := &iecHarness{t: t, policy: &fakePolicy{matched: true, mode: mode, allowType: 46}, inj: &session.Fake{}, settler: &fakeSettler{},
		clock: time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC), deletes: make(chan conntrack.DeleteRequest, 8),
		client: net.ParseIP("10.60.60.10"), server: net.ParseIP("10.30.30.30"), cport: 40000}
	e, err := New(Config{DPIEnabled: true, DPIMode: "monitor", ResetInjector: h.inj})
	if err != nil {
		t.Fatal(err)
	}
	e.dpiMgr = dpi.NewManager(stubIEC{})
	e.iec.dpi = e.dpiMgr
	e.iec.newPolicy = func(*rules.Snapshot) iecPolicy { return h.policy }
	e.iec.settler = func() capture.Settler { return h.settler }
	e.iec.now = func() time.Time { return h.clock }
	e.iec.ctDelete = func(_ context.Context, req conntrack.DeleteRequest) error {
		h.deletes <- req
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.hooks.blocks.run(ctx)
	e.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{ID: "iec", ICS: rules.ICSPredicate{Protocol: "iec104", Mode: mode}, Action: rules.ActionAllow}}})
	h.e = e
	return h
}

func (h *iecHarness) token() capture.Token {
	h.nextTok++
	return capture.NewToken(1, h.nextTok)
}

func (h *iecHarness) pkt(fromClient bool, flags capture.TCPFlags, seq, ack uint32, payload []byte) capture.Packet {
	p := capture.Packet{Timestamp: h.clock, Proto: 6, Transport: "tcp", Token: h.token(), Payload: payload,
		TCP: capture.TCPMeta{Valid: true, Seq: seq, Ack: ack, Flags: flags}}
	if fromClient {
		p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = h.client, h.server, h.cport, iec104Port
	} else {
		p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = h.server, h.client, iec104Port, h.cport
	}
	p.Queue = policyQueue(h.client, h.server, h.cport, iec104Port, !fromClient)
	markHandshake(&p)
	return p
}

// handshake runs SYN, SYN-ACK and ACK with the test ISNs.
func (h *iecHarness) handshake() {
	h.t.Helper()
	h.clientISN, h.serverISN = testClientISN, testServerISN
	h.cSeq, h.sSeq = h.clientISN+1, h.serverISN+1
	for _, p := range []capture.Packet{
		h.pkt(true, capture.TCPFlagSYN, h.clientISN, 0, nil),
		h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, h.serverISN, h.cSeq, nil),
		h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, nil),
	} {
		if d := h.e.handlePacket(p); d.Action != h.passingDisposition() {
			h.t.Fatalf("handshake packet %+v: %+v", p.TCP, d)
		}
	}
}

// send sends payload in one packet from a side, advancing its sequence.
func (h *iecHarness) send(fromClient bool, payload []byte) (capture.Packet, capture.Decision) {
	h.t.Helper()
	var p capture.Packet
	if fromClient {
		p = h.pkt(true, capture.TCPFlagACK|capture.TCPFlagPSH, h.cSeq, h.sSeq, payload)
		h.cSeq += uint32(len(payload))
	} else {
		p = h.pkt(false, capture.TCPFlagACK|capture.TCPFlagPSH, h.sSeq, h.cSeq, payload)
		h.sSeq += uint32(len(payload))
	}
	return p, h.e.handlePacket(p)
}

func (h *iecHarness) eventsOf(kind string) []events.Event {
	var out []events.Event
	list := h.e.Events().List(0)
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Kind == kind {
			out = append(out, list[i])
		}
	}
	return out
}

func (h *iecHarness) outcomes() []string {
	var out []string
	for _, ev := range h.eventsOf("ics.session") {
		out = append(out, ev.Attributes["outcome"].(string))
	}
	return out
}

func (h *iecHarness) waitResets(n int) []session.Reset {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := h.inj.Resets(); len(got) >= n {
			// SendRST is recorded before reset_sent and conntrack deletion.
			// Wait for the worker's barrier, not just the injector call.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if !h.e.hooks.blocks.flush(ctx.Done()) {
				h.t.Fatal("reset worker did not reach its barrier")
			}
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("resets = %+v, want %d", h.inj.Resets(), n)
	return nil
}

type rulesSnapshot = rules.Snapshot

var (
	testClientIP        = net.ParseIP("10.60.60.10")
	testServerIP        = net.ParseIP("10.30.30.30")
	rulesEntryLearnDeny = rules.Entry{ID: "deny-learn", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}}
)

func iecSnapshot(mode string) rules.Snapshot {
	return rules.Snapshot{Firewall: []rules.Entry{{ID: "iec", ICS: rules.ICSPredicate{Protocol: "iec104", Mode: mode}, Action: rules.ActionAllow}}}
}

func dpiManagerWithout() *dpi.Manager { return dpi.NewManager() }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (h *iecHarness) passingDisposition() capture.Disposition {
	return capture.Repeat
}

func (h *iecHarness) deniedDisposition() capture.Disposition {
	if h.policy.mode == "monitor" {
		return capture.Repeat
	}
	return capture.Drop
}

func (p *fakePolicy) IEC104Scope(rules.EvalContext, string) *rules.Entry {
	return &rules.Entry{ID: "iec", ICS: rules.ICSPredicate{Protocol: "iec104", Mode: p.mode}}
}
func (p *fakePolicy) MonitorMatches(ctx rules.EvalContext) []*rules.Entry {
	if p.denyRule != nil && rules.MonitorICS(*p.denyRule, p.mode) && ctx.ICS.IEC104.Class == "control" {
		return []*rules.Entry{p.denyRule}
	}
	return nil
}
