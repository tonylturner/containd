// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestIECAllowedAPDUPassesAndSplitAPDUIsHeld(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	if _, d := h.send(true, iframe(46, 1)); d.Action != h.passingDisposition() {
		t.Fatalf("allowed command = %+v", d)
	}
	cmd := iframe(46, 1)
	first, d := h.send(true, cmd[:5])
	if d.Action != capture.Hold {
		t.Fatalf("partial APDU = %+v, want Hold", d)
	}
	_, d = h.send(true, cmd[5:])
	if d.Action != h.passingDisposition() || len(d.Resolved) != 1 || d.Resolved[0] != (capture.Resolution{Token: first.Token, Verdict: capture.VerdictRepeat, Mark: markabi.Continue(first.Mark, false)}) {
		t.Fatalf("completing packet = %+v, want Repeat releasing the held prefix", d)
	}
	// Coalesced: allowed APDU plus an incomplete tail holds the packet.
	_, d = h.send(true, append(iframe(46, 1), iframe(46, 1)[:3]...))
	if d.Action != capture.Hold {
		t.Fatalf("allowed + tail = %+v, want Hold", d)
	}
	// A retransmission of accepted bytes is accepted; of pending bytes held.
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, h.clientISN+1, h.sSeq, iframe(46, 1))); d.Action != h.passingDisposition() {
		t.Fatalf("retransmit of accepted bytes = %+v", d)
	}
	if got := h.eventsOf("ics.decision"); len(got) != 0 {
		t.Fatalf("allow without log emitted decisions: %+v", got)
	}
}

func TestIECDenyDropsWholePacketAndResetsBothSides(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1)) // forwarded: 16 bytes to the server
	h.send(false, iframe(3, 1)) // forwarded: 16 bytes to the client
	held, d := h.send(true, iframe(46, 1)[:4])
	if d.Action != capture.Hold {
		t.Fatalf("partial = %+v", d)
	}
	// The rest of the allowed APDU plus a forbidden one, in one packet.
	payload := append(iframe(46, 1)[4:], iframe(45, 1)...)
	cur, d := h.send(true, payload)
	if d.Action != capture.Drop {
		t.Fatalf("benign+forbidden = %+v, want Drop", d)
	}
	if !reflect.DeepEqual(d.Resolved, []capture.Resolution{{Token: held.Token, Verdict: capture.VerdictDrop}}) {
		t.Fatalf("held tokens = %+v, want the held prefix dropped", d.Resolved)
	}
	dec := h.eventsOf("ics.decision")
	if len(dec) != 1 || dec[0].Attributes["decision"] != "deny" || dec[0].Attributes["reason"] != "default" || dec[0].Attributes["session_id"] == "" {
		t.Fatalf("decisions = %+v", dec)
	}
	trigger := dec[0].Attributes["apdu_id"]
	if got := h.outcomes(); !reflect.DeepEqual(got, []string{"aborted"}) {
		t.Fatalf("session outcomes before verdicts = %v", got)
	}
	if len(h.eventsOf("ics.verdict")) != 0 || len(h.inj.Resets()) != 0 {
		t.Fatal("verdict or resets before the drop completions")
	}
	h.e.hooks.onVerdict(held.Token, capture.VerdictDrop, nil)
	h.e.hooks.onVerdict(cur.Token, capture.VerdictDrop, nil)
	v := h.eventsOf("ics.verdict")
	if len(v) != 1 || v[0].Attributes["outcome"] != "dropped" || v[0].Attributes["trigger_apdu_id"] != trigger {
		t.Fatalf("verdict = %+v", v)
	}
	sid := dec[0].Attributes["session_id"].(string)
	wantIDs := []string{eventfields.APDUID(sid, 'c', 16), eventfields.APDUID(sid, 'c', 32)}
	if got := v[0].Attributes["apdu_ids"]; !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("apdu_ids = %v, want %v (collateral allowed APDU and the denied one)", got, wantIDs)
	}
	resets := h.waitResets(2)
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.30.30.30:2404")
	want := []session.Reset{
		{Src: client, Dst: server, Seq: 1}, // ISN 0xfffffff0 + 1 + 16 forwarded bytes, across 2^32
		{Src: server, Dst: client, Seq: uint32(testServerISN) + 1 + 16},
	}
	if !reflect.DeepEqual(resets, want) {
		t.Fatalf("resets = %+v, want %+v", resets, want)
	}
	select {
	case req := <-h.deletes:
		if req.Src != "10.60.60.10" || req.Sport != 40000 || req.Dport != 2404 {
			t.Fatalf("conntrack delete = %+v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no conntrack delete after the resets")
	}
	// The incarnation is a tombstone: later data is dropped, no ban.
	if _, d := h.send(true, iframe(46, 1)); d.Action != capture.Drop {
		t.Fatalf("old session data = %+v", d)
	}
	if flows := h.e.Events().Flows(0); len(flows) != 0 {
		t.Fatalf("aborted incarnation still in /flows: %+v", flows)
	}
}

func TestIECChallengeACKRetriesAndReconnect(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	cur, _ := h.send(true, iframe(45, 1))
	h.e.hooks.onVerdict(cur.Token, capture.VerdictDrop, nil)
	h.waitResets(2)
	// The client answers with a challenge ACK at its real receive point.
	for i := 0; i < 5; i++ {
		ack := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq+uint32(100+i), nil)
		if d := h.e.handlePacket(ack); d.Action != capture.Drop {
			t.Fatalf("old ACK = %+v", d)
		}
	}
	resets := h.waitResets(5)
	time.Sleep(50 * time.Millisecond)
	if got := len(h.inj.Resets()); got != 5 {
		t.Fatalf("resets = %d, want 2 + 3 retries", got)
	}
	if resets[2].Dst.Port() != 40000 || resets[2].Seq != h.sSeq+100 {
		t.Fatalf("retry = %+v, want seq at the challenge ACK", resets[2])
	}
	// A retransmitted old SYN is not a new session.
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil)); d.Action != capture.Drop {
		t.Fatalf("old SYN = %+v", d)
	}
	// Same 5-tuple, new ISN: a new incarnation once the handshake validates.
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("new SYN = %+v", d)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("new SYN-ACK = %+v", d)
	}
	h.cSeq, h.sSeq = 778, 9001
	if _, d := h.send(true, iframe(46, 1)); d.Action != h.passingDisposition() {
		t.Fatalf("new incarnation command = %+v", d)
	}
	if _, d := h.send(false, startdtCon); d.Action != h.passingDisposition() {
		t.Fatalf("STARTDT con = %+v", d)
	}
	got := h.outcomes()
	if got[len(got)-1] != "reconnected" {
		t.Fatalf("outcomes = %v, want reconnected last", got)
	}
}

func TestIECLearnEnvelopeNeverHoldsOrAborts(t *testing.T) {
	h := newIECHarness(t, "monitor")
	h.handshake()
	if _, d := h.send(true, iframe(45, 1)[:4]); d.Action != h.passingDisposition() {
		t.Fatalf("learn partial = %+v", d)
	}
	if _, d := h.send(true, iframe(45, 1)[4:]); d.Action != h.passingDisposition() {
		t.Fatalf("learn deny = %+v", d)
	}
	dec := h.eventsOf("ics.decision")
	if len(dec) != 1 || dec[0].Attributes["decision"] != "would_drop" || dec[0].Attributes["mode"] != "monitor" {
		t.Fatalf("decisions = %+v", dec)
	}
	if len(h.outcomes()) != 0 || len(h.inj.Resets()) != 0 {
		t.Fatalf("learn aborted: %v", h.outcomes())
	}
}

func TestIECMonitorRuleCannotSuppressEnvelopeDeny(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.policy.denyRule = &rulesEntryLearnDeny
	h.handshake()
	if _, d := h.send(true, iframe(45, 1)); d.Action != capture.Drop {
		t.Fatalf("monitor suppressed envelope: %+v", d)
	}
	dec := h.eventsOf("ics.decision")
	if len(dec) != 2 || dec[0].Attributes["decision"] != "would_drop" || dec[0].Attributes["ruleId"] != "deny-learn" || dec[1].Attributes["decision"] != "deny" {
		t.Fatalf("decisions=%+v", dec)
	}
}

func TestIECPendingTimeoutAborts(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	held, _ := h.send(true, iframe(46, 1)[:3])
	h.clock = h.clock.Add(1100 * time.Millisecond)
	h.e.iec.expire()
	if len(h.settler.calls) != 1 || h.settler.calls[0][0] != (capture.Resolution{Token: held.Token, Verdict: capture.VerdictDrop}) {
		t.Fatalf("settle calls = %+v", h.settler.calls)
	}
	h.e.hooks.onVerdict(held.Token, capture.VerdictDrop, nil)
	v := h.eventsOf("ics.verdict")
	if len(v) != 1 || v[0].Attributes["outcome"] != "dropped" {
		t.Fatalf("verdict = %+v", v)
	}
	if _, ok := v[0].Attributes["trigger_apdu_id"]; ok {
		t.Fatal("timeout abort must not name a trigger APDU")
	}
	if ids := v[0].Attributes["apdu_ids"].([]string); len(ids) != 1 || !strings.HasSuffix(ids[0], "/c/0") {
		t.Fatalf("apdu_ids = %v, want the known start of the incomplete tail", ids)
	}
	h.waitResets(2)
}

func TestIECConflictingRetransmitAborts(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1)[:6])
	bad := iframe(46, 1)
	bad[3] = 0x55
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, h.clientISN+1, h.sSeq, bad)); d.Action != capture.Drop {
		t.Fatalf("conflicting overlap = %+v, want Drop", d)
	}
	if got := h.outcomes(); len(got) != 1 || got[0] != "aborted" {
		t.Fatalf("outcomes = %v", got)
	}
}

func TestIECMidstreamSessionIsResetOnce(t *testing.T) {
	h := newIECHarness(t, "enforce")
	p := h.pkt(true, capture.TCPFlagACK|capture.TCPFlagPSH, 1000, 2000, iframe(46, 1))
	if d := h.e.handlePacket(p); d.Action != capture.Drop {
		t.Fatalf("mid-stream = %+v", d)
	}
	h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
	resets := h.waitResets(2)
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.30.30.30:2404")
	want := []session.Reset{{Src: client, Dst: server, Seq: 1000}, {Src: server, Dst: client, Seq: 2000}}
	if !reflect.DeepEqual(resets, want) {
		t.Fatalf("resets = %+v, want %+v", resets, want)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, 1016, 2000, iframe(46, 1))); d.Action != capture.Drop {
		t.Fatalf("second mid-stream packet = %+v", d)
	}
	time.Sleep(20 * time.Millisecond)
	if got := len(h.inj.Resets()); got != 2 {
		t.Fatalf("resets = %d, want one pair", got)
	}
}

func TestIECInjectorUnavailableFailsClosed(t *testing.T) {
	old := newInjector
	newInjector = func() (session.Injector, error) { return nil, session.ErrUnsupportedPlatform }
	t.Cleanup(func() { newInjector = old })
	e, err := New(Config{DPIEnabled: true, NFQueueGroup: 101})
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePolicy{matched: true, mode: "enforce"}
	e.iec.newPolicy = func(*rulesSnapshot) iecPolicy { return p }
	e.LoadRules(iecSnapshot("enforce"))
	h := &iecHarness{t: t, e: e, client: testClientIP, server: testServerIP, cport: 40000}
	if d := e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 1, 0, nil)); d.Action != capture.Drop {
		t.Fatalf("SYN without an injector = %+v, want Drop", d)
	}
	st := e.IEC104Enforcement()
	if !st.Active || st.Healthy || !strings.Contains(st.Reason, "injector") {
		t.Fatalf("health = %+v", st)
	}
}

func TestIECHealthQueueDownAndRecovery(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	held, _ := h.send(true, iframe(46, 1)[:3])
	if st := h.e.IEC104Enforcement(); !st.Active || !st.Healthy || st.Reason != "" {
		t.Fatalf("health = %+v", st)
	}
	h.e.hooks.onSource(capture.SourceEvent{Generation: 1, Ready: false, Err: errors.New("netlink closed")})
	if st := h.e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "netlink closed") {
		t.Fatalf("health after queue down = %+v", st)
	}
	h.e.hooks.onVerdict(held.Token, capture.VerdictDrop, capture.ErrQueueClosed)
	v := h.eventsOf("ics.verdict")
	if len(v) != 1 || v[0].Attributes["outcome"] != "drop_failed" {
		t.Fatalf("verdict after queue down = %+v", v)
	}
	h.waitResets(2)
	h.e.hooks.onSource(capture.SourceEvent{Generation: 2, Ready: true})
	if st := h.e.IEC104Enforcement(); !st.Healthy {
		t.Fatalf("health after ready = %+v", st)
	}
	got := h.outcomes()
	if !contains(got, "enforce_unhealthy") || got[len(got)-1] != "enforce_healthy" {
		t.Fatalf("outcomes = %v", got)
	}
}

func TestIECPolicyChangeResetsSession(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.policy.mode = "monitor"
	h.e.LoadRules(iecSnapshot("monitor"))
	resets := h.waitResets(2)
	if len(resets) != 2 || resets[0].Dst != netip.MustParseAddrPort("10.30.30.30:2404") ||
		resets[1].Dst != netip.MustParseAddrPort("10.60.60.10:40000") {
		t.Fatalf("policy change resets = %+v, want one per endpoint", resets)
	}
	if got := h.outcomes(); !reflect.DeepEqual(got, []string{"aborted", "reset_sent", "reset_sent"}) {
		t.Fatalf("outcomes = %v", got)
	}
	ev := h.eventsOf("ics.session")[0]
	if ev.Attributes["reason"] != "policy" {
		t.Fatalf("abort reason = %v, want policy", ev.Attributes["reason"])
	}
}

func TestIECUnframedStreamFailsClosed(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.e.dpiMgr = dpiManagerWithout()
	h.e.iec.dpi = h.e.dpiMgr
	h.handshake()
	if _, d := h.send(true, iframe(46, 1)); d.Action != capture.Drop {
		t.Fatalf("unframed = %+v, want Drop", d)
	}
	if st := h.e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "not framed") {
		t.Fatalf("health = %+v", st)
	}
}
