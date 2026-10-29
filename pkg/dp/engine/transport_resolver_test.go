// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

type transportZoneFake struct {
	mu      sync.Mutex
	setters []enforce.ZoneSetter
	err     error
}

func (f *transportZoneFake) ZoneSetters(context.Context) ([]enforce.ZoneSetter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]enforce.ZoneSetter(nil), f.setters...), f.err
}

func (f *transportZoneFake) set(setters []enforce.ZoneSetter, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setters, f.err = setters, err
}

type transportCTFake struct {
	mu       sync.Mutex
	evidence conntrack.Evidence
	calls    int
	miss     int
	err      error
	started  chan struct{}
	release  chan struct{}
	closed   chan struct{}
}

func (f *transportCTFake) Lookup(ctx context.Context, t conntrack.Tuple) (conntrack.Evidence, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	evidence, err, miss := f.evidence, f.err, f.miss
	f.mu.Unlock()
	if call == 1 && f.started != nil {
		close(f.started)
		select {
		case <-ctx.Done():
			return conntrack.Evidence{}, ctx.Err()
		case <-f.release:
		}
	}
	if call <= miss {
		return conntrack.Evidence{}, conntrack.ErrNotFound
	}
	if err != nil {
		return conntrack.Evidence{}, err
	}
	return evidence, evidence.Validate(t)
}

func (f *transportCTFake) Close() error {
	if f.closed != nil {
		close(f.closed)
	}
	return nil
}

func natEvidence() conntrack.Evidence {
	return conntrack.Evidence{ID: 41, Start: 1234, TimeoutSeconds: 120,
		Original: conntrack.Tuple{Family: 2, Protocol: 6,
			Source: netip.MustParseAddrPort("10.10.0.5:41000"), Destination: netip.MustParseAddrPort("10.20.0.4:502")},
		Reply: conntrack.Tuple{Family: 2, Protocol: 6,
			Source: netip.MustParseAddrPort("10.20.0.4:502"), Destination: netip.MustParseAddrPort("10.20.0.2:52000")},
	}
}

func transportWire(t conntrack.Tuple, at time.Time, payload []byte) capture.Packet {
	return capture.Packet{SrcIP: net.IP(t.Source.Addr().AsSlice()), DstIP: net.IP(t.Destination.Addr().AsSlice()),
		SrcPort: t.Source.Port(), DstPort: t.Destination.Port(), Proto: t.Protocol,
		Transport: "tcp", Timestamp: at, Payload: payload}
}

func newTransportTest(t *testing.T, f *transportCTFake) (*Engine, *transportResolver, *transportZoneFake) {
	t.Helper()
	e, err := New(Config{InspectAll: true, DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
		ID: "learn", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "learn"},
	}}})
	z := &transportZoneFake{}
	r, err := newTransportResolver(z, f)
	if err != nil {
		t.Fatal(err)
	}
	e.transport = r
	return e, r, z
}

func runTransportTest(t *testing.T, e *Engine, r *transportResolver) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx, e) }()
	waitTransport(t, func() bool { return r.authority.version.Load()%2 == 0 })
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("transport worker did not stop")
		}
	})
	return cancel, done
}

func waitTransport(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline.C:
			t.Fatal("transport condition timed out")
		case <-tick.C:
		}
	}
}

func transportModbusEvents(e *Engine) []events.Event {
	var out []events.Event
	for _, ev := range e.Events().List(0) {
		if ev.Proto == "modbus" && (ev.Kind == "request" || ev.Kind == "response" || ev.Kind == "exception") {
			out = append(out, ev)
		}
	}
	return out
}

func TestTransportResolverOrdersNATReplyAfterQueuedRequest(t *testing.T) {
	evidence := natEvidence()
	f := &transportCTFake{evidence: evidence, started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	e, r, _ := newTransportTest(t, f)
	cancel, done := runTransportTest(t, e, r)
	now := time.Now()
	reply := transportWire(evidence.Reply, now.Add(time.Millisecond), []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11})
	request := transportWire(evidence.Original, now, modbusADU(1, 3, 10, 2))
	r.admit(e, reply)
	select {
	case <-f.started:
	case <-time.After(3 * time.Second):
		t.Fatal("lookup did not start")
	}
	// This admission must not wait for the in-flight exact GET or flowMu.
	e.flowMu.Lock()
	r.admit(e, request)
	e.flowMu.Unlock()
	close(f.release)
	waitTransport(t, func() bool { return len(transportModbusEvents(e)) == 2 })
	cancel()
	<-done
	evs := transportModbusEvents(e)
	if evs[0].Kind != "response" || evs[1].Kind != "request" || evs[0].TransportConnectionID == "" ||
		evs[0].TransportConnectionID != evs[1].TransportConnectionID || evs[0].FlowID == evs[1].FlowID {
		t.Fatalf("identity/order: %+v", evs)
	}
	if evs[0].DstIP != "10.20.0.2" || evs[0].DstPort != 52000 || evs[1].SrcIP != "10.10.0.5" {
		t.Fatalf("wire coordinates changed: %+v", evs)
	}
	stats := e.AnomalyDetector().PairingStats()
	if stats.Matched != 1 || stats.Unmatched != 0 || stats.Unavailable != 0 {
		t.Fatalf("pairing = %+v", stats)
	}
	for _, asset := range e.Inventory().List() {
		if asset.IP == "10.20.0.2" || asset.IP == "10.10.0.5" && asset.Role != "master" ||
			asset.IP == "10.20.0.4" && asset.Role != "slave" {
			t.Fatalf("logical role = %+v", asset)
		}
	}
	profiles := e.Learner().Profiles()
	if len(profiles) != 1 || profiles[0].SourceIP != "10.10.0.5" || profiles[0].DestIP != "10.20.0.4" {
		t.Fatalf("logical profiles = %+v", profiles)
	}
	if len(e.Events().Flows(0)) != 2 {
		t.Fatal("transport identity regrouped directional flows")
	}
}

func TestTransportResolverAuthorityAndLaterConfirmation(t *testing.T) {
	evidence := natEvidence()
	f := &transportCTFake{evidence: evidence, miss: 1}
	_, r, z := newTransportTest(t, f)
	ctx := context.Background()
	pkt := transportWire(evidence.Original, time.Now(), nil)
	if c := r.resolve(ctx, pkt, false); c.PublicID() != "" || c.ResolutionStatus() != "zone_unverified" || f.calls != 0 {
		t.Fatalf("trusted unverified authority: %+v", c)
	}
	r.authority.check(ctx)
	c := r.resolve(ctx, pkt, false)
	if c.Status != "not_found" || f.calls != 1 {
		t.Fatalf("miss retried in worker: %+v, calls=%d", c, f.calls)
	}
	r.resolve(ctx, pkt, false)
	if f.calls != 1 {
		t.Fatal("negative cache did not bound GETs")
	}
	r.aliases[packetKey(pkt).Tuple()].expires = time.Now().Add(-time.Millisecond)
	c = r.resolve(ctx, pkt, false)
	if !c.Verified() || f.calls != 2 {
		t.Fatalf("later confirmation: %+v, calls=%d", c, f.calls)
	}
	z.set([]enforce.ZoneSetter{{Family: "ip", Table: "foreign", Chain: "raw", Handle: 1}}, nil)
	r.authority.check(ctx)
	c.Published().Store(true)
	c2 := r.resolve(ctx, pkt, false)
	if c2.PublicID() != c.ID || c2.Verified() || c2.Status != "zone_unverified" || f.calls != 2 {
		t.Fatal("queried or trusted ambiguous zone")
	}
	z.set(nil, errors.New("nft permission denied"))
	r.authority.check(ctx)
	if r.authority.snapshot().ZoneError == "" {
		t.Fatal("lost nft authority error")
	}
	z.set(nil, nil)
	r.authority.check(ctx)
	if c := r.resolve(ctx, pkt, false); !c.Verified() {
		t.Fatal("authority did not recover")
	}
}

func TestTransportResolverFailuresAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status string
	}{
		{"missing", conntrack.ErrNotFound, "not_found"}, {"permission", errors.New("permission denied"), "lookup_error"},
		{"timeout", context.DeadlineExceeded, "lookup_timeout"}, {"zone", conntrack.ErrUnsupportedZone, "unsupported_zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &transportCTFake{err: tc.err}
			e, r, _ := newTransportTest(t, f)
			r.authority.check(context.Background())
			pkt := transportWire(natEvidence().Reply, time.Now(), []byte{0, 1, 0, 0, 0, 3, 1, 0x83, 2})
			c := r.resolve(context.Background(), pkt, false)
			e.handleTransportPacket(pkt, c, nil)
			got := e.AnomalyDetector().Anomalies(0)
			if c.Status != tc.status || c.PublicID() != "" || len(got) != 1 || got[0].Type != "correlation_unavailable" {
				t.Fatalf("failure = %+v, %+v", c, got)
			}
			calls := f.calls
			r.resolve(context.Background(), pkt, false)
			if f.calls != calls {
				t.Fatal("negative cache performed per-packet I/O")
			}
		})
	}
	f := &transportCTFake{evidence: natEvidence()}
	e, r, _ := newTransportTest(t, f)
	pkt := transportWire(natEvidence().Original, time.Now(), make([]byte, 8192))
	for i := 0; i < transportQueueLimit+2; i++ {
		r.admit(e, pkt)
	}
	if r.count.Load() > transportQueueLimit || r.bytes.Load() > transportByteLimit ||
		r.authority.snapshot().Counters["queue_overflow"] == 0 {
		t.Fatal("unbounded admission")
	}
	r.authority.check(context.Background())
	if c := r.resolve(context.Background(), pkt, true); c.Status != "admission_timeout" {
		t.Fatal("missing admission deadline")
	}
}

func TestTransportResolverCancelAndFreshEpoch(t *testing.T) {
	f := &transportCTFake{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	e, r, _ := newTransportTest(t, f)
	cancel, done := runTransportTest(t, e, r)
	r.admit(e, transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2)))
	select {
	case <-f.started:
	case <-time.After(3 * time.Second):
		t.Fatal("no lookup")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled lookup did not finish")
	}
	if len(transportModbusEvents(e)) != 0 || r.count.Load() != 0 || r.bytes.Load() != 0 {
		t.Fatal("published canceled pending evidence")
	}
	_, fresh, _ := newTransportTest(t, &transportCTFake{})
	if fresh.epoch == r.epoch {
		t.Fatal("engine epochs collide")
	}
}

func TestTransportDNATCoordinatesAndConnectionConsumers(t *testing.T) {
	for _, original := range []string{"203.0.113.10:1502", "10.20.0.2:1502"} {
		t.Run(original, func(t *testing.T) {
			evidence := natEvidence()
			evidence.Original.Destination = netip.MustParseAddrPort(original)
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
			r.authority.check(context.Background())
			c := r.resolve(context.Background(), transportWire(evidence.Original, time.Now(), nil), false)
			c.Coverage().Store(true)
			var states []*flow.State
			for i, tuple := range []conntrack.Tuple{evidence.Original, evidence.Reply} {
				st := flow.NewState(flow.TupleKey(tuple, flow.Direction(i)), time.Now())
				st.Connection.Store(c)
				e.flows[st.Key.Hash()] = st
				states = append(states, st)
				ev := dpi.Event{FlowID: st.Key.Hash(), Connection: c, Proto: "modbus", Kind: "request",
					Attributes: map[string]any{"transaction_id": uint16(1), "unit_id": uint8(1), "function_code": uint8(3), "is_write": false,
						"address": uint16(10), "quantity": uint16(2)}}
				if i == 1 {
					ev.Kind = "response"
				}
				e.RecordDPIEvents(st, &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{ev})
			}
			if len(e.Inventory().GetAssets("10.20.0.2")) != 0 || len(e.Learner().Profiles()) != 1 ||
				e.Learner().Profiles()[0].DestIP != "10.20.0.4" {
				t.Fatal("NAT addresses became logical assets")
			}
			// Policy stays on the observed wire key, even though logical
			// inventory and connection-scoped consumers use CT evidence.
			pkt := &dpi.ParsedPacket{Proto: "tcp", DstPort: 1502, SrcPort: 41000}
			ctx, ok := evalContextFromDPIEvent(&rules.Snapshot{}, states[0], pkt, dpi.Event{Proto: "modbus", Kind: "request"}, "", "")
			if !ok || ctx.DstIP.String() != evidence.Original.Destination.Addr().String() || ctx.Port != "1502" {
				t.Fatalf("policy was normalized: %+v", ctx)
			}
			if conformanceKey(states[0]) != conformanceKey(states[1]) {
				t.Fatal("NAT split conformance identity")
			}
			if e.domainClientState(states[1]) != states[0] {
				t.Fatal("NAT split domain exclusion client association")
			}
			sig := signatures.New()
			sig.Add(signatures.Signature{ID: "threshold", Protocol: "modbus", Threshold: &signatures.Threshold{Count: 2, WindowSeconds: 60, Scope: "connection"}})
			for i, st := range states {
				got := sig.Match(dpi.Event{FlowID: st.Key.Hash(), Connection: c, Proto: "modbus"})
				if len(got) != i {
					t.Fatalf("connection threshold direction %d = %+v", i, got)
				}
			}
			for _, ev := range e.Events().List(0) {
				if ev.TransportConnectionID != c.ID {
					t.Fatalf("lost derived identity: %+v", ev)
				}
			}
			if strings.Contains(string(c.ID), original) {
				t.Fatal("public ID exposes tuple")
			}
		})
	}
}
