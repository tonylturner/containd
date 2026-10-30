// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportPublishedIdentitySurvivesRefresh(t *testing.T) {
	for _, replyOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "bidirectional", true: "reply-only"}[replyOnly], func(t *testing.T) {
			ev := natEvidence()
			e, r, z := newTransportTest(t, &transportCTFake{evidence: ev})
			ctx := context.Background()
			r.authority.check(ctx)
			tuple := ev.Original
			if replyOnly {
				tuple = ev.Reply
			}
			pkt := transportWire(tuple, time.Now(), nil)
			c := r.resolve(ctx, pkt, false)
			e.handleTransportPacket(pkt, c, nil)
			e.flowMu.Lock()
			state := e.tupleStateLocked(tuple)
			e.flowMu.Unlock()
			state.Connection.Load().Published().Store(true)
			id := state.Connection.Load().PublicID()
			for _, fail := range []bool{false, true, false} {
				if fail {
					z.set(nil, errors.New("permission denied"))
				} else {
					z.set(nil, nil)
				}
				r.authority.check(ctx)
				c = r.resolve(ctx, pkt, false)
				e.bindTransport(state, c)
				if fail {
					if state.Connection.Load().PublicID() != id || state.Connection.Load().Verified() {
						t.Fatal("published ID or downgraded evidence lost during authority failure")
					}
				} else if state.Connection.Load().PublicID() != id {
					t.Fatal("renamed published identity")
				}
			}

			// A second direction must share the refreshed record, including FIN.
			peer := ev.Reply
			if replyOnly {
				peer = ev.Original
			}
			peerPkt := transportWire(peer, time.Now(), nil)
			e.handleTransportPacket(peerPkt, r.resolve(ctx, peerPkt, false), nil)
			e.flowMu.Lock()
			other := e.tupleStateLocked(peer)
			e.flowMu.Unlock()
			if other.Connection.Load() != state.Connection.Load() {
				t.Fatal("directional lifecycle state split after refresh")
			}
		})
	}
}

func TestTransportIncarnationAndPeerCleanup(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	ctx := context.Background()
	r.authority.check(ctx)
	request := transportWire(ev.Original, time.Now(), modbusADU(1, 3, 10, 2))
	request.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	first := r.resolve(ctx, request, false)
	e.handleTransportPacket(request, first, nil)
	reply := transportWire(ev.Reply, time.Now(), nil)
	e.handleTransportPacket(reply, r.resolve(ctx, reply, false), nil)
	e.flowMu.Lock()
	original, reverse := e.tupleStateLocked(ev.Original), e.tupleStateLocked(ev.Reply)
	e.flowMu.Unlock()
	if e.peerFlow(original) != reverse {
		t.Fatal("translated peer not found")
	}
	e.closeCorrelation(original, false, false)
	e.closeCorrelation(reverse, false, false)
	if !original.Connection.Load().Closed().Load() || e.anomalyDetector.PairingStats().PendingTransactions != 0 {
		t.Fatal("FIN did not clean connection transactions")
	}
	request.TCP.Seq++
	next := r.resolve(ctx, request, false)
	e.handleTransportPacket(request, next, nil)
	e.flowMu.Lock()
	renewed, stalePeer := e.tupleStateLocked(ev.Original), e.tupleStateLocked(ev.Reply)
	e.flowMu.Unlock()
	if renewed == original || stalePeer != nil || renewed.Connection.Load().Key == first.Key {
		t.Fatal("new SYN inherited old streams/incarnation")
	}
	e.closeCorrelation(renewed, true, false)
	if !renewed.Connection.Load().Closed().Load() {
		t.Fatal("RST did not close incarnation")
	}
}

func TestTransportUnresolvedHistoryAdoptsIdentity(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	request := transportWire(ev.Original, time.Now(), modbusADU(1, 3, 10, 2))
	e.handleTransportPacket(request, r.unresolved("not_found"), nil)
	e.flowMu.Lock()
	key := e.tupleStateLocked(ev.Original).Connection.Load().Key
	e.flowMu.Unlock()
	r.authority.check(context.Background())
	reply := transportWire(ev.Reply, time.Now(), []byte{0, 1, 0, 0, 0, 3, 1, 0x83, 2})
	e.handleTransportPacket(reply, r.resolve(context.Background(), reply, false), nil)
	got := transportModbusEvents(e)
	if len(got) != 2 || got[0].TransportConnectionID == "" || e.AnomalyDetector().PairingStats().Matched != 1 {
		t.Fatalf("unresolved history not adopted: %+v", got)
	}
	e.flowMu.Lock()
	adopted := e.tupleStateLocked(ev.Original).Connection.Load()
	e.flowMu.Unlock()
	if adopted.Key != key {
		t.Fatal("adoption renamed the incarnation pairing key")
	}
}

func TestTransportAdoptsBothUnresolvedDirectionalHistories(t *testing.T) {
	ev := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: ev})
	original := flow.NewState(flow.TupleKey(ev.Original, flow.DirForward), time.Now())
	reply := flow.NewState(flow.TupleKey(ev.Reply, flow.DirReverse), time.Now())
	for i, state := range []*flow.State{original, reply} {
		c := r.unresolved("not_found")
		state.Connection.Store(c)
		e.flows[state.Key.MapKey()] = state
		e.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "modbus", Kind: "request", FlowID: state.Key.Hash(),
			Timestamp: time.Now(), Attributes: map[string]any{
				"transaction_id": uint16(i + 1), "unit_id": uint8(1), "function_code": uint8(3)}}})
	}
	original.Connection.Load().Coverage().Store(true)
	oldReply := reply.Connection.Load()
	// Preserve the reply-side notification and loss history too.
	oldReply.ReportUnavailable()
	oldReply.LoseCorrelation(time.Now(), time.Minute)
	r.authority.check(context.Background())
	pkt := transportWire(ev.Reply, time.Now(), nil)
	e.bindTransport(reply, r.resolve(context.Background(), pkt, false))
	c := reply.Connection.Load()
	if c.PublicID() == "" || c != original.Connection.Load() || c.ReportUnavailable() ||
		c.CorrelationAvailable(time.Now()) || e.AnomalyDetector().PairingStats().PendingTransactions != 2 {
		t.Fatal("adoption lost a directional pending/notification history")
	}
	for i, state := range []*flow.State{reply, original} {
		e.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "modbus", Kind: "response", FlowID: state.Key.Hash(),
			Timestamp: time.Now(), Attributes: map[string]any{
				"transaction_id": uint16(i + 1), "unit_id": uint8(1), "function_code": uint8(3)}}})
	}
	if stats := e.AnomalyDetector().PairingStats(); stats.Matched != 2 || stats.PendingTransactions != 0 {
		t.Fatalf("adoption did not transfer both directions: %+v", stats)
	}
}

func TestTransportResolverIPv6UDPAndAliasCapacity(t *testing.T) {
	ev := conntrack.Evidence{ID: 42, TimeoutSeconds: 60,
		Original: conntrack.Tuple{Family: 10, Protocol: 17,
			Source: netip.MustParseAddrPort("[2001:db8:1::1]:41000"), Destination: netip.MustParseAddrPort("[2001:db8:2::1]:502")},
		Reply: conntrack.Tuple{Family: 10, Protocol: 17,
			Source: netip.MustParseAddrPort("[2001:db8:2::1]:502"), Destination: netip.MustParseAddrPort("[2001:db8:2::2]:52000")}}
	f := &transportCTFake{evidence: ev}
	_, r, _ := newTransportTest(t, f)
	ctx := context.Background()
	r.authority.check(ctx)
	o := r.resolve(ctx, transportWire(ev.Original, time.Now(), nil), false)
	reply := r.resolve(ctx, transportWire(ev.Reply, time.Now(), nil), false)
	if !o.Verified() || o != reply || f.calls != 1 {
		t.Fatal("IPv6 UDP alias resolution")
	}
	for i := 0; i < transportAliasLimit; i++ {
		key := ev.Original
		key.Source = netip.AddrPortFrom(key.Source.Addr(), uint16(i))
		r.aliases[key] = &transportAlias{connection: o, version: r.authority.version.Load(), expires: time.Now().Add(time.Second)}
	}
	tuple := ev.Reply
	tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), 42)
	if got := r.resolve(ctx, transportWire(tuple, time.Now(), nil), false); got.Status != "cache_capacity" {
		t.Fatal("alias cap not enforced")
	}
}

type transportApplyFake struct {
	transportZoneFake
	authority *transportAuthority
}

func (a *transportApplyFake) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}

func (a *transportApplyFake) Apply(context.Context, string) error {
	if a.authority.version.Load()%2 == 0 {
		return errors.New("authority remained verified during apply")
	}
	a.set([]enforce.ZoneSetter{{Family: "ip", Table: "foreign", Chain: "raw", Handle: 1}}, nil)
	return nil
}

func TestTransportApplierRechecksWholeNamespace(t *testing.T) {
	base := &transportApplyFake{}
	a := newTransportAuthority(base)
	base.authority = a
	a.check(context.Background())
	wrapper := &transportApplier{Applier: base, authority: a}
	if err := wrapper.Apply(context.Background(), "rules"); err != nil {
		t.Fatal(err)
	}
	a.check(context.Background())
	if a.version.Load()%2 == 0 || a.snapshot().ZoneStatus != "unsupported_zone" || a.snapshot().Counters["zone_checks"] != 2 {
		t.Fatal("apply did not invalidate and recheck authority")
	}
}

func TestTransportEngineWiresApplierAndStatus(t *testing.T) {
	base := &transportApplyFake{}
	e, err := New(Config{Capture: capture.Config{Mode: "afpacket", Interfaces: []string{"lo"}},
		Enforce: EnforceConfig{Enabled: true, Applier: base}})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, ok := e.applier.(*transportApplier)
	if !ok || wrapped.Applier != base || e.transport.authority.reader != base {
		t.Fatal("engine did not use its own applier as zone authority")
	}
	status := e.RulesetStatus()
	if status.TransportIdentity == nil || status.TransportIdentity.ZoneStatus != "zone_unverified" {
		t.Fatal("missing initial authority health")
	}
	status.TransportIdentity.Counters["zone_checks"] = 999
	e.transport.authority.check(context.Background())
	if e.RulesetStatus().TransportIdentity.Counters["zone_checks"] != 1 {
		t.Fatal("status exposed mutable counters")
	}
	for _, cfg := range []Config{{NFQueueGroup: 5}, {Capture: capture.Config{Mode: "nfqueue", Interfaces: []string{"lo"}}}, {}} {
		wireOnly := &Engine{}
		if err := wireOnly.initTransport(cfg); err != nil || wireOnly.transport != nil {
			t.Fatal("wire-only capture acquired CT authority")
		}
	}
}

func TestTransportWireIncarnations(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	e.transport = nil
	ev := natEvidence()
	pkt := transportWire(ev.Original, time.Now(), nil)
	e.HandlePacket(pkt)
	e.flowMu.Lock()
	st := e.tupleStateLocked(ev.Original)
	e.flowMu.Unlock()
	c := st.Connection.Load()
	if c.PublicID() != "" || c.Status != "wire" {
		t.Fatal("wire-only path acquired CT identity")
	}
	events := []dpi.Event{{FlowID: st.Key.Hash(), Kind: "request", Proto: "modbus"}}
	bindEventConnections(st, events)
	if events[0].Connection != c || events[0].CorrelationStatus != "wire" {
		t.Fatal("wire-only event lost wire incarnation")
	}
	if c.Direction(flow.TupleKey(ev.Original, flow.DirForward)) != flow.DirForward {
		t.Fatal("wire-only direction changed")
	}
}

func TestTransportReconfigureCancelsOldWorkerBeforeRestart(t *testing.T) {
	f := &transportCTFake{evidence: natEvidence(), started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	e, old, _ := newTransportTest(t, f)
	e.capture = idleCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	old.admit(e, transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2)))
	select {
	case <-f.started:
	case <-time.After(3 * time.Second):
		t.Fatal("old worker did not start lookup")
	}
	fresh, err := New(Config{Events: e.Events(), InspectAll: true, DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	next, err := newTransportResolver(&transportZoneFake{}, &transportCTFake{evidence: natEvidence()})
	if err != nil {
		t.Fatal(err)
	}
	fresh.capture, fresh.transport = idleCapture{}, next
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("reconfigure returned before closing old reader")
	}
	if old.count.Load() != 0 || old.bytes.Load() != 0 || len(transportModbusEvents(e)) != 0 || old.epoch == next.epoch {
		t.Fatal("stale run leaked observations, budgets or epoch")
	}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	next.admit(e, transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2)))
	waitTransport(t, func() bool { return len(transportModbusEvents(e)) == 1 })
	cancel()
	select {
	case <-e.runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("new run did not stop")
	}
}
