// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

type transportBlockingApply struct {
	enforce.Applier
	started, release chan struct{}
}

func (a *transportBlockingApply) Apply(ctx context.Context, _ string) error {
	close(a.started)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.release:
		return nil
	}
}

func TestTransportEventsDuringApplyKeepIdentity(t *testing.T) {
	evidence := natEvidence()
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: evidence})
	ctx := context.Background()
	r.authority.check(ctx)
	request := transportWire(evidence.Original, time.Now(), modbusADU(1, 3, 10, 2))
	e.handleTransportPacket(request, r.resolve(ctx, request, false))
	first := transportModbusEvents(e)[0]
	base := &transportBlockingApply{started: make(chan struct{}), release: make(chan struct{})}
	applier := &transportApplier{Applier: base, authority: r.authority}
	done := make(chan error, 1)
	go func() { done <- applier.Apply(ctx, "rules") }()
	<-base.started
	// A whole-namespace read must not wait for the nft apply lock.
	r.authority.check(ctx)
	if r.authority.version.Load()%2 == 0 {
		t.Fatal("scan authorized an unfinished apply")
	}
	reply := transportWire(evidence.Reply, time.Now(), []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11})
	e.handleTransportPacket(reply, r.resolve(ctx, reply, false))
	close(base.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	last := transportModbusEvents(e)[0]
	if first.TransportConnectionID == "" || last.TransportConnectionID != first.TransportConnectionID ||
		last.CorrelationStatus != "zone_unverified" || e.AnomalyDetector().PairingStats().Matched != 1 {
		t.Fatalf("apply split the event identity: %+v, %+v", first, last)
	}
	for _, summary := range e.Events().Flows(0) {
		if summary.TransportConnectionID != first.TransportConnectionID {
			t.Fatal("apply erased rollup identity")
		}
	}
}

type transportBlockingZones struct {
	block            atomic.Bool
	started, release chan struct{}
}

func (z *transportBlockingZones) ZoneSetters(ctx context.Context) ([]enforce.ZoneSetter, error) {
	if z.block.Load() {
		select {
		case z.started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-z.release:
		}
	}
	return nil, nil
}

func TestTransportAuthorityReadDoesNotStallPacketWorker(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	z := &transportBlockingZones{started: make(chan struct{}, 1), release: make(chan struct{})}
	r.authority.reader = z
	_, _ = runTransportTest(t, e, r)
	z.block.Store(true)
	r.authority.requestCheck()
	select {
	case <-z.started:
	case <-time.After(3 * time.Second):
		t.Fatal("authority read did not start")
	}
	r.admit(e, transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2)))
	waitTransport(t, func() bool { return len(transportModbusEvents(e)) == 1 })
	close(z.release)
}
