// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func retentionKey(port uint16) flow.Key {
	return flow.Key{SrcIP: net.ParseIP(testClient), DstIP: net.ParseIP(testServer),
		SrcPort: port, DstPort: 502, Proto: 6}
}

func retentionEvictions(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "containd_dp_denied_tcp_evictions_total" {
			return family.Metric[0].GetCounter().GetValue()
		}
	}
	t.Fatal("denial eviction counter is not registered")
	return 0
}

// forceRetentionEviction fills the actual hard capacity, evicting the original
// connection. No extra reset jobs are needed for these independent tombstones.
func forceRetentionEviction(t *testing.T, e *Engine) {
	t.Helper()
	for port := 1; port <= deniedTCPCapacity; port++ {
		if e.rememberDeniedTCP(retentionKey(uint16(port)), retentionKey(uint16(port)), false) == nil {
			t.Fatalf("duplicate filler tuple %d", port)
		}
	}
}

func denyRetentionCommand(t *testing.T, f *resetFlow, p firstCommandProtocol) capture.Packet {
	t.Helper()
	loadResetPolicy(f.e)
	f.syn()
	f.synAck()
	f.accept("allowed read", p.read(1))
	pkt := f.segment(false, f.isn+f.next, 9000, ackPsh, p.denied[0].frame)
	if d := f.handle(pkt); d.Action != capture.Drop || d.Reason != reasonDPIDeny {
		t.Fatalf("original denied command = %+v", d)
	}
	f.waitResets(2)
	drainResetWorker(t, f.e)
	return pkt
}

// Once the guard is gone, the exact denied bytes, even resegmented, must be
// rejected as an untracked pickup rather than forwarded or parsed anew.
func TestDenyRetentionRetransmit(t *testing.T) {
	for _, p := range resetProtocols() {
		for _, removal := range []string{"sweep expiry", "lazy expiry", "capacity eviction"} {
			t.Run(p.name+"/"+removal, func(t *testing.T) {
				f := newResetFlow(t, p.port)
				now := time.Now()
				f.e.deniedTCPNow = func() time.Time { return now }
				pkt := denyRetentionCommand(t, f, p)
				hits := ruleHits(f.e, p.denied[0].rule)
				if removal == "capacity eviction" {
					forceRetentionEviction(t, f.e)
				} else {
					now = now.Add(deniedTCPLifetime)
					if removal == "sweep expiry" {
						f.e.sweepFlows(now)
					}
				}
				raw := pkt.Payload
				cut := len(raw) / 2
				pkt.Payload = raw[:cut]
				if d := f.handle(pkt); d.Action != capture.Drop || d.Reason != reasonStreamFailClosed {
					t.Fatalf("first retransmitted half = %+v, want mid-stream drop", d)
				}
				evs := failClosedEvents(f.e)
				if len(evs) != 1 || evs[0].Proto != p.name ||
					evs[0].Attributes[eventfields.KeyReason] != failClosedMidStream {
					t.Fatalf("pickup evidence = %+v", evs)
				}
				pkt.TCP.Seq += uint32(cut)
				pkt.Payload = raw[cut:]
				if d := f.handle(pkt); d.Action != capture.Drop {
					t.Fatalf("second retransmitted half = %+v", d)
				}
				if got := ruleHits(f.e, p.denied[0].rule); got != hits {
					t.Fatalf("old bytes inspected again: deny hits %d -> %d", hits, got)
				}
				f.waitResets(4)
				// This also covers a failed pickup stream created with the
				// pre-expiry state pointer, after that state was forgotten.
				f.isn, f.next = 800000, 0
				f.syn()
				f.accept("read after pickup reconnect", p.read(2))
				if len(f.up.calls) != 0 {
					t.Fatal("DPI installed a block")
				}
			})
		}
	}
}

func TestDenyRetentionReconnect(t *testing.T) {
	for _, p := range resetProtocols() {
		for _, sweep := range []bool{false, true} {
			name := "lazy expiry"
			if sweep {
				name = "sweep expiry"
			}
			t.Run(p.name+"/"+name, func(t *testing.T) {
				f := newResetFlow(t, p.port)
				now := time.Now()
				f.e.deniedTCPNow = func() time.Time { return now }
				denyRetentionCommand(t, f, p)
				// Keep the normal 30-second denial cache and failed stream.
				// Neither may strand this new handshake after 10 seconds.
				now = now.Add(deniedTCPLifetime)
				if sweep {
					f.e.sweepFlows(now)
				}
				f.isn, f.next = 800000, 0
				f.syn()
				read := p.read(2)
				hits := ruleHits(f.e, p.name+"-read")
				f.accept("read header prefix", read[:3])
				if got := ruleHits(f.e, p.name+"-read"); got != hits {
					t.Fatalf("incomplete header decoded: %d -> %d", hits, got)
				}
				f.accept("read header and body tail", read[3:])
				if got := ruleHits(f.e, p.name+"-read"); got != hits+1 {
					t.Fatalf("reconnect read hits %d -> %d, want one", hits, got)
				}
				denied := p.denied[0]
				f.accept("denied header prefix", denied.frame[:3])
				f.deny("denied command tail", denied.rule, denied.frame[3:])
			})
		}
	}
}

func TestDenyRetentionFixedLifetime(t *testing.T) {
	f := newResetFlow(t, 502)
	now := time.Now()
	f.e.deniedTCPNow = func() time.Time { return now }
	pkt := denyRetentionCommand(t, f, resetProtocols()[0])
	d := f.e.deniedTCPOrder.Front().Value.(*deniedTCP)
	deadline := d.expires
	if deadline.Sub(now) != 10*time.Second {
		t.Fatalf("lifetime = %v", deadline.Sub(now))
	}
	other := *f.fcFlow
	other.client++
	other.syn()
	other.accept("independent session", modbusADU(2, 3, 0, 1))
	now = now.Add(9 * time.Second)
	if got := f.handle(pkt); got.Action != capture.Drop {
		t.Fatalf("duplicate = %+v", got)
	}
	if d.expires != deadline || f.e.rememberDeniedTCP(d.key, d.service, false) != nil {
		t.Fatal("duplicate refreshed the denial")
	}
	before := retentionEvictions(t)
	now = deadline
	f.e.sweepFlows(now)
	if len(f.e.deniedTCP) != 0 || f.e.deniedTCPOrder.Len() != 0 || !d.retired {
		t.Fatal("tombstone did not expire at its original deadline")
	}
	if got := retentionEvictions(t); got != before {
		t.Fatalf("expiry counted as eviction: %v -> %v", before, got)
	}
	other.accept("independent session survives expiry", modbusADU(3, 3, 0, 1))
}

func TestDenyRetentionCapacity(t *testing.T) {
	e := recordEngine(t)
	now := time.Now()
	e.deniedTCPNow = func() time.Time { return now }
	before := retentionEvictions(t)
	const extra = 512
	for i := 1; i <= deniedTCPCapacity+extra; i++ {
		if e.rememberDeniedTCP(retentionKey(uint16(i)), retentionKey(uint16(i)), false) == nil {
			t.Fatalf("new denial %d was not recorded", i)
		}
		if len(e.deniedTCP) > deniedTCPCapacity || e.deniedTCPOrder.Len() != len(e.deniedTCP) {
			t.Fatalf("capacity violated at denial %d: %d", i, len(e.deniedTCP))
		}
		if i == deniedTCPCapacity && e.rememberDeniedTCP(retentionKey(1), retentionKey(1), false) != nil {
			t.Fatal("duplicate should neither insert nor move the oldest entry")
		}
	}
	for i := 1; i <= deniedTCPCapacity+extra; i++ {
		d := e.deniedTCP[tcpTupleKey(retentionKey(uint16(i)))]
		if (d == nil) != (i <= extra) {
			t.Fatalf("oldest-first eviction wrong for tuple %d", i)
		}
	}
	if got := retentionEvictions(t) - before; got != extra {
		t.Fatalf("evictions = %v, want %d", got, extra)
	}
}

func TestDenyRetentionConcurrentCapacity(t *testing.T) {
	e := recordEngine(t)
	now := time.Now()
	e.deniedTCPNow = func() time.Time { return now }
	before := retentionEvictions(t)
	const workers, perWorker = 8, deniedTCPCapacity/8 + 64
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			for i := range perWorker {
				port := uint16(worker*perWorker + i + 1)
				if e.rememberDeniedTCP(retentionKey(port), retentionKey(port), false) == nil {
					t.Errorf("new denial %d was not recorded", port)
					return
				}
				e.flowMu.Lock()
				size, ordered := len(e.deniedTCP), e.deniedTCPOrder.Len()
				e.flowMu.Unlock()
				if size > deniedTCPCapacity || ordered != size {
					t.Errorf("capacity violated: map=%d FIFO=%d", size, ordered)
					return
				}
			}
		})
	}
	wg.Wait()
	if len(e.deniedTCP) != deniedTCPCapacity {
		t.Fatalf("final size = %d", len(e.deniedTCP))
	}
	if got := retentionEvictions(t) - before; got != workers*perWorker-deniedTCPCapacity {
		t.Fatalf("evictions = %v", got)
	}
}

// Eviction can happen immediately after publication, before the original
// handler has scheduled its reset. That handler must not recreate failed-stream
// state after retirement, or its next handshake would have no guard to clear it.
func TestDenyRetentionConcurrentEvictionPublication(t *testing.T) {
	f := newResetFlow(t, 502)
	loadResetPolicy(f.e)
	now := time.Now()
	f.e.deniedTCPNow = func() time.Time { return now }
	f.syn()
	f.accept("read", modbusADU(1, 3, 0, 1))
	pkt := f.segment(false, f.isn+f.next, 9000, ackPsh, firstCommandProtocols()[0].denied[0].frame)

	// Pause reset preparation at its readiness check, after guard publication.
	f.e.iec.health.mu.Lock()
	release := sync.OnceFunc(f.e.iec.health.mu.Unlock)
	done := make(chan capture.Decision, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("denial handler did not finish")
		}
	})
	go func() {
		defer close(finished)
		done <- f.handle(pkt)
	}()
	tuple := tcpTupleKey(retentionKey(f.client))
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.e.flowMu.Lock()
		published := f.e.deniedTCP[tuple] != nil
		f.e.flowMu.Unlock()
		if published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("denial guard was not published")
		}
		time.Sleep(time.Millisecond)
	}
	forceRetentionEviction(t, f.e)
	release()
	select {
	case got := <-done:
		if got.Action != capture.Drop || got.Reason != reasonDPIDeny {
			t.Fatalf("denial = %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("denial handler did not finish")
	}
	drainResetWorker(t, f.e)
	if len(f.inj.Resets()) != 0 || len(f.deletes) != 0 {
		t.Fatal("evicted guard allowed an old reset")
	}
	f.isn, f.next = 800000, 0
	f.syn()
	hits := ruleHits(f.e, "modbus-read")
	f.accept("read after immediate eviction", modbusADU(2, 3, 0, 1))
	if got := ruleHits(f.e, "modbus-read"); got != hits+1 {
		t.Fatalf("reconnect read hits %d -> %d", hits, got)
	}
}

func TestDenyRetentionExpiryCancelsQueuedReset(t *testing.T) {
	f := newResetFlow(t, 502)
	loadResetPolicy(f.e)
	now := time.Now()
	f.e.deniedTCPNow = func() time.Time { return now }
	f.syn()
	pkt := f.segment(false, f.isn, 9000, ackPsh, firstCommandProtocols()[0].denied[0].frame)
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	if got := f.e.HandlePacket(pkt); got.Action != capture.Drop {
		t.Fatalf("denial = %+v", got)
	}
	now = now.Add(deniedTCPLifetime)
	f.e.sweepFlows(now)
	f.isn, f.next = 800000, 0
	f.syn()
	f.accept("reconnect before old drop completion", modbusADU(3, 3, 0, 1))
	f.e.hooks.onVerdict(pkt.Token, capture.VerdictDrop, nil)
	drainResetWorker(t, f.e)
	if len(f.inj.Resets()) != 0 || len(f.deletes) != 0 {
		t.Fatal("expired reset job affected the new connection")
	}
}
