// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/session"
)

type resetOnQueueStopCapture struct {
	ctx      context.Context
	runDone  <-chan struct{}
	onStop   func()
	stopOnce sync.Once
}

func (c *resetOnQueueStopCapture) Start(ctx context.Context, _ capture.Handler) error {
	c.ctx = ctx
	return nil
}

func (c *resetOnQueueStopCapture) Stop() {
	c.stopOnce.Do(func() {
		select {
		case <-c.ctx.Done():
			// Model capture shutdown finishing only after the engine run has
			// observed cancellation, as the old Reconfigure order did.
			<-c.runDone
		default:
		}
		c.onStop()
	})
}

func (*resetOnQueueStopCapture) Interfaces() []string { return nil }

func (*resetOnQueueStopCapture) Settler() capture.Settler { return nil }

func TestReconfigureRunsQueueShutdownResetsBeforeStoppingWorker(t *testing.T) {
	injector := &session.Fake{}
	e, err := New(Config{NFQueueGroup: 101, ResetInjector: injector})
	if err != nil {
		t.Fatal(err)
	}
	e.dpiMgr = dpi.NewManager(stubIEC{})
	e.iec.dpi = e.dpiMgr
	e.LoadRules(iecSnapshot("enforce"))

	oldHooks := e.hooks
	queue := &resetOnQueueStopCapture{
		onStop: func() {
			oldHooks.onSource(capture.SourceEvent{Generation: 1, Err: capture.ErrQueueClosed})
		},
	}
	e.capture = queue

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := e.Start(ctx); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	queue.runDone = e.runDone

	clientIP, serverIP := net.ParseIP("10.60.60.10"), net.ParseIP("10.30.30.30")
	packets := []capture.Packet{
		{SrcIP: clientIP, DstIP: serverIP, SrcPort: 40000, DstPort: 2404, Proto: 6, Transport: "tcp",
			TCP: capture.TCPMeta{Valid: true, Seq: 1000, Flags: capture.TCPFlagSYN}},
		{SrcIP: serverIP, DstIP: clientIP, SrcPort: 2404, DstPort: 40000, Proto: 6, Transport: "tcp",
			TCP: capture.TCPMeta{Valid: true, Seq: 5000, Ack: 1001, Flags: capture.TCPFlagSYN | capture.TCPFlagACK}},
		{SrcIP: clientIP, DstIP: serverIP, SrcPort: 40000, DstPort: 2404, Proto: 6, Transport: "tcp",
			TCP: capture.TCPMeta{Valid: true, Seq: 1001, Ack: 5001, Flags: capture.TCPFlagACK}},
	}
	for _, pkt := range packets {
		markHandshake(&pkt)
		if decision := e.handlePacket(pkt); decision.Action != capture.Accept {
			t.Fatalf("handshake packet decision = %+v, want Accept", decision)
		}
	}

	e.Reconfigure(engineWithCapture(t, &blockingCapture{}))
	if got := len(injector.Resets()); got != 2 {
		t.Fatalf("queue shutdown reset attempts = %d, want both endpoints reset", got)
	}
	if !injector.Closed() {
		t.Fatal("old reset injector was not closed after the queued resets ran")
	}
}
