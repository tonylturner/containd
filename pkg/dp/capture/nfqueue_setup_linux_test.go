// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNFQueueModeCanceledSetup(t *testing.T) {
	// Cancellation before binding is deterministic and needs neither a real
	// queue nor capabilities. A missing interface must not affect NFQUEUE.
	mgr, err := NewManager(Config{
		Mode: "nfqueue", QueueID: 100, Interfaces: []string{"no-such-capture-interface"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, func(Packet) Decision {
			t.Error("canceled capture delivered a packet")
			return Decision{Action: Accept}
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled NFQUEUE setup did not return")
	}
	if mgr.started || mgr.comp != nil || mgr.cancel != nil {
		t.Fatal("failed Start left capture resources running")
	}
}
