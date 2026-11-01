// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package capture

import (
	"context"
	"testing"
)

func TestNFQueueModeRequiresLinux(t *testing.T) {
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	err = mgr.Start(context.Background(), func(Packet) Decision { return Decision{Action: Accept} })
	if err == nil || err.Error() != "nfqueue capture is only supported on linux" {
		t.Fatalf("Start = %v, want Linux-only unsupported error", err)
	}
	if mgr.started || mgr.comp != nil || mgr.cancel != nil {
		t.Fatal("unsupported Start left capture resources running")
	}
}
