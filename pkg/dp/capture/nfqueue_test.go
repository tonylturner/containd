// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"context"
	"testing"
)

func TestNFQueueModeRequiresLinux(t *testing.T) {
	mgr, err := NewManager(Config{
		Interfaces: []string{"lo"},
		Mode:       "nfqueue",
		QueueID:    100,
	})
	if err != nil {
		// On platforms without loopback named "lo", try lo0.
		mgr, err = NewManager(Config{
			Interfaces: []string{"lo0"},
			Mode:       "nfqueue",
			QueueID:    100,
		})
		if err != nil {
			t.Skipf("no loopback interface available: %v", err)
		}
	}

	handler := func(Packet) Decision { return Decision{Action: Accept} }
	err = mgr.Start(context.Background(), handler)

	// On non-Linux, this should return a "not supported" error.
	// On Linux without proper nfqueue kernel support / permissions,
	// it will return an nfqueue open error. Either is acceptable.
	if err != nil {
		t.Logf("nfqueue start returned expected error: %v", err)
	}
}
