// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/events"
)

func TestStartNFLogUnavailableOnNonLinux(t *testing.T) {
	stop, err := StartNFLog(context.Background(), 100, events.NewStore(1), nil)
	if err == nil || !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("StartNFLog error = %v, want linux-unavailable error", err)
	}
	if stop == nil {
		t.Fatal("StartNFLog returned nil stop function")
	}
	stop()
}

func TestStartNFLogNonLinuxNoOpWhenDisabled(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group uint16
		sink  RuleHitSink
	}{
		{name: "zero group", group: 0, sink: events.NewStore(1)},
		{name: "nil sink", group: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop, err := StartNFLog(context.Background(), tc.group, tc.sink, nil)
			if err != nil {
				t.Fatalf("StartNFLog: %v", err)
			}
			if stop == nil {
				t.Fatal("StartNFLog returned nil stop function")
			}
			stop()
		})
	}
}
