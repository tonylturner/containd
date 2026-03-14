// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestShowNeighborsUnsupportedOnNonLinux(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := showNeighbors()(context.Background(), &buf, nil)
	if err == nil || !strings.Contains(err.Error(), "only supported on Linux") {
		t.Fatalf("expected linux-only error, got %v", err)
	}
}

func TestCaptureToPCAPUnsupportedOnNonLinux(t *testing.T) {
	t.Parallel()

	n, err := captureToPCAP(context.Background(), "eth0", 100*time.Millisecond, "/tmp/test.pcap")
	if err == nil || !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("expected linux-only error, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected zero packet count, got %d", n)
	}
}
