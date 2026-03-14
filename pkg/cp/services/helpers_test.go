// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHelpersAndQueue(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "fake-bin")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got, ok := detectBinary([]string{"", filepath.Join(tmp, "missing"), bin}); !ok || got != bin {
		t.Fatalf("detectBinary = %q, %v", got, ok)
	}
	if got, ok := detectBinary([]string{"", filepath.Join(tmp, "missing")}); ok || got != "" {
		t.Fatalf("detectBinary missing = %q, %v", got, ok)
	}
	if got := firstNonZero(3, 9); got != 3 {
		t.Fatalf("firstNonZero = %d", got)
	}
	if got := firstNonZero(0, 9); got != 9 {
		t.Fatalf("firstNonZero default = %d", got)
	}
	if got := formatMaybe(time.Time{}); got != "" {
		t.Fatalf("formatMaybe zero = %q", got)
	}
	if got := formatMaybe(time.Date(2026, 3, 13, 10, 0, 0, 0, time.UTC)); got == "" {
		t.Fatal("formatMaybe non-zero returned empty string")
	}
	if got := pidOrZero(nil); got != 0 {
		t.Fatalf("pidOrZero nil = %d", got)
	}
	if got := pidOrZero(&exec.Cmd{}); got != 0 {
		t.Fatalf("pidOrZero empty cmd = %d", got)
	}

	q := NewScanQueue(1)
	if q == nil || q.Len() != 0 {
		t.Fatalf("unexpected queue state: %#v len=%d", q, q.Len())
	}
	task := ScanTask{Hash: "flow-1"}
	if !q.Enqueue(task) {
		t.Fatal("expected enqueue to succeed")
	}
	if q.Enqueue(ScanTask{Hash: "flow-2"}) {
		t.Fatal("expected second enqueue to fail on full queue")
	}
	got, ok := q.Dequeue(10 * time.Millisecond)
	if !ok || got.Hash != "flow-1" {
		t.Fatalf("Dequeue = %#v, %v", got, ok)
	}
	if _, ok := q.Dequeue(5 * time.Millisecond); ok {
		t.Fatal("expected dequeue timeout on empty queue")
	}
}
