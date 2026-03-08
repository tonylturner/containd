// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func TestVerdictCachePutGet(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 100)

	v := verdict.Verdict{Action: verdict.AllowContinue, Reason: "test"}
	vc.Put("flow1", v)

	got, ok := vc.Get("flow1")
	if !ok {
		t.Fatal("expected cache hit for flow1")
	}
	if got.Action != verdict.AllowContinue || got.Reason != "test" {
		t.Fatalf("unexpected verdict: %+v", got)
	}
}

func TestVerdictCacheMiss(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 100)

	_, ok := vc.Get("nonexistent")
	if ok {
		t.Fatal("expected cache miss for nonexistent key")
	}
}

func TestVerdictCacheExpiry(t *testing.T) {
	// Use a very short TTL so entries expire immediately.
	vc := NewVerdictCache(1*time.Millisecond, 100)

	vc.Put("flow1", verdict.Verdict{Action: verdict.DenyDrop})
	time.Sleep(5 * time.Millisecond)

	_, ok := vc.Get("flow1")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestVerdictCacheInvalidate(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 100)

	vc.Put("flow1", verdict.Verdict{Action: verdict.AllowContinue})
	vc.Invalidate("flow1")

	_, ok := vc.Get("flow1")
	if ok {
		t.Fatal("expected cache miss after invalidation")
	}
}

func TestVerdictCacheFlush(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 100)

	vc.Put("flow1", verdict.Verdict{Action: verdict.AllowContinue})
	vc.Put("flow2", verdict.Verdict{Action: verdict.DenyDrop})

	if vc.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", vc.Len())
	}

	vc.Flush()
	if vc.Len() != 0 {
		t.Fatalf("expected 0 entries after flush, got %d", vc.Len())
	}
}

func TestVerdictCacheEvictsAtCapacity(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 4)

	for i := 0; i < 10; i++ {
		vc.Put("flow"+string(rune('a'+i)), verdict.Verdict{Action: verdict.AllowContinue})
	}

	// After inserting 10 items into a cache with max 4, we should have
	// at most 4 entries.
	if vc.Len() > 4 {
		t.Fatalf("expected at most 4 entries, got %d", vc.Len())
	}
}

func TestVerdictCacheOverwrite(t *testing.T) {
	vc := NewVerdictCache(5*time.Second, 100)

	vc.Put("flow1", verdict.Verdict{Action: verdict.AllowContinue, Reason: "first"})
	vc.Put("flow1", verdict.Verdict{Action: verdict.DenyDrop, Reason: "second"})

	got, ok := vc.Get("flow1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Action != verdict.DenyDrop || got.Reason != "second" {
		t.Fatalf("expected overwritten verdict, got %+v", got)
	}
}
