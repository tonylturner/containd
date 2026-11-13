// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
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
	vc := NewVerdictCache(5*time.Second, 3)
	ledger := limits.NewLedger(nil)
	vc.ledger = ledger

	for i := 0; i < 40; i++ {
		vc.Put(fmt.Sprintf("flow-%02d", i), verdict.Verdict{Action: verdict.AllowContinue})
	}

	// Repeated high-cardinality insertion stays within the configured cap.
	if vc.Len() > 3 {
		t.Fatalf("expected at most 3 entries, got %d", vc.Len())
	}
	if o := vc.LimitOccupancy(); o.Limit != 3 || o.Entries != 3 || o.HighWater != 3 {
		t.Fatalf("cache occupancy %+v", o)
	}
	hits := ledger.Status(limits.TableVerdictCache, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Reason != limits.ReasonEvicted || hits[0].Mode != limits.ModeObserve || hits[0].Total != 37 {
		t.Fatalf("cache eviction ledger hits %+v", hits)
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
