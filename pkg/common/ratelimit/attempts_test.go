// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ratelimit

import (
	"testing"
	"time"
)

func TestAllowInitialAttempt(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 5, 2*time.Minute)
	ok, retry := rl.Allow("user1")
	if !ok {
		t.Fatal("first attempt should be allowed")
	}
	if retry != 0 {
		t.Fatalf("retry should be 0, got %v", retry)
	}
}

func TestBlockAfterMaxAttempts(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 3, 2*time.Minute)
	key := "brute"
	for i := 0; i < 3; i++ {
		rl.Fail(key)
	}
	ok, retry := rl.Allow(key)
	if ok {
		t.Fatal("should be blocked after max attempts")
	}
	if retry <= 0 {
		t.Fatalf("retry-after should be positive, got %v", retry)
	}
}

func TestSuccessResetsCount(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 3, 2*time.Minute)
	key := "reset"
	rl.Fail(key)
	rl.Fail(key)
	rl.Success(key)

	// Should be allowed again after success
	ok, _ := rl.Allow(key)
	if !ok {
		t.Fatal("should be allowed after Success() resets counter")
	}

	// And we should be able to fail up to max again
	for i := 0; i < 3; i++ {
		rl.Fail(key)
	}
	ok, _ = rl.Allow(key)
	if ok {
		t.Fatal("should be blocked again after max failures")
	}
}

func TestDifferentKeysIndependent(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 2, 2*time.Minute)
	for i := 0; i < 2; i++ {
		rl.Fail("keyA")
	}
	ok, _ := rl.Allow("keyA")
	if ok {
		t.Fatal("keyA should be blocked")
	}

	ok, _ = rl.Allow("keyB")
	if !ok {
		t.Fatal("keyB should not be affected by keyA")
	}
}

func TestZeroConfigAlwaysAllows(t *testing.T) {
	rl := NewAttemptLimiter(0, 0, 0)
	for i := 0; i < 100; i++ {
		rl.Fail("key")
	}
	ok, _ := rl.Allow("key")
	if !ok {
		t.Fatal("zero config should always allow")
	}
}

func TestFailCountsIncrementally(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 5, time.Minute)
	key := "inc"

	// 4 fails should still be allowed
	for i := 0; i < 4; i++ {
		rl.Fail(key)
	}
	ok, _ := rl.Allow(key)
	if !ok {
		t.Fatal("should be allowed with 4 of 5 attempts used")
	}

	// 5th fail should trigger block
	rl.Fail(key)
	ok, _ = rl.Allow(key)
	if ok {
		t.Fatal("should be blocked after 5th fail")
	}
}

func TestBlockForDuration(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 1, 50*time.Millisecond)
	key := "dur"
	rl.Fail(key)

	ok, retry := rl.Allow(key)
	if ok {
		t.Fatal("should be blocked")
	}
	if retry > 50*time.Millisecond+10*time.Millisecond {
		t.Fatalf("retry should be ~50ms, got %v", retry)
	}
}

func TestGCRemovesStaleEntries(t *testing.T) {
	rl := NewAttemptLimiter(time.Minute, 5, time.Minute)
	rl.GCInterval = time.Nanosecond // force GC on every call

	rl.Fail("stale")

	// Manipulate lastSeen to simulate staleness and reset lastGCTime
	rl.mu.Lock()
	if st, ok := rl.m["stale"]; ok {
		st.lastSeen = time.Now().Add(-31 * time.Minute)
	}
	rl.lastGCTime = time.Time{} // reset so GC runs again
	rl.mu.Unlock()

	// Next Allow triggers GC
	rl.Allow("fresh")

	rl.mu.Lock()
	_, exists := rl.m["stale"]
	rl.mu.Unlock()

	if exists {
		t.Fatal("stale entry should have been garbage collected")
	}
}
