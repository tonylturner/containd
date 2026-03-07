// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// VerdictCache stores per-flow verdicts so that subsequent packets for the
// same flow bypass full re-inspection. This is critical for NFQUEUE mode
// where every packet is held in the kernel until userspace renders a verdict.
type VerdictCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedVerdict
	ttl     time.Duration
	maxSize int
}

type cachedVerdict struct {
	verdict   verdict.Verdict
	createdAt time.Time
}

// NewVerdictCache creates a verdict cache with the given TTL and max entries.
func NewVerdictCache(ttl time.Duration, maxSize int) *VerdictCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if maxSize <= 0 {
		maxSize = 65536
	}
	return &VerdictCache{
		entries: make(map[string]*cachedVerdict, 256),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Get retrieves a cached verdict for the given flow hash.
// Returns the verdict and true if found and not expired, or a zero verdict and false.
func (vc *VerdictCache) Get(flowHash string) (verdict.Verdict, bool) {
	vc.mu.RLock()
	entry, ok := vc.entries[flowHash]
	if !ok {
		vc.mu.RUnlock()
		metrics.VerdictCacheMisses.Inc()
		return verdict.Verdict{}, false
	}
	v := entry.verdict
	expired := time.Since(entry.createdAt) > vc.ttl
	vc.mu.RUnlock()
	if expired {
		// Lazy eviction — don't bother locking for write here;
		// the next Put or evictExpiredLocked will clean it up.
		metrics.VerdictCacheMisses.Inc()
		return verdict.Verdict{}, false
	}
	metrics.VerdictCacheHits.Inc()
	return v, true
}

// Put stores a verdict for the given flow hash.
func (vc *VerdictCache) Put(flowHash string, v verdict.Verdict) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	// Evict expired entries if we are at capacity.
	if len(vc.entries) >= vc.maxSize {
		vc.evictExpiredLocked()
	}
	// If still at capacity after eviction, remove oldest entries.
	if len(vc.entries) >= vc.maxSize {
		count := 0
		for k := range vc.entries {
			delete(vc.entries, k)
			count++
			if count >= vc.maxSize/4 {
				break
			}
		}
	}
	vc.entries[flowHash] = &cachedVerdict{
		verdict:   v,
		createdAt: time.Now(),
	}
}

// Invalidate removes a specific flow's cached verdict.
func (vc *VerdictCache) Invalidate(flowHash string) {
	vc.mu.Lock()
	delete(vc.entries, flowHash)
	vc.mu.Unlock()
}

// Len returns the number of cached entries.
func (vc *VerdictCache) Len() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.entries)
}

// Flush removes all entries from the cache.
func (vc *VerdictCache) Flush() {
	vc.mu.Lock()
	vc.entries = make(map[string]*cachedVerdict, 256)
	vc.mu.Unlock()
}

func (vc *VerdictCache) evictExpiredLocked() {
	now := time.Now()
	for k, v := range vc.entries {
		if now.Sub(v.createdAt) > vc.ttl {
			delete(vc.entries, k)
		}
	}
}
