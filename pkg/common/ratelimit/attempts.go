package ratelimit

import (
	"sync"
	"time"
)

// AttemptLimiter is a tiny in-memory rate limiter for authentication-style attempts.
// It is designed for per-process use (good enough for single-appliance deployments).
type AttemptLimiter struct {
	mu sync.Mutex
	m  map[string]*attemptState

	Window      time.Duration
	MaxAttempts int
	BlockFor    time.Duration
	GCInterval  time.Duration
	lastGCTime  time.Time
}

type attemptState struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

func NewAttemptLimiter(window time.Duration, maxAttempts int, blockFor time.Duration) *AttemptLimiter {
	return &AttemptLimiter{
		m:           map[string]*attemptState{},
		Window:      window,
		MaxAttempts: maxAttempts,
		BlockFor:    blockFor,
		GCInterval:  5 * time.Minute,
	}
}

// Allow returns whether the key can attempt now and, when blocked, a suggested retry-after duration.
func (l *AttemptLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked(now)

	st := l.getLocked(key, now)
	if !st.blockedUntil.IsZero() && now.Before(st.blockedUntil) {
		return false, time.Until(st.blockedUntil)
	}
	if l.Window <= 0 || l.MaxAttempts <= 0 {
		return true, 0
	}
	if st.windowStart.IsZero() || now.Sub(st.windowStart) > l.Window {
		st.windowStart = now
		st.count = 0
	}
	if st.count >= l.MaxAttempts {
		if l.BlockFor > 0 {
			st.blockedUntil = now.Add(l.BlockFor)
			return false, time.Until(st.blockedUntil)
		}
		return false, l.Window - now.Sub(st.windowStart)
	}
	return true, 0
}

func (l *AttemptLimiter) Fail(key string) {
	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.getLocked(key, now)
	if l.Window > 0 && (st.windowStart.IsZero() || now.Sub(st.windowStart) > l.Window) {
		st.windowStart = now
		st.count = 0
	}
	st.count++
	if l.MaxAttempts > 0 && st.count >= l.MaxAttempts && l.BlockFor > 0 {
		st.blockedUntil = now.Add(l.BlockFor)
	}
}

func (l *AttemptLimiter) Success(key string) {
	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.getLocked(key, now)
	st.count = 0
	st.blockedUntil = time.Time{}
	st.windowStart = time.Time{}
}

func (l *AttemptLimiter) getLocked(key string, now time.Time) *attemptState {
	if l.m == nil {
		l.m = map[string]*attemptState{}
	}
	st := l.m[key]
	if st == nil {
		st = &attemptState{}
		l.m[key] = st
	}
	st.lastSeen = now
	return st
}

func (l *AttemptLimiter) gcLocked(now time.Time) {
	if l.GCInterval <= 0 {
		return
	}
	if !l.lastGCTime.IsZero() && now.Sub(l.lastGCTime) < l.GCInterval {
		return
	}
	l.lastGCTime = now
	cutoff := now.Add(-30 * time.Minute)
	for k, st := range l.m {
		if st == nil {
			delete(l.m, k)
			continue
		}
		if st.lastSeen.Before(cutoff) {
			delete(l.m, k)
		}
	}
}
