// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/common/metrics"
)

// ObservableStore is the persistence contract preserved by ObservedStore.
// Requiring the complete contract avoids advertising unsupported capabilities.
type ObservableStore interface {
	Store
	ForwardLog
	AddOnce(context.Context, string, Record) error
	WipeAll(context.Context) error
}

// ObservedStore observes writes without changing success or error matching.
// It never writes failure records recursively. Read, reset and forwarding
// operations are delegated.
// Counters describe attempts since process start, including deduplicated AddOnce.
type ObservedStore struct {
	ObservableStore
	mu        sync.Mutex
	status    evidence.AuditStatus
	successes uint64
}

var _ evidence.AuditReporter = (*ObservedStore)(nil)
var _ ObservableStore = (*ObservedStore)(nil)

// NewObservedStore wraps a successfully opened store. Initial health reflects
// that successful initialization; write failures and recovery remain historical
// until process restart, including across WipeAll.
func NewObservedStore(store ObservableStore) *ObservedStore {
	return &ObservedStore{ObservableStore: store, status: evidence.AuditStatus{State: evidence.StateOK}}
}

func (s *ObservedStore) Add(ctx context.Context, r Record) error {
	err := s.ObservableStore.Add(ctx, r)
	s.observe(err)
	return observedResult(err)
}

func (s *ObservedStore) AddOnce(ctx context.Context, key string, r Record) error {
	err := s.ObservableStore.AddOnce(ctx, key, r)
	s.observe(err)
	return observedResult(err)
}

func (s *ObservedStore) observe(err error) {
	s.mu.Lock()
	now := time.Now().UTC()
	if err != nil {
		s.status.Failures++
		metrics.AuditWriteFailuresTotal.Inc()
		s.status.LastFailureAt = &now
		s.status.LastError = writeError(err)
		s.status.State = evidence.StateDegraded
		s.mu.Unlock()
		logWriteFailure(err)
		return
	}
	s.successes++
	metrics.AuditWriteSuccessesTotal.Inc()
	s.status.LastSuccessAt = &now
	s.status.State = evidence.StateOK
	if s.status.Failures > 0 {
		s.status.State = evidence.StateRecovered
	}
	s.mu.Unlock()
}

// AuditStatus returns a detached snapshot; callers cannot mutate internal times.
func (s *ObservedStore) AuditStatus() evidence.AuditStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	if out.LastFailureAt != nil {
		t := *out.LastFailureAt
		out.LastFailureAt = &t
	}
	if out.LastSuccessAt != nil {
		t := *out.LastSuccessAt
		out.LastSuccessAt = &t
	}
	return out
}

// Successes counts successful write attempts, not necessarily inserted rows.
func (s *ObservedStore) Successes() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.successes
}

// Use a closed vocabulary: driver errors may contain paths, SQL, credentials or
// record payloads. Neither authenticated status nor local logs receive those.
func writeError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "audit write canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "audit write timed out"
	case errors.Is(err, sql.ErrConnDone):
		return "audit connection closed"
	default:
		return "audit persistence failed"
	}
}

func logWriteFailure(err error) { slog.Error("audit write failed", "error", writeError(err)) }

// Write records a completed operation independently of client cancellation,
// within a bounded budget. Persistence failure never implies mutation rollback.
// Retry-capable producers must use Add/AddOnce directly and retain their cursor.
func Write(ctx context.Context, store Store, r Record) {
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if err := store.Add(ctx, r); err != nil {
		if !IsObservedFailure(err) {
			logWriteFailure(err)
		}
	}
}

// observedFailure preserves error matching while preventing downstream logging
// from disclosing a driver's raw message.
type observedFailure struct{ cause error }

func (e *observedFailure) Error() string { return writeError(e.cause) }
func (e *observedFailure) Unwrap() error { return e.cause }
func observedResult(err error) error {
	if err == nil {
		return nil
	}
	return &observedFailure{cause: err}
}

// IsObservedFailure identifies a persistence error already counted and logged.
func IsObservedFailure(err error) bool {
	var failure *observedFailure
	return errors.As(err, &failure)
}
