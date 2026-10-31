// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/common/metrics"
)

type failingWrites struct {
	ObservableStore
	err   error
	calls int
}

func (s *failingWrites) Add(context.Context, Record) error             { s.calls++; return s.err }
func (s *failingWrites) AddOnce(context.Context, string, Record) error { s.calls++; return s.err }

func observedSQLite(t *testing.T) (*ObservedStore, *SQLiteStore) {
	t.Helper()
	raw, err := NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return NewObservedStore(raw), raw
}

func TestAuditObservationFailureRecoveryRedaction(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	secret := "password=supersecret /private/audit.db -----BEGIN PRIVATE KEY-----"
	underlying := &failingWrites{err: errors.New(secret)}
	store := NewObservedStore(underlying)
	ctx := context.Background()
	if store.AuditStatus().State != evidence.StateOK {
		t.Fatal("opened store should be ok")
	}
	if err := store.Add(ctx, Record{Detail: secret}); !errors.Is(err, underlying.err) || strings.Contains(err.Error(), "supersecret") || !IsObservedFailure(err) {
		t.Fatalf("error matching or redaction lost: %v", err)
	}
	if err := store.AddOnce(ctx, secret, Record{Detail: secret}); err == nil {
		t.Fatal("lost AddOnce error")
	}
	status := store.AuditStatus()
	if status.State != evidence.StateDegraded || status.Failures != 2 || status.LastFailureAt == nil || store.Successes() != 0 {
		t.Fatalf("status: %+v", status)
	}
	if underlying.calls != 2 || strings.Count(logs.String(), "audit write failed") != 2 {
		t.Fatalf("recursive or duplicate logging: calls=%d logs=%s", underlying.calls, &logs)
	}
	if strings.Contains(logs.String(), "supersecret") || strings.Contains(status.LastError, "/private") || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("secret leaked")
	}
	underlying.err = nil
	if err := store.Add(ctx, Record{}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddOnce(ctx, "key", Record{}); err != nil {
		t.Fatal(err)
	}
	recovered := store.AuditStatus()
	if recovered.State != evidence.StateRecovered || recovered.Failures != 2 || recovered.LastSuccessAt == nil || store.Successes() != 2 {
		t.Fatalf("recovered: %+v", recovered)
	}
	*status.LastFailureAt = recovered.LastSuccessAt.AddDate(-1, 0, 0)
	if store.AuditStatus().LastFailureAt.Equal(*status.LastFailureAt) {
		t.Fatal("snapshot aliases internal state")
	}
}

func TestAuditObservationRealFailures(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-only", true: "closed"}[closed], func(t *testing.T) {
			store, raw := observedSQLite(t)
			if closed {
				if err := raw.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := raw.db.Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Add(context.Background(), Record{}); err == nil {
				t.Fatal("write succeeded")
			}
			if err := store.AddOnce(context.Background(), "key", Record{}); err == nil {
				t.Fatal("AddOnce succeeded")
			}
			if s := store.AuditStatus(); s.Failures != 2 || s.State != evidence.StateDegraded {
				t.Fatalf("%+v", s)
			}
			if !closed {
				if _, err := raw.db.Exec("PRAGMA query_only=OFF"); err != nil {
					t.Fatal(err)
				}
				if err := store.Add(context.Background(), Record{}); err != nil {
					t.Fatal(err)
				}
				if store.AuditStatus().State != evidence.StateRecovered {
					t.Fatal("not recovered")
				}
			}
		})
	}
}

func TestAuditObservationConcurrentAdd(t *testing.T) {
	store, _ := observedSQLite(t)
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if err := store.Add(context.Background(), Record{Action: "test"}); err != nil {
				t.Error(err)
			}
			_ = store.AuditStatus()
		})
	}
	wg.Wait()
	if store.Successes() != 24 || store.AuditStatus().Failures != 0 {
		t.Fatal("incorrect concurrent counters")
	}
}

func TestAuditObservationCapabilitiesAndReset(t *testing.T) {
	store, _ := observedSQLite(t)
	ctx := context.Background()
	if err := store.AddOnce(ctx, "once", Record{Action: "once"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddOnce(ctx, "once", Record{Action: "once"}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListAfter(ctx, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if err := store.StartForwardCursor(ctx, "syslog:test"); err != nil {
		t.Fatal(err)
	}
	if err := store.WipeAll(ctx); err != nil {
		t.Fatal(err)
	}
	cursor, ok, err := store.ForwardCursor(ctx, "syslog:test")
	if err != nil || !ok || cursor != 0 {
		t.Fatalf("cursor=%d ok=%v err=%v", cursor, ok, err)
	}
	if err := store.Add(ctx, Record{Action: "after reset"}); err != nil {
		t.Fatal(err)
	}
	rows, err = store.ListAfter(ctx, cursor, 10)
	if err != nil || len(rows) != 1 || rows[0].Action != "after reset" {
		t.Fatalf("%v %v", rows, err)
	}
	if err := store.AdvanceForwardCursor(ctx, "syslog:test", rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CountAfter(ctx, rows[0].ID); err != nil || n != 0 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	if err := store.RetainForwardCursors(ctx, "syslog:", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.ForwardCursor(ctx, "syslog:test"); err != nil || ok {
		t.Fatalf("cursor retained: %v %v", ok, err)
	}
}

func TestAuditWriteSurvivesCancellation(t *testing.T) {
	store, _ := observedSQLite(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Write(ctx, store, Record{Action: "completed"})
	if store.Successes() != 1 {
		t.Fatal("client canceled completed operation's audit")
	}
	if err := store.Add(ctx, Record{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Add must retain caller context: %v", err)
	}
	if store.AuditStatus().State != evidence.StateDegraded {
		t.Fatal("canceled write not observed")
	}
}

func TestAuditWriteLogsObservedFailureOnlyOnce(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	backend := &failingWrites{err: errors.New("password=secret")}
	store := NewObservedStore(backend)
	Write(context.Background(), store, Record{})
	if backend.calls != 1 || store.AuditStatus().Failures != 1 || strings.Count(logs.String(), "audit write failed") != 1 || strings.Contains(logs.String(), "password=") {
		t.Fatalf("recursive/unsafe log: calls=%d log=%s", backend.calls, &logs)
	}
}

func TestAuditObservationMetrics(t *testing.T) {
	value := func(counter prometheus.Counter) float64 {
		t.Helper()
		registry := prometheus.NewRegistry()
		registry.MustRegister(counter)
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		return families[0].Metric[0].GetCounter().GetValue()
	}
	failures, successes := value(metrics.AuditWriteFailuresTotal), value(metrics.AuditWriteSuccessesTotal)
	backend := &failingWrites{err: errors.New("failed")}
	store := NewObservedStore(backend)
	_ = store.Add(context.Background(), Record{})
	_ = store.AddOnce(context.Background(), "once", Record{})
	backend.err = nil
	_ = store.Add(context.Background(), Record{})
	if value(metrics.AuditWriteFailuresTotal)-failures != 2 || value(metrics.AuditWriteSuccessesTotal)-successes != 1 {
		t.Fatal("metrics do not count write attempts")
	}
}
