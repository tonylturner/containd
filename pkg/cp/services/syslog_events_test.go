// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

func manualEventSyslog(t *testing.T, feeds map[evidence.Source]dpevents.FeedReader, cfg config.SyslogConfig) *SyslogManager {
	t.Helper()
	m := NewSyslogManager()
	m.log = zap.NewNop().Sugar()
	m.SetEventFeeds(feeds)
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	t.Cleanup(m.Stop)
	return m
}

func eventLines(t *testing.T, lines <-chan string, count int) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for range count {
		select {
		case line := <-lines:
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(line, err)
			}
			out = append(out, row)
		case <-time.After(2 * time.Second):
			t.Fatal("missing forwarded event")
		}
	}
	return out
}

func TestSyslogIndependentSourcesAndBatches(t *testing.T) {
	port, lines := listenUDPLines(t)
	engine, services := dpevents.NewStore(32), dpevents.NewStoreWithIDBase(32, 1<<63)
	feeds := testEventFeeds(engine)
	feeds[evidence.SourceServices] = func(_ context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
		return services.ReadFeed(q), nil
	}
	cfg := forwarderConfig("json", "udp", port)
	cfg.BatchSize = 2
	m := manualEventSyslog(t, feeds, cfg)
	// Imported IDs and wall times deliberately run backwards.
	for i := range 5 {
		engine.Append(dpevents.Event{ID: uint64(100 - i), Kind: "engine", Timestamp: time.Unix(int64(100-i), 0)})
		services.Append(dpevents.Event{Kind: "service"})
	}
	for range 3 {
		m.flushEvents(context.Background())
	}
	rows := eventLines(t, lines, 10)
	count := map[string]int{}
	for _, row := range rows {
		count[row["source"].(string)]++
		if _, ok := row["id"].(string); !ok {
			t.Fatal("numeric identity", row)
		}
	}
	if count["engine"] != 5 || count["services"] != 5 {
		t.Fatal(count)
	}
	engine.Append(dpevents.Event{ID: 1, Kind: "low-engine"})
	m.flushEvents(context.Background())
	if got := eventLines(t, lines, 1)[0]; got["id"] != "1" || got["source"] != "engine" {
		t.Fatal(got)
	}
	for _, st := range m.ForwardStatus() {
		if st.Backlog != 0 || st.Lost != 0 {
			t.Fatal(st)
		}
	}
}

func TestSyslogRetentionOverflowAndPriority(t *testing.T) {
	port, lines := listenUDPLines(t)
	store := dpevents.NewStore(3)
	store.Append(dpevents.Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	m := manualEventSyslog(t, testEventFeeds(store), forwarderConfig("json", "udp", port))
	for range 6 {
		store.Append(dpevents.Event{Kind: "routine"})
	}
	m.flushEvents(context.Background())
	for _, r := range eventLines(t, lines, 3) {
		if r["kind"] != "routine" {
			t.Fatal(r)
		}
	}
	st := m.ForwardStatus()[0]
	if st.Lost != 3 || st.Backlog != 0 || st.SentThrough != "7" || st.State != evidence.StateRecovered {
		t.Fatal(st)
	}
	m.flushEvents(context.Background())
	if m.ForwardStatus()[0].Lost != 3 {
		t.Fatal("loss counted twice")
	}
}

func TestSyslogDestinationFailurePrefixRecoveryAndAudit(t *testing.T) {
	port, healthy := listenUDPLines(t)
	downPort := freeTCPPort(t)
	store := dpevents.NewStore(16)
	cfg := forwarderConfig("json", "udp", port)
	cfg.Forwarders = append(cfg.Forwarders, config.SyslogForwarder{Address: "127.0.0.1", Port: downPort, Proto: "tcp"})
	m := manualEventSyslog(t, testEventFeeds(store), cfg)
	log := openAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer log.Close()
	m.SetAuditLog(log)
	m.Stop()
	store.Append(dpevents.Event{ID: 5})
	store.Append(dpevents.Event{ID: 4})
	addAudit(t, log, auditAction("config.commit"))
	m.flushEvents(context.Background())
	m.flushAudit(context.Background())
	eventLines(t, healthy, 3)
	for _, st := range m.ForwardStatus() {
		if strings.HasPrefix(st.Destination, "tcp:") {
			if st.Backlog != 2 && st.Source == evidence.SourceEngine {
				t.Fatal(st)
			}
			if st.SentThrough != "0" || st.State != evidence.StateDegraded {
				t.Fatal("failed first record advanced prefix", st)
			}
		} else if st.Backlog != 0 {
			t.Fatal(st)
		}
	}
	_, recovered := listenTCPLines(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(downPort)))
	m.flushEvents(context.Background())
	m.flushAudit(context.Background())
	rows := eventLines(t, recovered, 3)
	// Each stream uses its own TCP connection. The collector's readers may
	// interleave audit and engine records even when the flushes are serial.
	var engineRows []map[string]any
	auditCount := 0
	for _, row := range rows {
		if row["kind"] == "audit" {
			auditCount++
			if row["action"] != "config.commit" {
				t.Fatal("unexpected audit record", row)
			}
			continue
		}
		if row["source"] != string(evidence.SourceEngine) {
			t.Fatal("unexpected source", row)
		}
		engineRows = append(engineRows, row)
	}
	if len(engineRows) != 2 || engineRows[0]["id"] != "5" || engineRows[0]["offset"] != "1" ||
		engineRows[1]["id"] != "4" || engineRows[1]["offset"] != "2" {
		t.Fatal("retry order changed", rows)
	}
	if auditCount != 1 {
		t.Fatal("missing recovered audit record", rows)
	}
	for _, st := range m.ForwardStatus() {
		if st.Backlog != 0 || st.LastError != "" || st.Lost != 0 {
			t.Fatal(st)
		}
	}
}

func TestSyslogSourceErrorRestartAndManagementRestart(t *testing.T) {
	port, lines := listenUDPLines(t)
	var mu sync.Mutex
	store := dpevents.NewStore(8)
	var sourceErr error
	read := func(_ context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
		mu.Lock()
		defer mu.Unlock()
		if sourceErr != nil {
			return dpevents.FeedPage{}, sourceErr
		}
		return store.ReadFeed(q), nil
	}
	feeds := map[evidence.Source]dpevents.FeedReader{evidence.SourceEngine: read}
	cfg := forwarderConfig("json", "udp", port)
	m := manualEventSyslog(t, feeds, cfg)
	store.Append(dpevents.Event{ID: 1})
	m.flushEvents(context.Background())
	eventLines(t, lines, 1)
	sourceErr = errors.New("private network detail")
	store.Append(dpevents.Event{ID: 2})
	m.flushEvents(context.Background())
	if st := m.ForwardStatus()[0]; st.State != evidence.StateDegraded || st.SentThrough != "1" || st.LastError != "source unavailable" {
		t.Fatal(st)
	}
	sourceErr = nil
	m.flushEvents(context.Background())
	eventLines(t, lines, 1)
	if st := m.ForwardStatus()[0]; st.State != evidence.StateRecovered || st.LastError != "" {
		t.Fatal(st)
	}
	oldEpoch := store.ReadFeed(dpevents.FeedRequest{TailOnly: true}).Epoch
	store = dpevents.NewStore(8)
	// A busy replacement can already have IDs above the old run.
	for i := range 5 {
		store.Append(dpevents.Event{ID: uint64(100 + i)})
	}
	m.flushEvents(context.Background())
	rows := eventLines(t, lines, 5)
	if rows[0]["epoch"] == oldEpoch || rows[0]["id"] != "100" {
		t.Fatal(rows)
	}
	if st := m.ForwardStatus()[0]; st.State != evidence.StateDegraded || !strings.Contains(st.LastError, "continuity unknown") {
		t.Fatal(st)
	}
	m.flushEvents(context.Background())
	if st := m.ForwardStatus()[0]; st.State != evidence.StateRecovered {
		t.Fatal(st)
	}
	// Management has volatile progress: after restart its configured targets
	// establish fresh tails, deliberately neither duplicating nor backfilling.
	restarted := manualEventSyslog(t, feeds, cfg)
	restarted.flushEvents(context.Background())
	if st := restarted.ForwardStatus()[0]; st.SentThrough != "5" || st.Backlog != 0 {
		t.Fatal(st)
	}
	store.Append(dpevents.Event{ID: 200})
	restarted.flushEvents(context.Background())
	if row := eventLines(t, lines, 1)[0]; row["id"] != "200" {
		t.Fatal(row)
	}
}

func TestSyslogTargetLifecycleAndFormat(t *testing.T) {
	port, first := listenUDPLines(t)
	secondPort, second := listenUDPLines(t)
	store := dpevents.NewStore(16)
	store.Append(dpevents.Event{ID: 1, Kind: "before-add"})
	cfg := forwarderConfig("json", "udp", port)
	m := manualEventSyslog(t, testEventFeeds(store), cfg)
	store.Append(dpevents.Event{ID: 2})
	m.flushEvents(context.Background())
	eventLines(t, first, 1)
	store.Append(dpevents.Event{ID: 3})
	cfg.Forwarders = append(cfg.Forwarders, config.SyslogForwarder{Address: "127.0.0.1", Port: secondPort, Proto: "udp"})
	cfg.Format = "rfc5424"
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	m.flushEvents(context.Background())
	select {
	case line := <-first:
		if !strings.Contains(line, `id="3" source="engine"`) {
			t.Fatal(line)
		}
	case <-time.After(time.Second):
		t.Fatal("format change lost retained progress")
	}
	if len(m.ForwardStatus()) != 2 || m.ForwardStatus()[1].SentThrough != "3" {
		t.Fatal(m.ForwardStatus())
	}
	cfg.Forwarders = cfg.Forwarders[1:]
	cfg.Format = "json"
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	store.Append(dpevents.Event{ID: 4})
	m.flushEvents(context.Background())
	if row := eventLines(t, second, 1)[0]; row["id"] != "4" {
		t.Fatal("new destination backfilled", row)
	}
	if len(m.ForwardStatus()) != 1 {
		t.Fatal("removed destination retained")
	}
}

func TestSyslogNoSelfFeedback(t *testing.T) {
	port, lines := listenUDPLines(t)
	manager := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	manager.SetEventFeeds(map[evidence.Source]dpevents.FeedReader{evidence.SourceServices: manager.ReadTelemetryFeed})
	m := manager.Syslog
	defer m.Stop()
	if err := m.Apply(context.Background(), forwarderConfig("json", "udp", port)); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	manager.recordServiceEvent("service.dns.query", nil)
	before, _ := manager.ReadTelemetryFeed(context.Background(), dpevents.FeedRequest{TailOnly: true})
	m.flushEvents(context.Background())
	eventLines(t, lines, 1)
	for range 3 {
		m.flushEvents(context.Background())
	}
	after, _ := manager.ReadTelemetryFeed(context.Background(), dpevents.FeedRequest{TailOnly: true})
	if before.Tail != after.Tail || manager.ForwardStatus()[0].Backlog != 0 {
		t.Fatalf("forwarding generated input: %d -> %d", before.Tail, after.Tail)
	}
}

func TestSyslogRFC5424ExactIdentityAndEscaping(t *testing.T) {
	m := NewSyslogManager()
	line, err := m.formatSourceEvent(dpevents.Event{ID: 1<<63 + 1, Kind: "a\"\\]\nb", Timestamp: time.Now()}, "rfc5424", evidence.SourceEngine, "run", 3)
	if err != nil || !strings.Contains(line, `id="9223372036854775809" source="engine" epoch="run" offset="3" kind="a\"\\\]\nb"`) || strings.Contains(line, "\n") {
		t.Fatal(line)
	}
}

func TestSyslogStopApplyJoinBlockedWrite(t *testing.T) {
	for _, action := range []string{"stop", "apply"} {
		t.Run(action, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			store := dpevents.NewStore(8)
			m := NewSyslogManager()
			defer m.Stop()
			m.SetEventFeeds(testEventFeeds(store))
			cfg := forwarderConfig("json", "tcp", ln.Addr().(*net.TCPAddr).Port)
			if err := m.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			store.Append(dpevents.Event{Attributes: map[string]any{"data": strings.Repeat("x", 16<<20)}})
			select {
			case conn := <-accepted:
				defer conn.Close() // deliberately never read
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not write")
			}
			start := time.Now()
			if action == "stop" {
				m.Stop()
			} else if err := m.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("cancellation did not interrupt the write and join")
			}
		})
	}
}

func TestSyslogBlockedSourceDoesNotDelayOtherBatchesOrAudit(t *testing.T) {
	port, lines := listenUDPLines(t)
	engine, services := dpevents.NewStore(8), dpevents.NewStore(8)
	feeds := testEventFeeds(engine)
	finished := make(chan struct{})
	var first sync.Once
	feeds[evidence.SourceServices] = func(ctx context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
		if q.TailOnly {
			return services.ReadFeed(q), nil
		}
		<-ctx.Done()
		first.Do(func() { close(finished) })
		return dpevents.FeedPage{}, ctx.Err()
	}
	cfg := forwarderConfig("json", "udp", port)
	cfg.BatchSize = 1
	log := openAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer log.Close()
	m := NewSyslogManager()
	defer m.Stop()
	m.SetEventFeeds(feeds)
	m.SetAuditLog(log)
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		engine.Append(dpevents.Event{Kind: "engine"})
	}
	addAudit(t, log, auditAction("first"), auditAction("second"))
	rows := eventLines(t, lines, 4)
	counts := map[string]int{}
	for _, row := range rows {
		counts[row["kind"].(string)]++
	}
	if counts["engine"] != 2 || counts["audit"] != 2 {
		t.Fatal(counts)
	}
	select {
	case <-finished:
		t.Fatal("healthy streams waited for the blocked source deadline")
	default:
	}
}

func TestSyslogSerializationLossIsCounted(t *testing.T) {
	port, lines := listenUDPLines(t)
	store := dpevents.NewStore(8)
	m := manualEventSyslog(t, testEventFeeds(store), forwarderConfig("json", "udp", port))
	store.Append(dpevents.Event{ID: 1, Attributes: map[string]any{"invalid": make(chan int)}})
	store.Append(dpevents.Event{ID: 2})
	m.flushEvents(context.Background())
	if row := eventLines(t, lines, 1)[0]; row["id"] != "2" {
		t.Fatal(row)
	}
	if st := m.ForwardStatus()[0]; st.Lost != 1 || st.SentThrough != "2" || st.Backlog != 0 || st.State != evidence.StateDegraded {
		t.Fatal(st)
	}
}
