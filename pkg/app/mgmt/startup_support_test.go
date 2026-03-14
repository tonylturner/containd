// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/audit"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type testAuditStore struct {
	records []audit.Record
}

func (s *testAuditStore) Add(_ context.Context, r audit.Record) error {
	s.records = append(s.records, r)
	return nil
}
func (s *testAuditStore) List(context.Context, int, ...int) ([]audit.Record, error) {
	return s.records, nil
}
func (s *testAuditStore) Close() error { return nil }

type testEventLister struct {
	events []dpevents.Event
	err    error
}

func (l testEventLister) ListEvents(context.Context, int) ([]dpevents.Event, error) {
	return l.events, l.err
}

func TestStartupHintHelpers(t *testing.T) {
	t.Parallel()

	if got := portOf("0.0.0.0:8443"); got != "8443" {
		t.Fatalf("portOf = %q, want 8443", got)
	}
	if !bindsAll(":8080") || !bindsAll("0.0.0.0:8080") {
		t.Fatal("expected bindsAll to accept wildcard binds")
	}
	if !hostOnly("127.0.0.1:8080") || hostOnly(":8080") {
		t.Fatal("unexpected hostOnly result")
	}
	if !isRFC1918(net.ParseIP("10.10.10.10")) || isRFC1918(net.ParseIP("8.8.8.8")) {
		t.Fatal("unexpected isRFC1918 result")
	}
	if got := ipFromAddr(&net.IPNet{IP: net.ParseIP("192.168.1.4")}); got.String() != "192.168.1.4" {
		t.Fatalf("ipFromAddr = %v", got)
	}
}

func TestDHCPLeaseAuditHelpers(t *testing.T) {
	t.Parallel()

	store := &testAuditStore{}
	now := time.Now().UTC()
	events := []dpevents.Event{
		{ID: 10, Proto: "dhcp", Kind: "service.dhcp.lease.renewed", Timestamp: now, Attributes: map[string]any{"dev": "lan1", "ip": "192.168.1.10", "mac": "aa:bb:cc", "hostname": "plc1"}},
		{ID: 9, Proto: "dns", Kind: "query", Timestamp: now},
		{ID: 8, Proto: "dhcp", Kind: "service.dhcp.lease.created", Timestamp: now, Attributes: map[string]any{"dev": "lan2", "ip": "192.168.2.20", "mac": "dd:ee:ff"}},
	}

	if maxID := highestDHCPLeaseEventID(events); maxID != 10 {
		t.Fatalf("highestDHCPLeaseEventID = %d, want 10", maxID)
	}
	if !shouldAuditDHCPLeaseEvent(events[0], 7) {
		t.Fatal("expected dhcp lease event to be auditable")
	}
	if shouldAuditDHCPLeaseEvent(events[1], 0) {
		t.Fatal("expected non-dhcp event to be ignored")
	}

	lastID := ingestDHCPLeaseAuditEvents(store, events, 11)
	if lastID != 10 {
		t.Fatalf("lastID = %d, want 10 after restart reset", lastID)
	}
	if len(store.records) != 2 {
		t.Fatalf("records = %d, want 2", len(store.records))
	}
	if store.records[0].Source != "dhcp" || store.records[0].Action == "" || store.records[0].Target == "" {
		t.Fatalf("unexpected audit record: %+v", store.records[0])
	}

	record := dhcpLeaseAuditRecord(events[0])
	if record.Actor != "system" || record.Source != "dhcp" {
		t.Fatalf("unexpected dhcp lease audit record: %+v", record)
	}
}

func TestDHCPLeaseAuditTickAndFetch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	if waitDHCPLeaseAuditTick(ctx, ticker) {
		t.Fatal("expected canceled context to stop ticker wait")
	}

	lister := testEventLister{events: []dpevents.Event{{ID: 1}}}
	evs, err := fetchDHCPLeaseEvents(lister)
	if err != nil || len(evs) != 1 {
		t.Fatalf("fetchDHCPLeaseEvents = (%v, %v), want one event", evs, err)
	}

	if _, ok := dhcpLeaseEventLister(zap.NewNop().Sugar(), lister, &testAuditStore{}); !ok {
		t.Fatal("expected dhcpLeaseEventLister to accept compatible lister")
	}
	if _, ok := dhcpLeaseEventLister(nil, lister, &testAuditStore{}); ok {
		t.Fatal("expected dhcpLeaseEventLister to reject nil logger")
	}
}

func TestPickUIDirAndDirExists(t *testing.T) {
	tmp := t.TempDir()
	custom := filepath.Join(tmp, "ui")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatalf("mkdir custom ui dir: %v", err)
	}

	t.Setenv("CONTAIND_UI_DIR", custom)
	if got := pickUIDir(); got != custom {
		t.Fatalf("pickUIDir = %q, want %q", got, custom)
	}
	if !dirExists(custom) || dirExists(filepath.Join(tmp, "missing")) {
		t.Fatal("unexpected dirExists result")
	}
}
