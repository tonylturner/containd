// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

func TestSyslogManagerApply(t *testing.T) {
	m := NewSyslogManager()
	cfg := config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{
			{Address: "192.0.2.1", Port: 514, Proto: "udp"},
		},
	}
	if err := m.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}
	cur := m.Current()
	if len(cur.Forwarders) != 1 || cur.Forwarders[0].Address != "192.0.2.1" {
		t.Fatalf("unexpected forwarders: %+v", cur.Forwarders)
	}
}

func TestSyslogManagerApplyRejects(t *testing.T) {
	m := NewSyslogManager()
	cfg := config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{
			{Address: "", Port: 514},
		},
	}
	if err := m.Apply(context.Background(), cfg); err == nil {
		t.Fatalf("expected validation failure")
	}
}

// The forwarder keeps running after the applying request's context ends, and
// starts when the event lister arrives after the configuration (boot order).
func TestSyslogForwarderOutlivesApplyContext(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()
	defer mgr.Stop()
	applyCtx, cancel := context.WithCancel(context.Background())
	err = mgr.Apply(applyCtx, config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{{Address: "127.0.0.1", Port: conn.LocalAddr().(*net.UDPAddr).Port, Proto: "udp"}},
		Format:     "json",
		FlushEvery: 1,
	})
	cancel()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	store := dpevents.NewStore(8)
	mgr.SetEventFeeds(testEventFeeds(store))
	store.Append(dpevents.Event{ID: 1, Proto: "modbus", Kind: "service.modbus.read", Timestamp: time.Now().UTC()})

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no event forwarded after the apply context ended: %v", err)
	}
	if !strings.Contains(string(buf[:n]), `"kind":"service.modbus.read"`) {
		t.Fatalf("unexpected payload %s", buf[:n])
	}
}

// A re-apply rewrites the flush interval while the previous loop starts; the
// loop takes its interval as an argument (checked under -race).
func TestSyslogReapplyWhileForwarderStarts(t *testing.T) {
	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()
	defer mgr.Stop()
	mgr.SetEventFeeds(testEventFeeds(dpevents.NewStore(8)))
	cfg := config.SyslogConfig{Forwarders: []config.SyslogForwarder{{Address: "127.0.0.1", Port: 514, Proto: "udp"}}}
	for range 20 {
		if err := mgr.Apply(context.Background(), cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
}

// A flush formats its events with the format read with its forwarders, while
// a concurrent Apply rewrites the configuration (checked under -race).
func TestSyslogFlushWhileFormatChanges(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()
	defer mgr.Stop()
	store := dpevents.NewStore(128)
	mgr.SetEventFeeds(testEventFeeds(store))
	cfg := func(format string) config.SyslogConfig {
		return config.SyslogConfig{Forwarders: []config.SyslogForwarder{{Address: "127.0.0.1", Port: port, Proto: "udp"}}, Format: format}
	}
	if err := mgr.Apply(context.Background(), cfg("json")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			format := "json"
			if i%2 == 0 {
				format = "rfc5424"
			}
			if err := mgr.Apply(context.Background(), cfg(format)); err != nil {
				t.Errorf("Apply: %v", err)
				return
			}
		}
	}()
	for range 50 {
		store.Append(dpevents.Event{Kind: "service.modbus.read", Timestamp: time.Now()})
		mgr.flushEvents(context.Background())
	}
	<-done
}

func TestSyslogEndpoint(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		port uint16
		want string
	}{
		{"192.0.2.1", 502, "192.0.2.1:502"},
		{"192.0.2.1", 0, "192.0.2.1"},
		{"2001:db8::1", 2404, "[2001:db8::1]:2404"},
		{"2001:db8::1", 0, "2001:db8::1"},
	} {
		if got := syslogEndpoint(tc.ip, tc.port); got != tc.want {
			t.Errorf("syslogEndpoint(%q, %d) = %q, want %q", tc.ip, tc.port, got, tc.want)
		}
	}
}

func TestSyslogRFC5424ICMPHasNoPorts(t *testing.T) {
	mgr := NewSyslogManager()
	ev := dpevents.Event{
		Kind:      "firewall.rule.hit",
		Timestamp: time.Date(2026, 3, 13, 15, 0, 0, 0, time.UTC),
		SrcIP:     "2001:db8::1",
		DstIP:     "2001:db8::2",
		Transport: "icmpv6",
	}
	line, err := mgr.formatSourceEvent(ev, "rfc5424", evidence.SourceEngine, "epoch", 1)
	if err != nil || !strings.Contains(line, `src="2001:db8::1"`) || !strings.Contains(line, `dst="2001:db8::2"`) {
		t.Fatalf("ICMPv6 event endpoints carry a port: %s", line)
	}
}

func testEventFeeds(store *dpevents.Store) map[evidence.Source]dpevents.FeedReader {
	return map[evidence.Source]dpevents.FeedReader{evidence.SourceEngine: func(_ context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
		return store.ReadFeed(q), nil
	}}
}
