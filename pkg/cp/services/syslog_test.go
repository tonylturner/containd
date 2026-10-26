// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

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
	mgr.SetEventLister(func(int) []dpevents.Event {
		return []dpevents.Event{{ID: 1, Proto: "modbus", Kind: "service.modbus.read", Timestamp: time.Now().UTC()}}
	})

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
