// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
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
