// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestHandlePacketAcceptsOnEveryExit pins the contract-commit behaviour:
// the handler returns Accept for the current packet, including after a DPI
// deny, which still acts only through the verdict cache and nft updater.
func TestHandlePacketAcceptsOnEveryExit(t *testing.T) {
	if got := (*Engine)(nil).handlePacket(capture.Packet{}); got.Action != capture.Accept {
		t.Fatalf("nil engine decision = %+v", got)
	}

	up := &recordingUpdater{}
	cfg := Config{
		Capture:    capture.Config{Interfaces: []string{"lo"}},
		Enforce:    EnforceConfig{Enabled: true, Updater: up},
		DPIEnabled: true,
		DPIMode:    "enforce",
	}
	e, err := New(cfg)
	if err != nil {
		cfg.Capture.Interfaces = []string{"lo0"}
		e, err = New(cfg)
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	e.LoadRules(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{{
			ID:        "deny-write",
			Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}},
			Action:    rules.ActionDeny,
		}},
	})
	write := capture.Packet{
		Timestamp: time.Now().UTC(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   42000,
		DstPort:   502,
		Proto:     6,
		Transport: "tcp",
		// Modbus write single register (FC 6), unit 1, register 1 = 3.
		Payload: []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x03},
	}

	if got := e.handlePacket(write); got.Action != capture.Accept {
		t.Fatalf("denied write decision = %+v, want Accept", got)
	}
	if up.flowKey == "" {
		t.Fatal("expected the DPI deny to install a flow block")
	}
	if got := e.handlePacket(write); got.Action != capture.Accept {
		t.Fatalf("cached-deny decision = %+v, want Accept", got)
	}
}
