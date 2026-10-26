// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// syncUpdater records dynamic blocks from the block worker goroutine.
type syncUpdater struct {
	mu    sync.Mutex
	flows []string
	err   error
	done  chan struct{}
}

func newSyncUpdater() *syncUpdater { return &syncUpdater{done: make(chan struct{}, 16)} }

func (u *syncUpdater) BlockHostTemp(context.Context, net.IP, time.Duration) error { return nil }

func (u *syncUpdater) BlockFlowTemp(_ context.Context, src, dst net.IP, proto, dport string, _ time.Duration) error {
	u.mu.Lock()
	u.flows = append(u.flows, src.String()+"->"+dst.String()+"/"+proto+":"+dport)
	err := u.err
	u.mu.Unlock()
	u.done <- struct{}{}
	return err
}

func (u *syncUpdater) blocked() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.flows...)
}

// idleCapture is a capture runner whose Start returns at once.
type idleCapture struct{}

func (idleCapture) Start(context.Context, capture.Handler) error { return nil }
func (idleCapture) Stop()                                        {}
func (idleCapture) Interfaces() []string                         { return nil }
func (idleCapture) Settler() capture.Settler                     { return nil }

func modbusDenyEngine(t *testing.T, up *syncUpdater) *Engine {
	t.Helper()
	e, err := New(Config{
		Enforce:    EnforceConfig{Enabled: true, Updater: up},
		DPIEnabled: true,
		DPIMode:    "enforce",
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	e.capture = idleCapture{}
	e.LoadRules(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{{
			ID:        "deny-write",
			Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}},
			Action:    rules.ActionDeny,
		}},
	})
	return e
}

func modbusWritePacket(tok capture.Token) capture.Packet {
	return capture.Packet{
		Timestamp: time.Now().UTC(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   42000,
		DstPort:   502,
		Proto:     6,
		Transport: "tcp",
		TCP:       capture.TCPMeta{Valid: true, Seq: 1000, Ack: 1, Flags: capture.TCPFlagACK | capture.TCPFlagPSH},
		Token:     tok,
		// Modbus write single register (FC 6), unit 1, register 1 = 3.
		Payload: []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x03},
	}
}

func waitBlock(t *testing.T, up *syncUpdater) {
	t.Helper()
	select {
	case <-up.done:
	case <-time.After(2 * time.Second):
		t.Fatal("dynamic block was not installed")
	}
}

// TestDeniedModbusWriteDropsCurrentPacket pins US change #1: the first
// complete denied write is dropped, the dynamic block is installed only
// after the drop verdict completes, and a cached denial drops later packets.
func TestDeniedModbusWriteDropsCurrentPacket(t *testing.T) {
	if got := (*Engine)(nil).handlePacket(capture.Packet{}); got.Action != capture.Accept {
		t.Fatalf("nil engine decision = %+v", got)
	}
	up := newSyncUpdater()
	e := modbusDenyEngine(t, up)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// The connection is seen from its SYN; a stream picked up
	// mid-connection fails closed without a flow block.
	syn := modbusWritePacket(capture.NewToken(1, 6))
	syn.Payload, syn.TCP.Seq, syn.TCP.Flags = nil, 999, capture.TCPFlagSYN
	markHandshake(&syn)
	if got := e.handlePacket(syn); got.Action != capture.Accept {
		t.Fatalf("SYN decision = %+v, want Accept", got)
	}
	tok := capture.NewToken(1, 7)
	if got := e.handlePacket(modbusWritePacket(tok)); got.Action != capture.Drop {
		t.Fatalf("denied write decision = %+v, want Drop", got)
	}
	time.Sleep(20 * time.Millisecond)
	if len(up.blocked()) != 0 {
		t.Fatal("dynamic block ran before the drop verdict completed")
	}
	e.hooks.onVerdict(tok, capture.VerdictDrop, nil)
	waitBlock(t, up)
	if got := up.blocked(); len(got) != 1 || got[0] != "10.0.0.1->10.0.0.2/tcp:502" {
		t.Fatalf("blocks = %v", got)
	}

	retry := modbusWritePacket(capture.NewToken(1, 8))
	retry.TCP.Seq = 1012
	if got := e.handlePacket(retry); got.Action != capture.Drop || got.Reason != reasonCachedDeny {
		t.Fatalf("cached-deny decision = %+v, want Drop", got)
	}
}

func TestUpdaterFailureKeepsDrop(t *testing.T) {
	up := newSyncUpdater()
	up.err = errors.New("nft: permission denied")
	e := modbusDenyEngine(t, up)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Not inline (observational source): the block is queued at once.
	if got := e.handlePacket(modbusWritePacket(capture.Token{})); got.Action != capture.Drop {
		t.Fatalf("decision = %+v, want Drop despite updater failure", got)
	}
	waitBlock(t, up)
}
