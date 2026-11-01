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
}

func newSyncUpdater() *syncUpdater { return &syncUpdater{} }

func (u *syncUpdater) BlockHostTemp(context.Context, net.IP, time.Duration) error { return nil }

func (u *syncUpdater) BlockFlowTemp(_ context.Context, src, dst net.IP, proto, dport string, _ time.Duration) error {
	u.mu.Lock()
	u.flows = append(u.flows, src.String()+"->"+dst.String()+"/"+proto+":"+dport)
	err := u.err
	u.mu.Unlock()
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
		Enforce:    EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Updater: up},
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

// TestDeniedModbusWriteDropsCurrentPacket also pins follow-up ordering.
func TestDeniedModbusWriteDropsCurrentPacket(t *testing.T) {
	if got := (*Engine)(nil).handlePacket(capture.Packet{}); got.Action != capture.Accept {
		t.Fatalf("nil engine = %+v", got)
	}
	f := newResetFlow(t, 502)
	f.syn()
	pkt := f.segment(false, f.isn, 9000, ackPsh, modbusADU(1, 6, 1, 3))
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	if got := f.e.HandlePacket(pkt); got.Action != capture.Drop {
		t.Fatalf("denied write = %+v", got)
	}
	drainResetWorker(t, f.e)
	if len(f.inj.Resets()) != 0 {
		t.Fatal("reset before drop completion")
	}
	f.e.hooks.onVerdict(pkt.Token, capture.VerdictDrop, nil)
	f.waitResets(2)
	if got := f.handle(pkt); got.Action != capture.Drop {
		t.Fatalf("retransmit = %+v", got)
	}
	if len(f.up.calls) != 0 {
		t.Fatal("DPI installed block")
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
	// Not inline: no reset and no block, even with a failing updater.
	if got := e.handlePacket(modbusWritePacket(capture.Token{})); got.Action != capture.Drop {
		t.Fatalf("decision = %+v, want Drop despite updater failure", got)
	}
	drainResetWorker(t, e)
	if len(up.blocked()) != 0 {
		t.Fatal("DPI called updater")
	}
}
