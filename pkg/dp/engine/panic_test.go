// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// panicDecoder panics on every packet.
type panicDecoder struct{}

func (panicDecoder) Supports(*flow.State) bool { return true }
func (panicDecoder) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	panic("decoder bug")
}
func (panicDecoder) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }

func TestCaptureHandlerRecoversPanics(t *testing.T) {
	var logged []string
	e, err := New(Config{DPIEnabled: true, InspectAll: true, OnError: func(err error) { logged = append(logged, err.Error()) }})
	if err != nil {
		t.Fatal(err)
	}
	e.dpiMgr = dpi.NewManager(panicDecoder{})
	pkt := capture.Packet{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 502,
		Proto: 6, Transport: "tcp", Payload: []byte{1, 2, 3}, TCP: capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK}}
	if d := e.capturePacket(pkt); d.Action != capture.Accept {
		t.Fatalf("panic on an unmarked packet = %+v, want Accept", d)
	}
	pkt.HasMark, pkt.Mark, pkt.SrcPort = true, enforce.EnvelopeMark, 40001
	if d := e.capturePacket(pkt); d.Action != capture.Drop {
		t.Fatalf("panic on an envelope-marked packet = %+v, want Drop", d)
	}
	if len(logged) != 2 || !strings.Contains(logged[0], "decoder bug") {
		t.Fatalf("logged = %v", logged)
	}
	e.iec.health.clear(faultInjector)
	e.LoadRules(iecSnapshot("enforce"))
	if st := e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "panic") {
		t.Fatalf("health = %+v", st)
	}
}
