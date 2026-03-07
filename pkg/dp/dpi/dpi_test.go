// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

type mockDecoder struct {
	support bool
	calls   int
}

func (m *mockDecoder) Supports(state *flow.State) bool { return m.support }
func (m *mockDecoder) OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error) {
	m.calls++
	return []Event{{FlowID: state.Key.Hash(), Proto: "test", Kind: "pkt", Timestamp: time.Now()}}, nil
}
func (m *mockDecoder) OnFlowEnd(state *flow.State) ([]Event, error) { return nil, nil }

func TestManagerDispatch(t *testing.T) {
	d1 := &mockDecoder{support: true}
	d2 := &mockDecoder{support: false}
	mgr := NewManager(d1, d2)

	st := flow.NewState(flow.Key{}, time.Now())
	events, err := mgr.OnPacket(st, &ParsedPacket{Payload: []byte{1}})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || d1.calls != 1 || d2.calls != 0 {
		t.Fatalf("unexpected dispatch: events=%d d1=%d d2=%d", len(events), d1.calls, d2.calls)
	}
}

