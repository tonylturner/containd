// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package dpi

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

type flowEndDecoder struct {
	err   error
	calls int
	event Event
}

func (*flowEndDecoder) Supports(*flow.State) bool { return true }

func (*flowEndDecoder) OnPacket(*flow.State, *ParsedPacket) ([]Event, error) {
	return nil, nil
}

func (d *flowEndDecoder) OnFlowEnd(*flow.State) ([]Event, error) {
	d.calls++
	return []Event{d.event}, d.err
}

func TestFlowEndCollectsEventsAndErrors(t *testing.T) {
	tests := []struct {
		name         string
		errorIndices []int
	}{
		{name: "error_first", errorIndices: []int{0}},
		{name: "error_middle", errorIndices: []int{1}},
		{name: "error_last", errorIndices: []int{2}},
		{name: "errors_joined", errorIndices: []int{0, 1, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoders := make([]*flowEndDecoder, 3)
			wantErrors := make([]error, len(tt.errorIndices))
			for i := range decoders {
				decoders[i] = &flowEndDecoder{
					event: Event{Kind: fmt.Sprintf("decoder_%d", i)},
				}
			}
			for i, errorIndex := range tt.errorIndices {
				wantErrors[i] = fmt.Errorf("decoder %d failure", errorIndex)
				decoders[errorIndex].err = wantErrors[i]
			}

			manager := NewManager(decoders[0], decoders[1], decoders[2])
			events, err := manager.OnFlowEnd(flow.NewState(flow.Key{}, time.Now()))

			for _, wantErr := range wantErrors {
				if !errors.Is(err, wantErr) {
					t.Errorf("OnFlowEnd() error = %v, want it to contain %v", err, wantErr)
				}
			}
			if len(events) != len(decoders) {
				t.Fatalf("OnFlowEnd() returned %d events, want %d", len(events), len(decoders))
			}
			for i, decoder := range decoders {
				if decoder.calls != 1 {
					t.Errorf("decoder %d called %d times, want once", i, decoder.calls)
				}
				if events[i].Kind != decoder.event.Kind {
					t.Errorf("event %d kind = %q, want %q", i, events[i].Kind, decoder.event.Kind)
				}
			}
		})
	}
}
