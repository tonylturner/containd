// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// ICSMarker tags DPI events with ICS=true when they originate from ICS protocols.
type ICSMarker struct{}

func NewICSMarker() *ICSMarker { return &ICSMarker{} }

func (d *ICSMarker) Supports(state *flow.State) bool { return true }

func (d *ICSMarker) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}

func (d *ICSMarker) OnFlowEnd(state *flow.State) ([]dpi.Event, error) {
	return nil, nil
}

// MarkICS returns a cloned event with ICS flag set when applicable.
func MarkICS(ev dpi.Event) dpi.Event {
	switch ev.Proto {
	case "modbus", "dnp3", "iec104", "s7", "s7comm", "cip", "bacnet", "opcua", "mms", "goose", "ics":
		attrs := ev.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		} else {
			attrs = cloneMap(attrs)
		}
		attrs["ics"] = true
		ev.Attributes = attrs
		ev.Timestamp = time.Now().UTC()
	}
	return ev
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
