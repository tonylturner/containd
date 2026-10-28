// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/httpgate"
)

// Event kinds the gate records. Detections keep the kind the events query,
// the dashboard and the UI already count.
const (
	gateEventDetected   = "service.av.detected"
	gateEventScanned    = "service.av.scanned"
	gateEventConnection = "service.av.gate_connection"
	gateEventState      = "service.av.gate_state"
	gateEventPending    = "service.av.pending"
)

// gateEvent converts a gate event into a telemetry event. The client is the
// source, the effective destination the destination; original is the
// destination before DNAT when known.
func gateEvent(ev httpgate.Event, original netip.AddrPort) events.Event {
	attrs := map[string]any{
		"client": ev.Client.String(),
		"server": ev.Server.String(),
	}
	if original.IsValid() {
		attrs["original_destination"] = original.String()
	}
	kind := gateEventScanned
	switch {
	case ev.Error != "":
		kind = gateEventConnection
		attrs["error"] = ev.Error
	default:
		if ev.Verdict == avscan.Infected {
			kind = gateEventDetected
		}
		attrs["transaction"] = ev.ID
		attrs["direction"] = string(ev.Direction)
		attrs["verdict"] = string(ev.Verdict)
		attrs["action"] = string(ev.Action)
		attrs["backend"] = ev.Backend
		attrs["size"] = ev.Size
		attrs["duration_ms"] = ev.Duration.Milliseconds()
		gateSetIf(attrs, "reason", string(ev.Reason))
		gateSetIf(attrs, "signature", ev.Signature)
		gateSetIf(attrs, "detail", ev.Detail)
		gateSetIf(attrs, "method", ev.Method)
		gateSetIf(attrs, "host", ev.Host)
		gateSetIf(attrs, "target", ev.Target)
		if ev.Status != 0 {
			attrs["status"] = ev.Status
		}
		if ev.ICS {
			attrs["ics"] = true
		}
		if ev.SHA256Partial {
			attrs["sha256_partial"] = true
		}
		if ev.Streamed != 0 {
			attrs["streamed"] = ev.Streamed
		}
	}
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	return events.Event{
		Proto:      "av",
		Kind:       kind,
		Timestamp:  at.UTC(),
		Attributes: attrs,
		SrcIP:      gateAddrString(ev.Client),
		DstIP:      gateAddrString(ev.Server),
		SrcPort:    ev.Client.Port(),
		DstPort:    ev.Server.Port(),
		Transport:  "tcp",
		Hash:       ev.SHA256,
	}
}

func gateSetIf(attrs map[string]any, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}

func gateAddrString(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return ""
	}
	return ap.Addr().String()
}
