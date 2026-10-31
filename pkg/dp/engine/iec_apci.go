// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// observeAPCILocked runs once per decoded frame, never once per ASDU object
// or packet. The session table has already ordered and deduplicated TCP bytes.
func (s *iecSession) observeAPCILocked(dir int, f dpi.DecodedFrame, acts *iecActions, now time.Time) {
	if len(f.Events) == 0 {
		return
	}
	ev := f.Events[0]
	format, _ := eventfields.String(ev.Attributes, eventfields.KeyAPCIType)
	// Malformed S/U lengths are not valid APCI acknowledgements/handshakes.
	// A malformed I-format ASDU still has valid, decoded APCI fields.
	if (format == "S" || format == "U") && ev.Kind != eventfields.KindAPCI {
		return
	}
	input := anomaly.IEC104APCIFrame{Direction: dir, Format: format}
	switch format {
	case "I":
		var ok bool
		input.Send, ok = eventfields.Uint16(ev.Attributes, eventfields.KeySendSequence)
		if !ok {
			return
		}
		fallthrough
	case "S":
		var ok bool
		input.Receive, ok = eventfields.Uint16(ev.Attributes, eventfields.KeyReceiveSequence)
		if !ok {
			return
		}
	case "U":
		input.UFunction, _ = eventfields.String(ev.Attributes, eventfields.KeyUFunction)
	default:
		return
	}
	if s.apci == nil {
		s.apci = &anomaly.IEC104APCI{}
	}
	s.appendAPCIFindingsLocked(s.apci.Observe(input, now), ev, acts, now)
}

func (s *iecSession) expireAPCILocked(acts *iecActions, now time.Time) {
	if s.apci != nil && !s.stopParse {
		s.appendAPCIFindingsLocked(s.apci.Expire(now), dpi.Event{}, acts, now)
	}
}

// appendAPCIFindingsLocked only constructs events; finish emits them after
// unlock. It shares the anomaly alert builder with other protocol anomalies.
func (s *iecSession) appendAPCIFindingsLocked(findings []anomaly.IEC104APCIFinding, frame dpi.Event, acts *iecActions, now time.Time) {
	for _, f := range findings {
		src, dst := s.client, s.server
		if f.Direction == iecDirSrv {
			src, dst = dst, src
		}
		ev := frame
		// Timer evidence refers to the activation, not the frame that
		// happened to expose the expiry (which may be in either direction).
		if f.Type == anomaly.IEC104TestTimeout {
			ev = dpi.Event{Proto: iecProtocol, Attributes: map[string]any{
				eventfields.KeySessionID: s.id, eventfields.KeyDirection: dirName(f.Direction),
				eventfields.KeyAPCIType: "U", eventfields.KeyUFunction: "testfr_act",
			}}
		}
		a := anomalyAlertFromEvent(ev, anomaly.Anomaly{
			Type: f.Type, Protocol: iecProtocol, Severity: "medium", Message: f.Message,
			SourceIP: src.Addr().String(), DestIP: dst.Addr().String(), Timestamp: now.UTC(),
		})
		for k, v := range f.Attributes {
			a.Attributes[k] = v
		}
		acts.events = append(acts.events, s.telemetry(events.Event{
			FlowID: a.FlowID, Proto: a.Proto, Kind: a.Kind, Attributes: a.Attributes, Timestamp: a.Timestamp,
			SrcIP: src.Addr().String(), DstIP: dst.Addr().String(), SrcPort: src.Port(), DstPort: dst.Port(), Transport: "tcp",
		}))
	}
}
