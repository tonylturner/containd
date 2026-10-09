// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// apduSeenMax bounds the APDU IDs remembered for rate deduplication.
const apduSeenMax = 4096

// IEC104RoleViolation reports the B profile role and cause restrictions of
// spec §7.3 from a malformed event's decoded identity: a monitor-direction
// type (1..44) sent by the client, or a control or system command (cause 6
// activation or 8 deactivation) sent by the server.
func IEC104RoleViolation(attrs map[string]any) bool {
	dir, _ := eventfields.String(attrs, eventfields.KeyDirection)
	typeID, ok := eventfields.Uint8(attrs, eventfields.KeyTypeID)
	if !ok {
		return false
	}
	if dir == "request" {
		return typeID >= 1 && typeID <= 44
	}
	class, _ := eventfields.String(attrs, eventfields.KeyClass)
	cause, hasCause := eventfields.Uint8(attrs, eventfields.KeyCause)
	return dir == "response" && hasCause && (cause == 6 || cause == 8) && (class == "control" || class == "system")
}

// checkIEC104 flags role and cause violations. Spontaneous telemetry and
// confirmations are not transactions, so no request/response pairing runs.
func (d *Detector) checkIEC104(srcIP, dstIP string, ev dpi.Event) []Anomaly {
	if ev.Kind != "malformed" || !IEC104RoleViolation(ev.Attributes) {
		return nil
	}
	typeID, _ := eventfields.Uint8(ev.Attributes, eventfields.KeyTypeID)
	dir, _ := eventfields.String(ev.Attributes, eventfields.KeyDirection)
	return []Anomaly{{
		Type:     "protocol_violation",
		Protocol: "iec104",
		Severity: "high",
		Message:  fmt.Sprintf("IEC 104 role violation: type %d in %s direction", typeID, dir),
		SourceIP: srcIP,
		DestIP:   dstIP,
		Attributes: map[string]any{
			eventfields.KeyTypeID:    typeID,
			eventfields.KeyDirection: dir,
		},
		Timestamp: ev.Timestamp,
	}}
}

// countsForRate reports whether ev is the first event of its APDU: IEC104
// emits one event per information object, and rates count APDUs.
func (d *Detector) countsForRate(ev dpi.Event) bool {
	id, ok := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
	if !ok || id == "" || ev.Proto != "iec104" {
		return true
	}
	if _, seen := d.apduSeen[id]; seen {
		return false
	}
	d.apduSeen[id] = struct{}{}
	d.apduOrder = append(d.apduOrder, id)
	if len(d.apduOrder) > apduSeenMax {
		delete(d.apduSeen, d.apduOrder[0])
		d.apduOrder = d.apduOrder[1:]
	}
	return true
}
