// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// IEC104 decoder event kinds (contracts K4).
const (
	iecKindMalformed   = "malformed"
	iecKindUnsupported = "unsupported"
)

// ics.decision values and reasons (spec §8.4).
const (
	decisionAllow     = "allow"
	decisionDeny      = "deny"
	decisionWouldDrop = "would_drop"

	reasonRule        = "rule"
	reasonDefault     = "default"
	reasonBroadcast   = "broadcast"
	reasonMalformed   = "malformed"
	reasonUnsupported = "unsupported"
	reasonRole        = "role"
)

// ics.verdict and ics.session outcomes (spec §8.4).
const (
	outcomeDropped          = "dropped"
	outcomeDropFailed       = "drop_failed"
	outcomeAborted          = "aborted"
	outcomeResetSent        = "reset_sent"
	outcomeResetFailed      = "reset_failed"
	outcomeReconnected      = "reconnected"
	outcomeEnforceUnhealthy = "enforce_unhealthy"
	outcomeEnforceHealthy   = "enforce_healthy"
)

// Abort reasons, carried as the reason of the ics.session aborted event.
const (
	abortDeny      = "deny"
	abortTimeout   = "timeout"
	abortBound     = "bound"
	abortStream    = "stream"
	abortFraming   = "framing"
	abortTransport = "transport"
	abortPolicy    = "policy"
	abortQueue     = "queue"
	abortMidstream = "midstream"
	abortUnhealthy = "unhealthy"
)

// liveRunID identifies this process's live engine for session IDs
// (contracts K4: once per live engine lifetime; Reconfigure keeps it).
var (
	liveRunID      = newRunID()
	liveSessionSeq atomic.Uint64
)

// newRunID returns a random 128-bit lowercase hex run ID.
func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("engine: run ID: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// nextLiveSessionID allocates the next live incarnation ID.
func nextLiveSessionID() string {
	return eventfields.SessionID(liveRunID, liveSessionSeq.Add(1))
}

// iecEvent builds an engine IEC104 event on the session tuple.
func (s *iecSession) event(kind string, attrs map[string]any, now time.Time) events.Event {
	attrs[eventfields.KeySessionID] = s.id
	return events.Event{
		Proto:      eventfields.ProtoIEC104,
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  now.UTC(),
		SrcIP:      s.client.Addr().String(),
		DstIP:      s.server.Addr().String(),
		SrcPort:    s.client.Port(),
		DstPort:    s.server.Port(),
		Transport:  "tcp",
	}
}

func (s *iecSession) sessionEvent(outcome string, extra map[string]any, now time.Time) events.Event {
	attrs := map[string]any{eventfields.KeyOutcome: outcome}
	for k, v := range extra {
		attrs[k] = v
	}
	return s.event(eventfields.KindSession, attrs, now)
}

// decisionKeys are the decoded attributes an ics.decision event repeats.
var decisionKeys = []string{
	eventfields.KeyAPDUID, eventfields.KeyTypeID, eventfields.KeyCA, eventfields.KeyIOA,
	eventfields.KeySelect, eventfields.KeyDirection,
}

func (s *iecSession) decisionEvent(ev dpi.Event, d iecDecision, now time.Time) events.Event {
	attrs := map[string]any{
		eventfields.KeyDecision: d.decision,
		eventfields.KeyRuleID:   d.ruleID,
		eventfields.KeyAction:   d.action,
		eventfields.KeyMode:     d.mode,
		eventfields.KeyReason:   d.reason,
	}
	for _, k := range decisionKeys {
		if v, ok := ev.Attributes[k]; ok {
			attrs[k] = v
		}
	}
	return s.event(eventfields.KindDecision, attrs, now)
}

// healthEvent is an enforcement health change. It belongs to no session,
// so it carries no session_id.
func healthEvent(outcome, errText string, now time.Time) events.Event {
	attrs := map[string]any{eventfields.KeyOutcome: outcome}
	if errText != "" {
		attrs[eventfields.KeyError] = errText
	}
	return events.Event{
		Proto:      eventfields.ProtoIEC104,
		Kind:       eventfields.KindSession,
		Attributes: attrs,
		Timestamp:  now.UTC(),
	}
}
