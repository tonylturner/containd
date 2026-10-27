// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// IEC104 decoder event kinds.
const (
	iecKindMalformed   = "malformed"
	iecKindUnsupported = "unsupported"
)

// ics.decision values and reasons.
const (
	decisionAllow     = "allow"
	decisionDeny      = "deny"
	decisionWouldDrop = "would_drop"

	reasonRule      = "rule"
	reasonDefault   = "default"
	reasonBroadcast = "broadcast"
	reasonMalformed = "malformed" // unframeable bytes or a stream fault, never decoded content
)

// ics.verdict and ics.session outcomes.
const (
	outcomeDropped          = "dropped"
	outcomeDropFailed       = "drop_failed"
	outcomeAborted          = "aborted"
	outcomeResetSent        = "reset_sent"
	outcomeResetFailed      = "reset_failed"
	outcomeReconnected      = "reconnected"
	outcomeEnforceUnhealthy = "enforce_unhealthy"
	outcomeEnforceHealthy   = "enforce_healthy"
	outcomeUntracked        = "untracked"
)

// iecAbortReason binds each fixed reason label to its process-lifetime counter.
// Packet-path callers take a declared reason, never a string or an array index.
type iecAbortReason struct {
	name  string
	total atomic.Uint64
}

// Session aborts and fail-closed admission/steering rejections share this catalog.
var (
	abortDeny      = &iecAbortReason{name: "deny"}
	abortTimeout   = &iecAbortReason{name: "timeout"}
	abortBound     = &iecAbortReason{name: "bound"}
	abortStream    = &iecAbortReason{name: "stream"}
	abortFraming   = &iecAbortReason{name: "framing"}
	abortTransport = &iecAbortReason{name: "transport"}
	abortPolicy    = &iecAbortReason{name: "policy"}
	abortQueue     = &iecAbortReason{name: "queue"}
	abortMidstream = &iecAbortReason{name: "midstream"}
	abortUnhealthy = &iecAbortReason{name: "unhealthy"}
	abortFailClose = &iecAbortReason{name: "fail_close"}
	abortInjector  = &iecAbortReason{name: "injector"}
)

// The catalog is used by metric initialization, snapshots and exhaustive tests.
var iecAbortReasons = [...]*iecAbortReason{
	abortDeny, abortTimeout, abortBound, abortStream, abortFraming, abortTransport,
	abortPolicy, abortQueue, abortMidstream, abortUnhealthy, abortFailClose, abortInjector,
}

// liveRunID identifies this process's live engine for session IDs.
// It is set once per live engine lifetime; Reconfigure keeps it.
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

// decisionKeys are the decoded attributes an ics.decision event repeats,
// including the conformance findings the decision was made with.
var decisionKeys = []string{
	eventfields.KeyAPDUID, eventfields.KeyTypeID, eventfields.KeyCA, eventfields.KeyIOA,
	eventfields.KeySelect, eventfields.KeyDirection, eventfields.KeyConformance,
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

// untrackedEvent reports a learn-mode SYN accepted without tracking. There
// is no incarnation, so it deliberately carries no session_id or apdu_id.
func untrackedEvent(client, server netip.AddrPort, now time.Time) events.Event {
	return events.Event{
		Proto: eventfields.ProtoIEC104,
		Kind:  eventfields.KindSession,
		Attributes: map[string]any{
			eventfields.KeyOutcome: outcomeUntracked,
			eventfields.KeyMode:    "learn",
			eventfields.KeyReason:  "bound",
			"limit":                iecMaxSessions,
		},
		Timestamp: now.UTC(),
		SrcIP:     client.Addr().String(),
		DstIP:     server.Addr().String(),
		SrcPort:   client.Port(),
		DstPort:   server.Port(),
		Transport: "tcp",
	}
}
