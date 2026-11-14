// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const (
	iec104Port  = ics.IEC104Port
	iecProtocol = "iec104"
)

// iecAdapter contains the IEC104 policy and observation binding. The
// session owner's single lock protects it and each session's protocol state.
// It owns no TCP tracker, sequence space, held credits or settlement lock.
type iecAdapter struct {
	policy      iecPolicy
	newPolicy   func(*rules.Snapshot) iecPolicy
	safeRead    func(map[string]any) bool
	globalMode  string
	hasIEC      bool
	hasSessions bool
	gatedPolicy *rules.Evaluator
	// parsing is resolved for each packet; changes do not retire sessions.
	parsing   ics.Parsing
	inventory iecInventoryInput
	shadow    func(*rules.Snapshot, *rules.Entry)
}

// iecSession is the protocol state of an incarnation. ctx is opener-oriented;
// mode is the envelope mode fixed at SYN admission.
type iecSession struct {
	ctx        rules.EvalContext
	mode       string
	reconnects bool // first STARTDT con counts as a reconnect
	apci       *anomaly.IEC104APCI
}

// iecPolicy is the IEC104 part of the rule evaluator.
// *rules.Evaluator implements it.
type iecPolicy interface {
	IEC104Envelope(ctx rules.EvalContext, globalMode string) (bool, string)
	EvaluateIEC104(ctx rules.EvalContext) (rules.Action, *rules.Entry)
	MonitorMatches(rules.EvalContext) []*rules.Entry
	IEC104Scope(rules.EvalContext, string) *rules.Entry
}

type enforcingIECPolicy struct{ *rules.Evaluator }

func (p enforcingIECPolicy) EvaluateIEC104(ctx rules.EvalContext) (rules.Action, *rules.Entry) {
	return p.EvaluateIEC104Enforcing(ctx)
}
func newRulesPolicy(snap *rules.Snapshot) iecPolicy {
	return enforcingIECPolicy{rules.NewEvaluator(snap)}
}

// newIECTable binds the session owner to IEC104, the only gated protocol.
func newIECTable(globalMode string, zones *zoneCache) *sessionTable {
	return &sessionTable{
		ruleOwner:    &ruleSnapshots{},
		ledger:       limits.NewLedger(nil),
		resources:    limits.NewResources(nil, nil),
		settlements:  make(map[capture.Token]*heldCredit),
		zones:        zones,
		now:          time.Now,
		newID:        nextLiveSessionID,
		ctDelete:     conntrack.Delete,
		sessions:     make(map[sessionKey]*trackedSession),
		tokenOwners:  make(map[capture.Token]sessionToken),
		byConnection: make(map[string]*trackedSession),
		held:         make(map[capture.Token]*trackedSession),
		aborts:       make(map[capture.Token]*abortTxn),
		reconnect:    make(map[string]time.Time),
		pickups:      newPickupResets(),

		iecAdapter: iecAdapter{globalMode: globalMode, newPolicy: newRulesPolicy, safeRead: iec104.SafeRead},
	}
}

// streamErrorEvent is the malformed evidence of a byte-level stream error
// (overlap conflict, bounds, bytes before the stream).
func (a *iecAdapter) streamErrorEvent(s *trackedSession, dir int, off int64, err error, now time.Time) dpi.Event {
	return dpi.Event{
		Proto: eventfields.ProtoIEC104,
		Kind:  iecKindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError:     "stream: " + err.Error(),
			eventfields.KeyDirection: dirName(dir),
			eventfields.KeySessionID: s.id,
			"offset":                 off,
		},
		Timestamp: now.UTC(),
	}
}

// envelopeLocked evaluates the envelope of a session tuple.
func (a *iecAdapter) envelopeLocked(ctx rules.EvalContext) (bool, string) {
	switch ctx.Port {
	case "502":
		return a.gatedPolicy.ProtocolEnvelope(ctx, "modbus", a.globalMode)
	case "20000":
		return a.gatedPolicy.ProtocolEnvelope(ctx, "dnp3", a.globalMode)
	}
	if a.policy == nil || !a.hasIEC {
		return false, ""
	}
	return a.policy.IEC104Envelope(ctx, a.globalMode)
}

// hasEnforceIEC reports whether a snapshot loads an enforce envelope.
func hasEnforceIEC(snap *rules.Snapshot, globalMode string) (hasIEC, enforce bool) {
	if snap == nil {
		return false, false
	}
	for _, entry := range snap.Firewall {
		if !strings.EqualFold(entry.ICS.Protocol, iecProtocol) {
			continue
		}
		hasIEC = true
		if rules.EffectiveMode(entry.ICS.Mode, globalMode) == "enforce" {
			enforce = true
		}
	}
	return hasIEC, enforce
}

// hasEnforceICS reports whether a snapshot loads an enforce rule of an ICS
// protocol other than IEC104, whose inline flows fail closed.
func hasEnforceICS(snap *rules.Snapshot, globalMode string) bool {
	if snap == nil {
		return false
	}
	for _, entry := range snap.Firewall {
		if entry.ICS.Protocol != "" && !strings.EqualFold(entry.ICS.Protocol, iecProtocol) &&
			rules.EffectiveMode(entry.ICS.Mode, globalMode) == "enforce" {
			return true
		}
	}
	return false
}

// droppedAPDUsLocked lists every identified APDU whose bytes the dropped
// packets carry: decided frames they overlap, and the known start of the
// incomplete tail. Unknown boundaries get no ID.
func (a *iecAdapter) droppedAPDUsLocked(s *trackedSession, dropped []*heldPacket) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(dir int, start int64) {
		id := eventfields.APDUID(s.id, dirLetter(dir), start)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, h := range dropped {
		d := s.dirs[h.dir]
		if d == nil {
			continue
		}
		for _, f := range d.frames {
			if f.start < h.end && h.off < f.end {
				add(h.dir, f.start)
			}
		}
		if d.framedEnd < d.bytes.Next() && h.end > d.framedEnd {
			add(h.dir, d.framedEnd)
		}
	}
	sort.Strings(ids)
	return ids
}

func dirLetter(dir int) byte {
	if dir == sessionDirClient {
		return eventfields.DirClient
	}
	return eventfields.DirServer
}

type iecInventoryInput interface {
	ObserveIEC104(inventory.IEC104Observation)
}

// frameLocked collects protocol observations under the session lock. Inventory
// consumers receive immutable observations only after that lock is released.
func (a *iecAdapter) frameLocked(s *trackedSession, dir int, f dpi.DecodedFrame, acts *sessionActions, now time.Time) {
	if sessionProtocol(s.flow) != iecProtocol {
		return
	}
	s.observeAPCILocked(dir, f, acts, now)
	if a.inventory == nil {
		return
	}
	o, ok := inventory.IEC104ObservationFromEvents(f.Events)
	if !ok {
		return
	}
	o.SessionID, o.Controlling, o.Controlled = s.id, s.client, s.server
	o.ControlDirection, o.Time = dir == sessionDirClient, now
	acts.inventoryObserve = append(acts.inventoryObserve, o)
}

// installLocked changes only protocol policy; the owner applies the resulting
// envelope changes to its sessions and carries out retirement after unlock.
func (a *iecAdapter) installLocked(snap *rules.Snapshot) (active, otherICS bool) {
	if snap != nil && snap.DPIMode != "" {
		a.globalMode = snap.DPIMode
	}
	a.hasIEC, active = hasEnforceIEC(snap, a.globalMode)
	otherICS = hasEnforceICS(snap, a.globalMode)
	a.policy = a.newPolicy(snap)
	a.gatedPolicy = rules.NewEvaluator(snap)
	a.hasSessions = a.hasIEC
	if snap != nil {
		for _, entry := range snap.Firewall {
			if entry.ICS.Protocol == "modbus" || entry.ICS.Protocol == "dnp3" {
				a.hasSessions = true
			}
		}
	}
	return active, otherICS
}

func (a *iecAdapter) acceptsSYN(state *flow.State) bool {
	return state.ServiceKey().Dir == flow.DirForward && sessionProtocol(state) != ""
}
