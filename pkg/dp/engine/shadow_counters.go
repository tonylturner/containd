// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ShadowCounters describes applied-policy message observations, not packet
// verdict predictions. Memory is lost on restart or successful policy install.
type ShadowCounters struct {
	Available       bool              `json:"available"`
	Reason          string            `json:"reason,omitempty"`
	SnapshotVersion string            `json:"snapshotVersion,omitempty"`
	Since           *time.Time        `json:"since,omitempty"`
	Unit            string            `json:"unit,omitempty"`
	Rules           []ShadowRuleCount `json:"rules,omitempty"`
}

type ShadowRuleCount struct {
	RuleID        string `json:"ruleId"`
	ShadowMatches uint64 `json:"shadowMatches"`
	WouldAllow    uint64 `json:"wouldAllow"`
	WouldDeny     uint64 `json:"wouldDeny"`
}

type shadowState struct {
	mu     sync.Mutex
	since  time.Time
	counts map[string]ShadowRuleCount
}

func newShadowState(snap *rules.Snapshot, since time.Time) *shadowState {
	s := &shadowState{since: since, counts: map[string]ShadowRuleCount{}}
	for _, r := range snap.Firewall {
		if rules.MonitorICS(r, snap.DPIMode) {
			s.counts[r.ID] = ShadowRuleCount{RuleID: r.ID}
		}
	}
	return s
}

func (e *Engine) ShadowCounters() ShadowCounters {
	if e == nil {
		return ShadowCounters{Reason: "no engine"}
	}
	p := e.ruleSnap.current.Load()
	if p == nil || p.shadow == nil {
		return ShadowCounters{Reason: "no policy is applied"}
	}
	s := p.shadow
	s.mu.Lock()
	defer s.mu.Unlock()
	out := ShadowCounters{Available: true, SnapshotVersion: p.snapshot.Version, Since: &s.since, Unit: "messages", Rules: make([]ShadowRuleCount, 0, len(s.counts))}
	for _, r := range s.counts {
		out.Rules = append(out.Rules, r)
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].RuleID < out.Rules[j].RuleID })
	return out
}

func (e *Engine) countShadow(snap *rules.Snapshot, entry *rules.Entry) {
	p := e.ruleSnap.current.Load()
	if p == nil || p.snapshot != snap || p.shadow == nil {
		return
	}
	s := p.shadow
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.counts[entry.ID]
	if !ok {
		return
	}
	c.ShadowMatches++
	if entry.Action == rules.ActionAllow {
		c.WouldAllow++
	} else {
		c.WouldDeny++
	}
	s.counts[entry.ID] = c
}

func shadowDecision(entry *rules.Entry) string {
	if entry.Action == rules.ActionAllow {
		return decisionWouldAllow
	}
	return decisionWouldDrop
}

func (e *Engine) observeMonitor(snap *rules.Snapshot, evaluator *rules.Evaluator, state *flow.State, pkt *dpi.ParsedPacket, ev dpi.Event, contexts []rules.EvalContext) {
	seen := map[string]bool{}
	for _, ctx := range contexts {
		for _, entry := range evaluator.MonitorMatches(ctx) {
			if seen[entry.ID] {
				continue
			}
			seen[entry.ID] = true
			e.countShadow(snap, entry)
			attrs := make(map[string]any, len(ev.Attributes)+5)
			for k, v := range ev.Attributes {
				attrs[k] = v
			}
			attrs[eventfields.KeyDecision], attrs[eventfields.KeyMode] = shadowDecision(entry), "monitor"
			attrs[eventfields.KeyRuleID], attrs[eventfields.KeyAction], attrs[eventfields.KeyReason] = entry.ID, string(entry.Action), reasonRule
			shadow := ev
			shadow.Kind, shadow.Timestamp, shadow.Attributes = eventfields.KindDecision, time.Now().UTC(), attrs
			e.recordTaggedEvents(state, pkt, []dpi.Event{shadow})
		}
	}
}

func (c ShadowCounters) MarshalJSON() ([]byte, error) {
	type plain ShadowCounters
	if !c.Available {
		return json.Marshal(struct {
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		}{false, c.Reason})
	}
	if c.Rules == nil {
		c.Rules = []ShadowRuleCount{}
	}
	return json.Marshal(struct {
		plain
		Rules []ShadowRuleCount `json:"rules"`
	}{plain(c), c.Rules})
}
