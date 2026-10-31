// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

const iecInventoryCap = 128 // commands and carrying tokens, independently, per session

type iecInventoryInput interface {
	ObserveIEC104(inventory.IEC104Observation) inventory.IEC104CommandRef
	IEC104CommandOutcome(inventory.IEC104Outcome)
	RecordIEC104DeliveryOverflow(uint64)
}

// Session-owned delivery evidence. All maps, pending and allowed are protected
// by iecTable.mu. Only the observation/outcome rendezvous crosses that lock.
type iecInventoryLedger struct {
	commands map[string]*iecInventoryCommand
	tokens   map[capture.Token]map[*iecInventoryCommand]struct{}
}

type iecInventoryCommand struct {
	input         iecInventoryInput
	learnDelivery func(string)
	observation   inventory.IEC104Observation // immutable after construction
	ref           inventory.IEC104CommandRef  // published by observed.Store
	observed      atomic.Bool
	final         atomic.Uint32 // 0 pending, 1 not accepted, 2 accepted
	emitted       atomic.Bool
	id            string
	start, end    int64
	pending       int
	allowed       bool
}

func (c *iecInventoryCommand) observe() {
	c.ref = c.input.ObserveIEC104(c.observation)
	c.observed.Store(true)
	c.flush()
}

// Neither side waits for the other. Observation publishes the opaque ref
// before an outcome can acquire it; whichever side arrives last emits once.
func (c *iecInventoryCommand) flush() {
	if c.observed.Load() && c.final.Load() != 0 && c.emitted.CompareAndSwap(false, true) {
		c.input.IEC104CommandOutcome(inventory.IEC104Outcome{Command: c.ref, Accepted: c.final.Load() == 2})
		if c.final.Load() == 2 && c.id != "" && c.learnDelivery != nil {
			c.learnDelivery(c.id)
		}
	}
}

func (t *iecTable) observeInventoryLocked(s *iecSession, dir int, f dpi.DecodedFrame, cur *heldPacket, acts *iecActions, now time.Time) {
	if t.inventory == nil {
		return
	}
	o, ok := inventory.IEC104ObservationFromEvents(f.Events)
	if !ok {
		return
	}
	o.SessionID, o.Controlling, o.Controlled = s.id, s.client, s.server
	o.ControlDirection, o.Time = dir == iecDirClient, now
	c := &iecInventoryCommand{input: t.inventory, learnDelivery: t.learnDelivery, observation: o, start: f.Start, end: f.End, allowed: true}
	acts.inventoryObserve = append(acts.inventoryObserve, c)
	if !o.IsCommand() {
		return
	}
	if s.mode != "enforce" || !cur.tok.Inline() {
		c.final.Store(1) // no provable userspace delivery in observational modes
		return
	}
	if s.inventory == nil {
		s.inventory = &iecInventoryLedger{
			commands: make(map[string]*iecInventoryCommand),
			tokens:   make(map[capture.Token]map[*iecInventoryCommand]struct{}),
		}
	}
	if len(s.inventory.commands) >= iecInventoryCap {
		c.final.Store(1)
		acts.inventoryOverflow++
		return
	}
	c.id = eventfields.APDUID(s.id, dirLetter(dir), f.Start)
	s.inventory.commands[c.id] = c
	for _, h := range s.held {
		t.inventoryAttachLocked(s, c, h, acts)
	}
	t.inventoryAttachLocked(s, c, cur, acts)
}

func (t *iecTable) inventoryAttachLocked(s *iecSession, c *iecInventoryCommand, h *heldPacket, acts *iecActions) {
	if h.dir != iecDirClient || h.off >= c.end || c.start >= h.end || c.final.Load() != 0 {
		return
	}
	l := s.inventory
	cmds := l.tokens[h.tok]
	if cmds == nil {
		if len(l.tokens) >= iecInventoryCap {
			acts.inventoryOverflow++
			t.inventoryFinalLocked(s, c, false, acts)
			return
		}
		cmds = make(map[*iecInventoryCommand]struct{})
		l.tokens[h.tok] = cmds
		t.inventoryTokens[h.tok] = s
	}
	if _, exists := cmds[c]; !exists {
		cmds[c] = struct{}{}
		c.pending++
	}
}

// Attach retransmissions received while delivery is still pending. Completed
// APDUs are not observed again and later retransmissions cannot change history.
func (t *iecTable) inventoryPacketLocked(s *iecSession, cur *heldPacket, acts *iecActions) {
	if s.inventory != nil {
		for _, c := range s.inventory.commands {
			t.inventoryAttachLocked(s, c, cur, acts)
		}
	}
}

func (s *iecSession) inventoryDecisionLocked(ev dpi.Event, d iecDecision) {
	if s.inventory == nil || d.decision == decisionAllow {
		return
	}
	id, _ := eventfields.String(ev.Attributes, eventfields.KeyAPDUID)
	if c := s.inventory.commands[id]; c != nil {
		c.allowed = false
	}
}

func (t *iecTable) inventoryFinalLocked(s *iecSession, c *iecInventoryCommand, accepted bool, acts *iecActions) {
	value := uint32(1)
	if accepted {
		value = 2
	}
	if !c.final.CompareAndSwap(0, value) {
		return
	}
	delete(s.inventory.commands, c.id)
	// Fixed caps bound both dimensions, including removal after early failure.
	for tok, cmds := range s.inventory.tokens {
		delete(cmds, c)
		if len(cmds) == 0 {
			delete(s.inventory.tokens, tok)
			delete(t.inventoryTokens, tok)
		}
	}
	acts.inventoryOutcome = append(acts.inventoryOutcome, c)
}

func (t *iecTable) inventoryVerdictLocked(tok capture.Token, v capture.Verdict, err error, acts *iecActions) {
	s := t.inventoryTokens[tok]
	if s == nil {
		return
	}
	cmds := s.inventory.tokens[tok]
	delete(s.inventory.tokens, tok)
	delete(t.inventoryTokens, tok)
	for c := range cmds {
		c.pending--
		if err != nil || v != capture.VerdictAccept {
			t.inventoryFinalLocked(s, c, false, acts)
		} else if c.pending == 0 {
			t.inventoryFinalLocked(s, c, c.allowed, acts)
		}
	}
}

func (t *iecTable) endInventoryLocked(s *iecSession) iecActions {
	var acts iecActions
	if s.inventory != nil {
		for _, c := range s.inventory.commands {
			t.inventoryFinalLocked(s, c, false, &acts)
		}
		s.inventory = nil
	}
	if s.next != nil {
		acts.merge(t.endInventoryLocked(s.next))
	}
	return acts
}

func (t *iecTable) expireInventoryLocked(s *iecSession, acts *iecActions, now time.Time) {
	if s.inventory != nil {
		for _, c := range s.inventory.commands {
			if now.Sub(c.observation.Time) > iecPendingTimeout {
				t.inventoryFinalLocked(s, c, false, acts)
			}
		}
	}
}

func (t *iecTable) finishInventory(acts iecActions) {
	for _, c := range acts.inventoryObserve {
		c.observe()
	}
	for _, c := range acts.inventoryOutcome {
		c.flush()
	}
	if acts.inventoryOverflow != 0 {
		t.inventory.RecordIEC104DeliveryOverflow(acts.inventoryOverflow)
	}
}

// stopInventory also covers a configuration replaced before Start.
func (t *iecTable) stopInventory() {
	var acts iecActions
	t.mu.Lock()
	for _, s := range t.sessions {
		acts.merge(t.endInventoryLocked(s))
	}
	t.mu.Unlock()
	t.finishInventory(acts)
}
