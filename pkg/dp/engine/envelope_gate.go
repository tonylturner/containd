// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// envelopeSwitchTimeout bounds one envelope switch (a single nft
// transaction).
const envelopeSwitchTimeout = 5 * time.Second

// envelopeGate keeps the nft IEC104 envelope chain fail closed until this
// engine owns its queue: envelope traffic is queued only
// while the queue the installed ruleset steers to is bound by this engine,
// and dropped in every other state. Another process that holds the queue
// number therefore never decides envelope traffic.
//
// The gate outlives Reconfigure, because the kernel ruleset does. mu
// serialises ruleset applies with switches, so a reapply always writes the
// current state and a switch never races a reapply.
type envelopeGate struct {
	mu sync.Mutex
	// owned is the NFQUEUE group this engine has bound and registered; 0
	// before the first bind and while a bind fault or source-down stands.
	owned uint16
	// The installed ruleset: its compiler (table, queue) and applier, and
	// whether it has an envelope chain.
	comp      *enforce.Compiler
	applier   enforce.Applier
	installed bool
	// open is the state last written to the kernel.
	open bool
	// fault reports a failed switch; ok reports a successful one.
	fault func(reason string)
	ok    func()
}

// wantOpenLocked reports whether the installed envelope may queue: only to
// the queue this engine owns.
func (g *envelopeGate) wantOpenLocked() bool {
	return g.installed && g.comp != nil && g.queueOpenLocked(g.comp.QueueID)
}

// queueOpenLocked is the envelope decision for both candidate and live applies.
func (g *envelopeGate) queueOpenLocked(queue int) bool {
	return g.owned != 0 && queue == int(g.owned)
}

// sampleOpen reads the decision for a candidate queue without changing the gate.
func (g *envelopeGate) sampleOpen(queue int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.queueOpenLocked(queue)
}

// apply compiles snap in the current envelope state and installs it. The
// compiler's envelope state is set here and nowhere else. When comp owns
// differently named tables than the installed ruleset, the same transaction
// removes the installed ones; the returned ruleset is comp's alone.
func (g *envelopeGate) apply(ctx context.Context, comp *enforce.Compiler, applier enforce.Applier, snap *rules.Snapshot) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	open := g.queueOpenLocked(comp.QueueID)
	comp.IEC104EnvelopeOpen = open
	compiled, err := comp.CompileFirewall(snap)
	if err != nil {
		return compiled, err
	}
	if applier == nil {
		return compiled, errors.New("no applier configured")
	}
	retire := ""
	if g.comp != nil {
		retire = g.comp.RetireTables(comp)
	}
	if err := applier.Apply(ctx, retire+compiled); err != nil {
		return compiled, err
	}
	g.comp, g.applier = comp, applier
	g.installed = comp.SteersIEC104(snap)
	g.open = g.installed && open
	if g.ok != nil {
		g.ok() // the kernel holds the current state again
	}
	return compiled, nil
}

// release deletes the tables of the installed ruleset, if any, and forgets
// it. On failure the ruleset stays installed and recorded.
func (g *envelopeGate) release() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.comp == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), envelopeSwitchTimeout)
	defer cancel()
	if err := g.applier.Apply(ctx, g.comp.DeleteTables()); err != nil {
		return err
	}
	g.comp, g.applier = nil, nil
	g.installed, g.open = false, false
	return nil
}

// own records the queue group this engine has bound (0: none) and writes
// the resulting envelope state to the kernel.
func (g *envelopeGate) own(group uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.owned = group
	want := g.wantOpenLocked()
	if !g.installed || want == g.open {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), envelopeSwitchTimeout)
	defer cancel()
	if err := g.applier.Apply(ctx, g.comp.IEC104EnvelopeSwitch(want)); err != nil {
		// Opening failed: the chain still drops (fail closed). Closing
		// failed: the chain may still queue to a queue this engine no
		// longer holds. Either way enforcement is unhealthy.
		if g.fault != nil {
			g.fault("envelope steering switch: " + err.Error())
		}
		return
	}
	g.open = want
	if g.ok != nil {
		g.ok()
	}
}

// bindGate points the current configuration's capture hooks and health at
// the engine's gate. Called by New and after Reconfigure swaps in a fresh
// configuration.
func (e *Engine) bindGate() {
	health := e.iec.health
	e.hooks.gate, e.hooks.group = e.gate, e.nfqueueGroup
	fault := func(reason string) { health.fault(faultSteering, reason) }
	ok := func() { health.clear(faultSteering) }
	e.gate.mu.Lock()
	e.gate.fault, e.gate.ok = fault, ok
	e.gate.mu.Unlock()
}
