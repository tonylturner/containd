// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// The scanning gate's admission chain (enforce.GateAdmitChain) decides what
// happens to a connection the installed ruleset has just selected: delivery
// to the gate's listeners, a reset, or an ungated pass. Its state is
// listener liveness combined with the fail policy, which the gate manager
// knows and the engine does not, so the manager sets it through
// SetGateAdmit. The engine keeps the state across ruleset applies, which
// write it into the admission chain of every ruleset they install, and
// across Reconfigure, which replaces the compiler but not the kernel
// ruleset. Until the manager reports its listeners up, the state is
// GateAdmitRefuse: nothing selected is forwarded unscanned by default.

// SetGateAdmit sets the admission state of the scanning gate: in the
// installed ruleset's admission chain now, in one nft transaction, and in
// every ruleset applied later. It is serialised with ruleset applies and
// Reconfigure, so a reapply never reverts a switch and a switch never races
// an apply; do not call it from an engine callback. Without enforcement the
// state is kept and nothing is written. A failed switch leaves the kernel
// in its previous state and returns the error; the next apply writes the
// state the caller wanted.
func (e *Engine) SetGateAdmit(ctx context.Context, state enforce.GateAdmitState) error {
	switch state {
	case enforce.GateAdmitRefuse, enforce.GateAdmitOpen, enforce.GateAdmitPass:
	default:
		return fmt.Errorf("unknown gate admission state %d", state)
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.gateAdmit = state
	if e.compiler == nil {
		return nil
	}
	return e.gate.switchGateAdmit(ctx, state)
}

// GateAdmit returns the admission state the engine holds.
func (e *Engine) GateAdmit() enforce.GateAdmitState {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.gateAdmit
}

// switchGateAdmit writes state into the installed ruleset's admission chain
// under the mutex that serialises applies with switches. There is nothing
// to write before the first apply, or when the installed ruleset carries no
// gate.
func (g *envelopeGate) switchGateAdmit(ctx context.Context, state enforce.GateAdmitState) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.comp == nil || !g.comp.SteersGate() {
		return nil
	}
	if err := g.applier.Apply(ctx, g.comp.GateAdmitSwitch(state)); err != nil {
		return fmt.Errorf("gate admission switch: %w", err)
	}
	g.comp.GateAdmit = state
	return nil
}
