// SPDX-License-Identifier: Apache-2.0

package engineapp

// Scanner readiness is sampled by the gate's lifetime worker because Scanner
// exposes Ready(), not a notification API. Listener/routing/admission changes
// also publish immediately; health requests never drive readiness transitions.
func (g *gateManager) publishProtection() {
	if g == nil || g.protection == nil {
		return
	}
	// A sample must not publish the gap between a successful kernel switch
	// and syncAdmit recording that acknowledgement.
	g.admitMu.Lock()
	defer g.admitMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.statusLocked()
	state, reason := "pending", "awaiting gate listeners and routing"
	switch {
	case g.server == nil:
		state, reason = "off", ""
	case g.routingTerminal:
		state, reason = "failed", g.routingErr
	case g.admitErr != "":
		state, reason = "failed", g.admitErr
	case g.server != nil && g.routingOK && g.listenersUpLocked() && g.appliedKnown && g.applied == g.desiredAdmitLocked():
		state, reason = "ready", ""
	}
	unknown := g.admitErr != ""
	g.protection.SetScanProtection(state, reason, st.Scanner.Ready, st.Scanner.Error, unknown)
}
