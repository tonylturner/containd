// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestProtectionGateObservesScannerWithoutHealthRequests(t *testing.T) {
	dp := newCountingDP(t).Engine
	env := newGateTestEnv(t)
	env.g.protection = dp
	component := func(name string) string {
		for _, c := range dp.Protection().Components {
			if c.Name == name {
				return c.State
			}
		}
		return ""
	}
	await := func(name, state string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if component(name) == state {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("%s did not become %s: %+v", name, state, dp.Protection())
	}
	env.g.setEnforcing(true)
	env.admit.await(t, enforce.GateAdmitOpen)
	await("scan-gate", "ready")
	await("scanner", "ready")
	env.scanner.ready.Store(false)
	await("scanner", "pending")
	env.scanner.ready.Store(true)
	await("scanner", "ready")
	env.g.mu.Lock()
	env.g.admitErr = "admission transaction failed"
	env.g.appliedKnown = false
	env.g.mu.Unlock()
	env.g.publishProtection()
	await("scan-gate", "failed")
	env.g.mu.Lock()
	env.g.admitErr = ""
	env.g.routingTerminal = true
	env.g.routingErr = "routing unsupported"
	env.g.routingOK = false
	env.g.mu.Unlock()
	env.g.publishProtection()
	await("scan-gate", "failed")
}
