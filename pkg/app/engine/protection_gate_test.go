// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
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
	env.g.applyAV(config.AVConfig{Enabled: true})
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

func TestProtectionGateProjectsDisabledScannerOff(t *testing.T) {
	dp := newCountingDP(t).Engine
	env := newGateTestEnv(t)
	env.g.protection = dp

	env.g.publishProtection()
	st := dp.Protection()
	componentFound := false
	for _, component := range st.Components {
		if component.Name == "scanner" {
			componentFound = true
			if component.State != "off" || component.Reason != "" {
				t.Fatalf("disabled scanner component = %+v", component)
			}
			break
		}
	}
	if !componentFound {
		t.Fatalf("disabled scanner component missing: %+v", st)
	}
	for _, outcome := range st.Subsystems {
		if outcome.Name != protection.SubsystemScanner {
			continue
		}
		if outcome.State != protection.DeliveryOff || outcome.Fault != nil ||
			outcome.Retryable || outcome.NextRetryAt != nil {
			t.Fatalf("disabled scanner outcome = %+v", outcome)
		}
		if st.Retryable {
			t.Fatalf("disabled scanner made protection retryable: %+v", st)
		}
		return
	}
	t.Fatalf("disabled scanner outcome missing: %+v", st)
}

func TestProtectionGateLossPublishesDuringAdmissionIO(t *testing.T) {
	env := newGateTestEnv(t)
	env.g.protection = newCountingDP(t).Engine
	env.g.setEnforcing(true)
	env.admit.await(t, enforce.GateAdmitOpen)
	env.g.publishProtection()
	// An admission transaction may block in kernel I/O. A routing/listener
	// loss must still invalidate the previous ready observation immediately.
	env.g.admitMu.Lock()
	env.g.mu.Lock()
	env.g.routingOK = false
	env.g.mu.Unlock()
	done := make(chan struct{})
	go func() { env.g.publishProtection(); close(done) }()
	select {
	case <-done:
		found := false
		for _, c := range env.g.protection.Protection().Components {
			if c.Name == "scan-gate" {
				found = true
				if c.State != "pending" {
					t.Errorf("routing loss kept scan gate ready: %+v", c)
				}
			}
		}
		if !found {
			t.Error("missing scan-gate observation")
		}
	case <-time.After(time.Second):
		t.Error("admission I/O delayed publication of a required component loss")
	}
	env.g.admitMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publication did not complete")
	}
}
