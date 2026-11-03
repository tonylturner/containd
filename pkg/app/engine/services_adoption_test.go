// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"go.uber.org/zap"
)

func TestServiceOwnersFreshAttemptSelective(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	var fail atomic.Bool
	fail.Store(true)
	dhcp, av := &runtimeDHCPApplier{fail: &fail}, &runtimeAVApplier{}
	wgCalls := 0
	live := "first-interface"
	wg := newWireGuardDelivery(func(context.Context, config.WireGuardConfig) error {
		wgCalls++
		if live == "dead" {
			live = "replacement-interface"
		}
		return nil
	}, func(context.Context, config.WireGuardConfig) (string, error) {
		if live == "dead" {
			return "", errors.New("interface died")
		}
		return live, nil
	})
	h := c.admit("services", serviceApplyHandler(zap.NewNop().Sugar(), dp, nil, dhcp, av, nil, wg))
	cfg := config.ServicesConfig{}
	cfg.VPN.WireGuard.Enabled, cfg.DHCP.Enabled = true, true
	for i := range 5 {
		if i == 2 {
			fail.Store(false)
		}
		if i == 3 {
			live = "dead"
		}
		if i == 4 {
			cfg.DHCP.Authoritative = true
		}
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		id := []string{"failed", "fresh-failed", "recovered", "dead-owner", "changed-owner"}[i]
		if w := coordinatedPost(c, h, id, string(body)); w.Code != 200 {
			t.Fatalf("services: %d %s", w.Code, w.Body)
		}
		st := dp.Protection()
		for _, name := range []protection.SubsystemName{protection.SubsystemAV, protection.SubsystemWireGuard, protection.SubsystemDHCP} {
			out := subsystem(t, st, name)
			if name == protection.SubsystemDHCP && i < 2 {
				if out.Acknowledged != nil || !out.Retryable || out.Fault == nil {
					t.Fatalf("fresh attempt lost outstanding failure: %+v", out)
				}
			} else if out.Acknowledged == nil || out.Acknowledged.Metadata != c.metadata {
				t.Fatalf("owner not adopted: %+v", out)
			}
		}
		wantWG, wantDHCP := 1, int32(i+1)
		if i >= 3 {
			wantWG = 2
			wantDHCP = int32(i)
		}
		if av.calls.Load() != 1 || wgCalls != wantWG || dhcp.calls.Load() != wantDHCP {
			t.Fatalf("unrelated mutation at %d: av=%d wg=%d dhcp=%d", i, av.calls.Load(), wgCalls, dhcp.calls.Load())
		}
	}
}

func TestServiceRetryEndpointRepairsOnlyDHCP(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	var fail atomic.Bool
	fail.Store(true)
	dhcp, av := &runtimeDHCPApplier{fail: &fail}, &runtimeAVApplier{}
	wgCalls := 0
	wg := fakeWireGuard(func(context.Context, config.WireGuardConfig) error { wgCalls++; return nil })
	h := c.admit("services", serviceApplyHandler(zap.NewNop().Sugar(), dp, nil, dhcp, av, nil, wg))
	if w := coordinatedPost(c, h, "retry", `{}`); w.Code != 200 {
		t.Fatalf("services: %d %s", w.Code, w.Body)
	}
	beforeAV, beforeWG := av.DeliveryOutcome(), wg.observation()
	fail.Store(false)
	if w := coordinatedPost(c, c.retryHandler(nil), "retry", `{"bootId":"`+engineBootID+`"}`); w.Code != 202 {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	if av.calls.Load() != 1 || wgCalls != 1 || dhcp.calls.Load() != 2 {
		t.Fatalf("retry mutated healthy owners: av=%d wg=%d dhcp=%d", av.calls.Load(), wgCalls, dhcp.calls.Load())
	}
	if av.DeliveryOutcome().ObservedAt != beforeAV.ObservedAt || wg.observation().ObservedAt != beforeWG.ObservedAt {
		t.Fatal("retry replaced healthy acknowledgements")
	}
	if out := subsystem(t, dp.Protection(), protection.SubsystemDHCP); out.Acknowledged == nil {
		t.Fatalf("DHCP not recovered: %+v", out)
	}
}

func TestFreshAttemptOwnerProofsReduceReady(t *testing.T) {
	dp := &adoptionPlane{countingDP: newCountingDP(t)}
	c := testProtectionCoordinator(t, dp)
	logger := zap.NewNop().Sugar()
	conf := configHandler(logger, dp, &simulationManager{dpEngine: dp.Engine}, c)
	rules := applyRulesHandler(dp.Engine, nil, c, nil)
	var fail atomic.Bool
	dhcp, av := &runtimeDHCPApplier{fail: &fail}, &runtimeAVApplier{}
	wgCalls := 0
	svc := c.admit("services", serviceApplyHandler(logger, dp.Engine, nil, dhcp, av, nil, fakeWireGuard(func(context.Context, config.WireGuardConfig) error { wgCalls++; return nil })))
	// Namespace fakes complete owner operations; adoption of capture and policy
	// below still uses the real engine's equality checks and live callbacks.
	interfaces := c.admit("interfaces", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	routing := c.admit("routing", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	local := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
	local.DHCP = nil // DHCP runtime is the engine owner, not the render-only owner.
	for _, id := range []string{"original", "fresh"} {
		for _, phase := range []struct {
			handler http.Handler
			body    string
		}{
			{interfaces, `[]`}, {routing, `{}`}, {svc, `{}`},
			{conf, `{"enforcement":true,"nfqueueGroup":101,"dpiEnabled":true,"dpiMode":"monitor"}`},
		} {
			if w := coordinatedPost(c, phase.handler, id, phase.body); w.Code != 200 {
				t.Fatalf("phase: %d %s", w.Code, w.Body)
			}
		}
		if err := dp.waitStart(t); err != nil {
			t.Fatal(err)
		}
		if w := coordinatedPost(c, rules, id, `{}`); w.Code != 200 {
			t.Fatalf("rules: %d %s", w.Code, w.Body)
		}
		management, err := local.ApplyDelivery(context.Background(), c.metadata, config.ServicesConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		st := dp.Protection()
		outcomes := append(management.Outcomes, st.Subsystems...)
		reduced := protection.Reduce(protection.Input{DesiredRevision: c.metadata.RunningRevision, Current: c.metadata,
			Engine: st.Observation(), Outcomes: outcomes, Coherent: true, EnforcementEnabled: true})
		if !reduced.Ready {
			t.Fatalf("fresh owner proofs did not converge: %+v", reduced)
		}
	}
	if dp.reconfigs.Load() != 1 || dp.runner.starts.Load() != 1 || wgCalls != 1 || av.calls.Load() != 1 || dhcp.calls.Load() != 1 {
		t.Fatal("fresh attempt restarted a healthy owner")
	}
}

func TestServiceLiveLedgerCannotResurrectInvalidatedProof(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	av := services.NewAVManager(context.Background(), services.AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	t.Cleanup(func() {
		if err := av.Stop(); err != nil {
			t.Error(err)
		}
	})
	h := c.admit("services", serviceApplyHandler(zap.NewNop().Sugar(), dp, nil, nil, av, nil,
		fakeWireGuard(func(context.Context, config.WireGuardConfig) error { return nil })))
	if w := coordinatedPost(c, h, "live-ledger", `{}`); w.Code != 200 {
		t.Fatalf("services: %d %s", w.Code, w.Body)
	}
	if out := subsystem(t, dp.Protection(), protection.SubsystemAV); out.Acknowledged == nil {
		t.Fatalf("missing initial proof: %+v", out)
	}
	// Operational/unlabelled mutation clears the owner's identity. The engine
	// must not fall back to a previously copied acknowledgement for that owner.
	if err := av.Apply(context.Background(), config.AVConfig{}); err != nil {
		t.Fatal(err)
	}
	for _, out := range dp.Protection().Subsystems {
		if out.Name == protection.SubsystemAV && out.Acknowledged != nil {
			t.Fatalf("resurrected stale proof: %+v", out)
		}
	}
}
