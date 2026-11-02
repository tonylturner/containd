// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

type runtimeDHCPApplier struct {
	calls atomic.Int32
	fail  *atomic.Bool
}

func (a *runtimeDHCPApplier) Apply(context.Context, config.DHCPConfig, []config.Interface) error {
	a.calls.Add(1)
	if a.fail.Load() {
		return errors.New("DHCP backend refused secret-material")
	}
	return nil
}

type runtimeAVApplier struct{ calls atomic.Int32 }

func (a *runtimeAVApplier) Apply(context.Context, config.AVConfig) error {
	a.calls.Add(1)
	return nil
}

func TestServiceRuntimeWireGuardDisableVerified(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	m := protocolMetadata("disable")
	if w := protocolPost(applyRulesHandler(dp, nil, c, nil), m, "", `{}`); w.Code != 200 {
		t.Fatalf("rules: %d %s", w.Code, w.Body)
	}
	installed := dp.Protection().Installed
	running, fail := true, true
	h := c.admit("services", serviceApplyHandler(zap.NewNop().Sugar(), dp, nil, nil, nil, nil,
		func(context.Context, config.WireGuardConfig) error {
			if fail {
				return errors.New("stop failed")
			}
			running = false
			return nil
		}))
	for _, failure := range []bool{true, false} {
		fail = failure
		if w := protocolPost(h, m, "", `{}`); w.Code != 200 {
			t.Fatalf("services: %d %s", w.Code, w.Body)
		}
		o := subsystem(t, dp.Protection(), protection.SubsystemWireGuard)
		st := dp.Protection()
		if st.State == "pending" || st.Installed == nil || installed == nil || *st.Installed != *installed {
			t.Fatalf("service retry invalidated installed policy: %+v", st)
		}
		if o.Operation != protection.OperationStop || running != failure ||
			(o.Acknowledged == nil) != failure {
			t.Fatalf("unverified WireGuard teardown: %+v running=%v", o, running)
		}
		if !failure && (o.State != protection.DeliveryOff || o.Acknowledged.Operation != protection.OperationStop) {
			t.Fatalf("missing verified stop: %+v", o)
		}
	}
}

func TestServiceRuntimeFaultReplay(t *testing.T) {
	for _, service := range []string{config.ServiceWireGuard, config.ServiceDHCP} {
		t.Run(service, func(t *testing.T) {
			dp := newCountingDP(t)
			c := testProtectionCoordinator(t, dp)
			var failWG, failDHCP atomic.Bool
			failWG.Store(service == config.ServiceWireGuard)
			failDHCP.Store(service == config.ServiceDHCP)
			dhcp := &runtimeDHCPApplier{fail: &failDHCP}
			av := &runtimeAVApplier{}
			var wgCalls atomic.Int32
			applyWG := func(context.Context, config.WireGuardConfig) error {
				wgCalls.Add(1)
				if failWG.Load() {
					return errors.New("WireGuard backend refused secret-material")
				}
				return nil
			}
			gate := &gateManager{}
			handler := c.admit("services", serviceApplyHandler(zap.NewNop().Sugar(), dp.Engine, nil, dhcp, av, gate, applyWG))
			apply := applyRulesHandler(dp.Engine, gate, c, nil)
			svc := config.ServicesConfig{}
			if err := json.Unmarshal([]byte(`{"av":{"scan":{"include":[{"destPorts":["80"]}]}}}`), &svc); err != nil {
				t.Fatal(err)
			}
			svc.VPN.WireGuard.Enabled = true
			svc.DHCP.Enabled = true
			// The backend is quarantined but the selected fail-closed policy survives.
			svc.AV.Enabled, svc.AV.BackendDisabled = true, true
			svc.AV.FailPolicy, svc.AV.HTTPDownload = "closed", true
			body, err := json.Marshal(svc)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 3 {
				if i == 2 {
					failWG.Store(false)
					failDHCP.Store(false)
				}
				w := coordinatedPost(c, handler, "runtime", string(body))
				var result struct {
					Faults []config.ServiceFault `json:"faults"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
					t.Fatalf("services: %d %s", w.Code, w.Body)
				}
				if strings.Contains(w.Body.String(), "secret-material") {
					t.Fatalf("secret leaked: %s", w.Body)
				}
				if i < 2 && (len(result.Faults) != 1 || result.Faults[0].Service != service) {
					t.Fatalf("fault attribution: %+v", result)
				}
				if i == 2 && len(result.Faults) != 0 {
					t.Fatalf("recovery retained fault: %+v", result)
				}
				if !gate.av.Enabled || !gate.av.ScanGateEnabled() {
					t.Fatal("quarantine removed selected policy")
				}
				if w := coordinatedPost(c, apply, "runtime", `{}`); w.Code != 200 {
					t.Fatalf("rules blocked: %d %s", w.Code, w.Body)
				}
				var found bool
				for _, o := range dp.Protection().Subsystems {
					if string(o.Name) == service {
						found = true
						if (o.Acknowledged != nil) != (i == 2) {
							t.Fatalf("owner proof: %+v", o)
						}
					}
				}
				if !found {
					t.Fatalf("missing outcome for %s", service)
				}
			}
			if wgCalls.Load() != 3 || dhcp.calls.Load() != 3 || av.calls.Load() != 3 {
				t.Fatal("runtime fault prevented owner retry")
			}
			events, err := json.Marshal(dp.Events().List(100))
			if err != nil || strings.Contains(string(events), "secret-material") {
				t.Fatalf("secret-bearing runtime diagnostic: %s %v", events, err)
			}
		})
	}
}
