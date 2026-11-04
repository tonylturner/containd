// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

type recoveryPlane struct{ *countingDP }

func (p *recoveryPlane) Reconfigure(fresh *engine.Engine) error {
	fresh.Close()
	next, err := engine.New(engine.Config{Events: p.Events(),
		Enforce: engine.EnforceConfig{Enabled: true, Applier: adoptionApplier{}, ClearMark: noPolicyMarks}})
	if err != nil {
		return err
	}
	return p.Engine.Reconfigure(next)
}

func (p *recoveryPlane) StartProtection(context.Context, context.Context) error { return nil }

func TestProtectionRecoveryOrderAndAddressWarning(t *testing.T) {
	dp := &recoveryPlane{newCountingDP(t)}
	c := testProtectionCoordinator(t, dp)
	m := protocolMetadata("refused-running")
	configure := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine}, c)
	apply := applyRulesHandler(dp.Engine, nil, c, nil)
	// Recovery does not require any normal running revision, interfaces, trust,
	// routing or services acknowledgement. It does require its own safe order.
	m.Mode = protection.ModeRecovery
	m.RunningRevision = protection.RecoveryRevision(m.BootID)
	snap := rules.Snapshot{Version: config.ManagementRecoveryVersion, Default: rules.ActionDeny,
		LocalInput: []rules.LocalServiceRule{{ID: "auto-allow-mgmt-http", Proto: "tcp", Port: 8080, Ifaces: []string{"mgmt0"}}}}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if w := protocolPost(apply, m, "", string(body)); w.Code != 409 || c.current != "" {
		t.Fatalf("rules before configure: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(configure, m, "", `{"enforcement":false}`); w.Code != 409 {
		t.Fatalf("unsafe recovery dataplane: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(configure, m, "", `{"enforcement":true}`); w.Code != 200 {
		t.Fatalf("configure: %d %s", w.Code, w.Body)
	}
	addressCalls := 0
	address := c.admit("interfaces", func(w http.ResponseWriter, _ *http.Request) {
		addressCalls++
		http.Error(w, "address unavailable", http.StatusBadRequest)
	})
	if w := protocolPost(address, m, "", `[{"name":"mgmt0","addresses":["192.0.2.1/24"]}]`); w.Code != 409 || addressCalls != 0 {
		t.Fatalf("address before rules: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(apply, m, "", string(body)); w.Code != 200 {
		t.Fatalf("recovery install: %d %s", w.Code, w.Body)
	}
	before := dp.Protection()
	if before.Installed == nil || before.Installed.Metadata != m || before.State != "protecting" {
		t.Fatalf("recovery installation: %+v", before)
	}
	script := dp.RulesetStatus().Ruleset
	if !strings.Contains(script, "policy drop") || !strings.Contains(script, "8080") || !strings.Contains(script, "mgmt0") {
		t.Fatalf("recovery must retain management and drop new transit: %s", script)
	}
	for _, phase := range []string{"routing", "trust", "services"} {
		h := c.admit(phase, func(http.ResponseWriter, *http.Request) { t.Fatal("ordinary prerequisite admitted in recovery") })
		if w := protocolPost(h, m, "", `{}`); w.Code != 409 {
			t.Fatalf("ordinary phase %s: %d %s", phase, w.Code, w.Body)
		}
	}
	if w := protocolPost(address, m, "", `[{"name":"other","addresses":["192.0.2.1/24"]}]`); w.Code != 409 {
		t.Fatalf("unadmitted recovery address: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(address, m, "", `[{"name":"mgmt0","addresses":["192.0.2.1/24"]}]`); w.Code != 400 || addressCalls != 1 {
		t.Fatalf("address warning: %d %s", w.Code, w.Body)
	}
	after := dp.Protection()
	if after.Installed == nil || *after.Installed != *before.Installed || after.State == "pending" ||
		subsystem(t, after, protection.SubsystemNFT).State != protection.DeliveryReady {
		t.Fatalf("address warning invalidated recovery nft: %+v", after)
	}
	// A later transition and recovery reentry both need fresh attempts. Neither
	// delayed narrowed work nor the old recovery identity can overwrite them.
	normal := protocolMetadata("normal-transition")
	if w := protocolPost(configure, normal, string(m.ApplyID), `{"enforcement":true}`); w.Code != 200 {
		t.Fatalf("normal transition: %d %s", w.Code, w.Body)
	}
	reentry := m
	reentry.ApplyID = "reentry"
	if w := protocolPost(configure, reentry, string(normal.ApplyID), `{"enforcement":true}`); w.Code != 200 {
		t.Fatalf("reentry: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(apply, reentry, "", string(body)); w.Code != 200 {
		t.Fatalf("reentry rules: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(apply, normal, string(reentry.ApplyID), `{}`); w.Code != 409 {
		t.Fatalf("delayed normal work admitted: %d %s", w.Code, w.Body)
	}
	if w := protocolPost(apply, m, string(reentry.ApplyID), string(body)); w.Code != 409 {
		t.Fatalf("old recovery work admitted: %d %s", w.Code, w.Body)
	}
}
