// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestUninspectableEnforceCompilation(t *testing.T) {
	for _, proto := range []string{"modbus", "dnp3", "iec104"} {
		for _, cause := range []string{"master", "decoder", "ip", "cidr"} {
			for _, action := range []config.Action{config.ActionAllow, config.ActionDeny} {
				t.Run(fmt.Sprintf("%s/%s/%s", proto, cause, action), func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.DataPlane.DPIMode = "enforce"
					cfg.DataPlane.NFQueueGroup = 101
					cfg.DataPlane.DPIEnabled = cause != "master"
					if cause == "decoder" {
						cfg.DataPlane.DPIICSProtocols = map[string]bool{proto: false}
					}
					if cause == "ip" {
						cfg.DataPlane.DPIExclusions = []config.DPIExclusion{{Type: "ip", Value: "10.30.30.30"}}
					}
					if cause == "cidr" {
						cfg.DataPlane.DPIExclusions = []config.DPIExclusion{{Type: "cidr", Value: "10.60.0.0/16"}}
					}
					cfg.Firewall.Rules = []config.Rule{{ID: "guard", Action: action, Log: true, ICS: config.ICSPredicate{Protocol: proto, Mode: "enforce", ReadOnly: true}}}
					snap, err := CompileSnapshot(cfg)
					if err != nil {
						t.Fatal(err)
					}
					c := enforce.NewCompiler()
					c.QueueID = 101
					c.NFLogGroup = 100
					warnings := c.RuleWarnings(&snap)
					wantCause := map[string]string{"master": "DPI is off", "decoder": proto + " decoder is off", "ip": "DPI exclusion 10.30.30.30", "cidr": "DPI exclusion 10.60.0.0/16"}[cause]
					found := false
					for _, w := range warnings {
						if w.RuleID == "guard" && w.Predicate == enforce.PredicateInspection && strings.Contains(w.Message, "drops") && strings.Contains(w.Message, wantCause) {
							found = true
						}
					}
					if !found {
						t.Errorf("no fail-closed warning: %+v", warnings)
					}
					text, err := c.CompileFirewall(&snap)
					if err != nil {
						t.Fatal(err)
					}
					if cause == "master" || cause == "decoder" {
						port := map[string]string{"modbus": "502", "dnp3": "20000", "iec104": "2404"}[proto]
						for _, clause := range []string{"tcp dport " + port + " goto ics_uninspectable_0", "ct reply proto-src " + port + " goto ics_uninspectable_0"} {
							if !strings.Contains(text, clause) {
								t.Errorf("missing scope clause %q", clause)
							}
						}
						if !strings.Contains(text, `log prefix "containd:guard:DENY "`) || !strings.Contains(text, "goto ics_uninspectable_0") {
							t.Errorf("no logged transport drop")
						}
					}
				})
			}
		}
	}
}
