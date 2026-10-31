// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestMonitorRulesCounterOnly(t *testing.T) {
	for _, protocol := range []string{"modbus", "iec104"} {
		for _, queue := range []int{0, 101} {
			for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
				snap := &rules.Snapshot{DPIMode: "enforce", Default: rules.ActionAllow, Firewall: []rules.Entry{{ID: "trial", Action: action, ICS: rules.ICSPredicate{Protocol: protocol, Mode: "monitor"}}}}
				c := NewCompiler()
				c.QueueID = queue
				text, err := c.CompileFirewall(snap)
				if err != nil {
					t.Fatal(err)
				}
				if c.SteersIEC104(snap) || strings.Contains(text, "chain iec104_envelope") {
					t.Fatalf("monitor opens envelope:\n%s", text)
				}
				if strings.Contains(text, "queue num") != (queue > 0) {
					t.Fatalf("observation steering:\n%s", text)
				}
				counted := false
				for _, line := range strings.Split(text, "\n") {
					if !strings.Contains(line, counterStmt("trial")) {
						continue
					}
					counted = true
					if strings.Contains(line, "accept") || strings.Contains(line, "drop") || strings.Contains(line, "reject") {
						t.Fatalf("terminal monitor line: %s", line)
					}
					if queue > 0 {
						if !strings.Contains(line, unobservedGuard) || !(strings.Contains(line, "jump "+ICSQueueChain) || strings.Contains(line, "jump "+monitorIECChain)) {
							t.Fatalf("unguarded observation: %s", line)
						}
					} else if strings.Contains(line, "jump") {
						t.Fatal(line)
					}
				}
				if counted != (queue > 0) {
					t.Fatal("no monitor counter line")
				}
				if _, err := RuleCounts(snap, map[string]CounterValue{ruleCounterName("trial"): {}}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestConditionalMonitorNeverRechecksOrAdmits(t *testing.T) {
	snap := &rules.Snapshot{DPIMode: "monitor", Default: rules.ActionDeny, Firewall: []rules.Entry{{
		ID: "trial", Action: rules.ActionAllow, Identities: []string{"unbound"},
		Schedule: maintenanceWindow, ICS: rules.ICSPredicate{Protocol: "modbus"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
	}}}
	p, err := newPredicates(snap, 101)
	if err != nil {
		t.Fatal(err)
	}
	entry := snap.Firewall[0]
	if p.kernelGuarded(entry) {
		t.Fatal("conditional monitor participates in kernel decisions")
	}
	c := goldenCompiler()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "chain conditional_policy") || strings.Contains(text, "chain conditional_scope") {
		t.Fatalf("monitor installed decision recheck chains:\n%s", text)
	}
	if !strings.Contains(text, unobservedGuard+" "+untrackedState+" tcp dport 502 "+counterStmt(entry.ID)+" jump "+ICSQueueChain) {
		t.Fatalf("monitor observation was narrowed by unresolved identity:\n%s", text)
	}
}
