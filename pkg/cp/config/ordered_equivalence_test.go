// SPDX-License-Identifier: Apache-2.0
package config_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func legacyDecision(s *rules.Snapshot, ctx rules.EvalContext, iec bool) (rules.Action, string) {
	for _, i := range rules.DecisionOrder(s.Firewall) {
		e := s.Firewall[i]
		if rules.MonitorICS(e, s.DPIMode) || iec && e.ICS.Protocol != "iec104" {
			continue
		}
		if rules.PreviewMatch(e, ctx) {
			return e.Action, e.ID
		}
	}
	if !iec && s.Default == rules.ActionAllow {
		return rules.ActionAllow, ""
	}
	return rules.ActionDeny, ""
}

func decisionID(entry *rules.Entry) string {
	if entry == nil {
		return ""
	}
	return entry.ID
}

func TestOrderedMigrationEvaluatorCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(110))
	actions := []config.Action{config.ActionAllow, config.ActionDeny, config.ActionReset}
	contexts, configs := 0, 96
	for n := range configs {
		c := config.DefaultConfig()
		c.DataPlane.DPIMode, c.DataPlane.NFQueueGroup = "enforce", 101
		if n%2 == 0 {
			c.Firewall.DefaultAction = config.ActionAllow
		}
		c.Firewall.Rules = nil
		for i := range 8 {
			r := config.Rule{ID: fmt.Sprintf("r-%d", i), Action: actions[(n+i)%3]}
			if i%2 == 0 {
				r.Sources = []string{"198.51.100.0/25"}
			}
			if i%3 == 0 {
				r.SourceZones = []string{"wan"}
			}
			if i%2 == 1 {
				r.Protocols = []config.Protocol{{Name: "tcp", Port: "502"}}
			}
			if i%3 == 1 && r.Action != config.ActionReset {
				r.ICS = config.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}
				if i%2 == 0 {
					r.ICS.Mode = "monitor"
				}
			}
			if i%4 == 0 {
				r.Identities = []string{"operator"}
				r.Schedule = &config.ScheduleConfig{StartTime: "08:00", EndTime: "16:00", Timezone: "UTC"}
			}
			c.Firewall.Rules = append(c.Firewall.Rules, r)
		}
		rng.Shuffle(len(c.Firewall.Rules), func(i, j int) {
			c.Firewall.Rules[i], c.Firewall.Rules[j] = c.Firewall.Rules[j], c.Firewall.Rules[i]
		})
		effect := config.Rule{ID: "tag", Action: config.ActionTag, Tag: "site"}
		c.Firewall.Rules = append(c.Firewall.Rules[:3], append([]config.Rule{effect}, c.Firewall.Rules[3:]...)...)
		before, err := compile.CompileSnapshot(c)
		if err != nil {
			t.Fatal(err)
		}
		c.SchemaVersion = "0.1.9"
		after, err := compile.CompileSnapshot(c)
		if err != nil {
			t.Fatal(err)
		}
		if c.Firewall.Rules[3].ID != effect.ID {
			t.Fatal("effect slot moved")
		}
		ev := rules.NewEvaluator(&after)
		for _, src := range []string{"198.51.100.1", "198.51.100.200"} {
			for _, zone := range []string{"wan", "lan"} {
				for _, port := range []string{"502", "8080"} {
					for _, fc := range []int{-1, 3, 6} {
						for _, identity := range []string{"operator", "guest"} {
							for _, hour := range []int{10, 20} {
								ctx := rules.EvalContext{SrcIP: net.ParseIP(src), DstIP: net.ParseIP("10.0.0.8"),
									SrcZone: zone, DstZone: "lan", Proto: "tcp", Port: port,
									Identities: []string{identity}, Now: time.Date(2026, 10, 26, hour, 0, 0, 0, time.UTC)}
								if fc >= 0 {
									ctx.ICS = &rules.ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: uint8(fc)}
								}
								wantAction, wantID := legacyDecision(&before, ctx, false)
								action, winner := ev.EvaluateEnforcing(ctx)
								if action != wantAction || decisionID(winner) != wantID {
									t.Fatalf("config %d context %+v: %s/%s, want %s/%s", n, ctx, action, decisionID(winner), wantAction, wantID)
								}
								contexts++
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d configurations, %d exact verdict/winner comparisons; forwards inside=0 partial=0 no-overlap=0", configs, contexts)
}

func TestOrderedMigrationRangerDangerCorpus(t *testing.T) {
	for _, name := range []string{"substation-weak.json", "substation-improved.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "rangerdanger", name))
			if err != nil {
				t.Fatal(err)
			}
			var legacy config.Config
			if err := json.Unmarshal(raw, &legacy); err != nil {
				t.Fatal(err)
			}
			current := legacy
			current.SchemaVersion = config.SchemaVersionCurrent
			before, err := compile.CompileSnapshot(&current)
			if err != nil {
				t.Fatal(err)
			}
			after, err := compile.CompileSnapshot(&legacy)
			if err != nil {
				t.Fatal(err)
			}
			ev := rules.NewEvaluator(&after)
			count := 0
			for _, src := range []string{"10.10.10.5", "10.20.20.5", "10.30.30.20", "10.40.40.10"} {
				for _, srcZone := range []string{"wan", "dmz", "lan1", "lan2"} {
					for _, dstZone := range []string{"wan", "dmz", "lan1", "lan2"} {
						for _, fc := range []uint8{3, 6, 16} {
							ctx := rules.EvalContext{SrcIP: net.ParseIP(src), DstIP: net.ParseIP("10.40.40.10"), SrcZone: srcZone,
								DstZone: dstZone, Proto: "tcp", Port: "502",
								ICS: &rules.ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: fc}}
							wantAction, wantID := legacyDecision(&before, ctx, false)
							action, winner := ev.EvaluateEnforcing(ctx)
							if action != wantAction || decisionID(winner) != wantID {
								t.Fatalf("context %+v: %s/%s, want %s/%s", ctx, action, decisionID(winner), wantAction, wantID)
							}
							count++
						}
					}
				}
			}
			t.Logf("%d comparisons; %d forwards", count, len(legacy.Firewall.NAT.PortForwards))
		})
	}
}

func TestOrderedMigrationIECCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(104))
	comparisons := 0
	for n := range 24 {
		c := config.DefaultConfig()
		c.DataPlane.DPIMode, c.DataPlane.NFQueueGroup = "enforce", 101
		c.DataPlane.DPIICSProtocols = map[string]bool{"iec104": true}
		c.Firewall.DefaultAction = config.ActionAllow // IEC's unmatched default remains DENY.
		c.Firewall.Rules = []config.Rule{
			{ID: "z-read", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "iec104", ReadOnly: true}},
			{ID: "a-command", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}}},
			{ID: "b-deny", Action: config.ActionDeny, ICS: config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{45}}},
			{ID: "monitor", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "iec104", Mode: "monitor"}},
			{ID: "plain", Action: config.ActionAllow},
		}
		rng.Shuffle(len(c.Firewall.Rules), func(i, j int) { c.Firewall.Rules[i], c.Firewall.Rules[j] = c.Firewall.Rules[j], c.Firewall.Rules[i] })
		before, err := compile.CompileSnapshot(c)
		if err != nil {
			t.Fatal(err)
		}
		c.SchemaVersion = "0.1.9"
		after, err := compile.CompileSnapshot(c)
		if err != nil {
			t.Fatal(err)
		}
		ev := rules.NewEvaluator(&after)
		for _, typeID := range []uint8{1, 45, 46, 47} {
			for _, direction := range []string{"request", "response"} {
				ctx := rules.EvalContext{Proto: "tcp", Port: "2404",
					ICS: &rules.ICSContext{Protocol: "iec104", Direction: direction,
						IEC104: &rules.IEC104Context{APCIType: "I", TypeID: &typeID, SafeRead: typeID == 1}}}
				action, winner := ev.EvaluateIEC104Enforcing(ctx)
				wantAction, wantID := legacyDecision(&before, ctx, true)
				if action != wantAction || decisionID(winner) != wantID {
					t.Fatalf("config %d IEC context %+v: %s/%s, want %s/%s", n, ctx, action, decisionID(winner), wantAction, wantID)
				}
				comparisons++
			}
		}
	}
	t.Logf("24 IEC configurations, %d exact verdict/winner comparisons", comparisons)
}

func TestPartialForwardPreservesInspectionAndUnrelatedPolicy(t *testing.T) {
	c := config.DefaultConfig()
	c.SchemaVersion = "0.1.9"
	c.DataPlane.DPIMode, c.DataPlane.NFQueueGroup = "enforce", 101
	c.Firewall.NAT.PortForwards = []config.PortForward{{ID: "process", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: 1502, DestIP: "10.0.0.8", DestPort: 502}}
	c.Firewall.Rules = []config.Rule{
		{ID: "reads", Action: config.ActionAllow, Sources: []string{"198.51.100.0/25"}, Protocols: []config.Protocol{{Name: "tcp", Port: "502"}}, ICS: config.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}},
		{ID: "other-service", Action: config.ActionAllow, Protocols: []config.Protocol{{Name: "tcp", Port: "443"}}},
	}
	snap, err := compile.CompileSnapshot(c)
	if err != nil {
		t.Fatal(err)
	}
	ev := rules.NewEvaluator(&snap)
	for _, p := range []struct {
		src, port, id string
		fc            uint8
		action        rules.Action
	}{
		{"198.51.100.1", "502", "reads", 3, rules.ActionAllow},
		{"198.51.100.1", "502", "", 6, rules.ActionDeny},
		{"198.51.100.200", "502", "", 3, rules.ActionDeny},
		{"198.51.100.200", "443", "other-service", 3, rules.ActionAllow},
	} {
		ctx := rules.EvalContext{SrcIP: net.ParseIP(p.src), DstIP: net.ParseIP("10.0.0.8"), SrcZone: "wan", DstZone: "lan", Proto: "tcp", Port: p.port,
			ICS: &rules.ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: p.fc}}
		action, winner := ev.EvaluateMessage(ctx, false)
		if action != p.action || decisionID(winner) != p.id {
			t.Fatalf("%+v: %s/%s", p, action, decisionID(winner))
		}
	}
	if len(config.ForwardWarnings(c)) != 1 || !reflect.DeepEqual(snap.Firewall[0].ViaForwards, []string(nil)) {
		t.Fatal("partial grant generated or warning missing")
	}
}
