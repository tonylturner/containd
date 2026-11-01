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
	for _, corpus := range []struct {
		name string
		eu   bool
	}{
		{name: "substation-weak.json"},
		{name: "substation-improved.json"},
		{name: "eu-weak.json", eu: true},
		{name: "eu-improved.json", eu: true},
	} {
		t.Run(corpus.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "rangerdanger", corpus.name))
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
			if corpus.eu {
				// Course subnets are per-zone; lan3 uses the management reservation.
				zoneSubnets := map[string]string{
					"wan":  "10.10.10.0/24",
					"dmz":  "10.20.20.0/24",
					"lan1": "10.30.30.0/24",
					"lan2": "10.40.40.0/24",
					"lan3": "10.99.99.0/24",
					"lan4": "10.60.60.0/24",
					"lan5": "10.70.70.0/24",
				}
				var zones []string
				namedZones := make(map[string]bool)
				for _, rule := range legacy.Firewall.Rules {
					for _, zone := range append(append([]string(nil), rule.SourceZones...), rule.DestZones...) {
						namedZones[zone] = true
					}
				}
				for _, zone := range []string{"wan", "dmz", "lan1", "lan2", "lan3", "lan4", "lan5"} {
					if namedZones[zone] {
						zones = append(zones, zone)
					}
				}
				if len(zones) != len(namedZones) {
					t.Fatalf("policy names zones without course subnets: %v", namedZones)
				}

				sourceIPsByZone := make(map[string][]string)
				destinationIPsByZone := make(map[string][]string)
				addUnique := func(ips []string, ip string) []string {
					for _, existing := range ips {
						if existing == ip {
							return ips
						}
					}
					return append(ips, ip)
				}
				for _, rule := range legacy.Firewall.Rules {
					sourceZones, destinationZones := rule.SourceZones, rule.DestZones
					if len(sourceZones) == 0 {
						sourceZones = zones
					}
					if len(destinationZones) == 0 {
						destinationZones = zones
					}
					for _, cidr := range rule.Sources {
						ip, _, err := net.ParseCIDR(cidr)
						if err != nil {
							t.Fatalf("rule %s source %q: %v", rule.ID, cidr, err)
						}
						for _, zone := range sourceZones {
							sourceIPsByZone[zone] = addUnique(sourceIPsByZone[zone], ip.String())
						}
					}
					for _, cidr := range rule.Destinations {
						ip, _, err := net.ParseCIDR(cidr)
						if err != nil {
							t.Fatalf("rule %s destination %q: %v", rule.ID, cidr, err)
						}
						for _, zone := range destinationZones {
							destinationIPsByZone[zone] = addUnique(destinationIPsByZone[zone], ip.String())
						}
					}
				}
				for _, zone := range zones {
					ip, _, err := net.ParseCIDR(zoneSubnets[zone])
					if err != nil {
						t.Fatal(err)
					}
					unnamed := append(net.IP(nil), ip.To4()...)
					unnamed[3] = 250
					sourceIPsByZone[zone] = addUnique(sourceIPsByZone[zone], unnamed.String())
					destinationIPsByZone[zone] = addUnique(destinationIPsByZone[zone], unnamed.String())
				}

				var zonePairs [][2]string
				seenPairs := make(map[[2]string]bool)
				for _, rule := range legacy.Firewall.Rules {
					sourceZones, destinationZones := rule.SourceZones, rule.DestZones
					if len(sourceZones) == 0 {
						sourceZones = zones
					}
					if len(destinationZones) == 0 {
						destinationZones = zones
					}
					for _, sourceZone := range sourceZones {
						for _, destinationZone := range destinationZones {
							pair := [2]string{sourceZone, destinationZone}
							if !seenPairs[pair] {
								seenPairs[pair] = true
								zonePairs = append(zonePairs, pair)
							}
						}
					}
				}

				var ports []string
				for _, rule := range legacy.Firewall.Rules {
					for _, protocol := range rule.Protocols {
						if protocol.Name != "tcp" {
							t.Fatalf("EU policy %s rule %s uses non-TCP protocol %q", corpus.name, rule.ID, protocol.Name)
						}
						if protocol.Port != "" {
							ports = addUnique(ports, protocol.Port)
						}
					}
				}

				var typeIDs []uint8
				var ioas []uint32
				seenTypeIDs := make(map[uint8]bool)
				seenIOAs := make(map[uint32]bool)
				for _, rule := range legacy.Firewall.Rules {
					if rule.ICS.Protocol != "iec104" || rule.ICS.Mode != "monitor" {
						continue
					}
					for _, id := range rule.ICS.TypeIDs {
						typeID := uint8(id)
						if !seenTypeIDs[typeID] {
							seenTypeIDs[typeID] = true
							typeIDs = append(typeIDs, typeID)
						}
					}
					for _, selected := range rule.ICS.IOA {
						for ioa := selected.Start; ioa <= selected.End; ioa++ {
							if !seenIOAs[ioa] {
								seenIOAs[ioa] = true
								ioas = append(ioas, ioa)
							}
						}
					}
				}
				otherTypeID := uint8(1)
				for {
					found := false
					for _, id := range typeIDs {
						if id == otherTypeID {
							found = true
							break
						}
					}
					if !found {
						break
					}
					otherTypeID++
				}
				typeIDs = append(typeIDs, otherTypeID)
				otherIOA := uint32(1)
				for {
					found := false
					for _, ioa := range ioas {
						if ioa == otherIOA {
							found = true
							break
						}
					}
					if !found {
						break
					}
					otherIOA++
				}
				ioas = append(ioas, otherIOA)

				count := 0
				compare := func(ctx rules.EvalContext, iec bool) {
					wantAction, wantID := legacyDecision(&before, ctx, iec)
					var action rules.Action
					var winner *rules.Entry
					if iec {
						action, winner = ev.EvaluateIEC104Enforcing(ctx)
					} else {
						action, winner = ev.EvaluateEnforcing(ctx)
					}
					if action != wantAction || decisionID(winner) != wantID {
						t.Fatalf("policy %s context %+v: upgraded %s/%s, legacy %s/%s",
							corpus.name, ctx, action, decisionID(winner), wantAction, wantID)
					}
					count++
				}
				for _, pair := range zonePairs {
					for _, src := range sourceIPsByZone[pair[0]] {
						for _, dst := range destinationIPsByZone[pair[1]] {
							for _, port := range ports {
								base := rules.EvalContext{
									SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst),
									SrcZone: pair[0], DstZone: pair[1], Proto: "tcp", Port: port,
								}
								switch port {
								case "2404":
									for _, typeID := range typeIDs {
										for _, ioa := range ioas {
											for _, direction := range []string{"request", "response"} {
												ca := uint16(1)
												typeID, ioa := typeID, ioa
												ctx := base
												ctx.ICS = &rules.ICSContext{
													Protocol: "iec104", Direction: direction,
													IEC104: &rules.IEC104Context{
														APCIType: "I", TypeID: &typeID, CA: &ca, IOA: &ioa,
													},
												}
												compare(ctx, false)
												compare(ctx, true)
											}
										}
									}
								case "502":
									for _, functionCode := range []uint8{3, 6, 16} {
										ctx := base
										ctx.ICS = &rules.ICSContext{
											Protocol: "modbus", HasFunctionCode: true, FunctionCode: functionCode,
										}
										compare(ctx, false)
									}
								default:
									compare(base, false)
								}
							}
						}
					}
				}
				t.Logf("%d EU zone-pair/address/port/context comparisons", count)
				return
			}

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
