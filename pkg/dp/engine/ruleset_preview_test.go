// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestRulesetPreviewEqualsApply(t *testing.T) {
	reservation := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"),
		Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	settings := enforce.CompilerSettings{TableName: "candidate_table", NFLogGroup: 203, NFQueueGroup: 207}
	snap := iecSnapshot("enforce")
	snap.Firewall = append(snap.Firewall,
		rules.Entry{ID: "logged", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Log: true, Action: rules.ActionAllow},
		rules.Entry{ID: "modbus", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: rules.ICSPredicate{Protocol: "modbus"}, Action: rules.ActionAllow})
	for _, tc := range []struct {
		name  string
		owned uint16
		open  bool
	}{
		{"unbound", 0, false},
		{"owned", 207, true},
		{"different candidate queue", 101, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applier := &recordingApplier{}
			e, err := New(Config{Enforce: EnforceConfig{Enabled: true, TableName: settings.TableName,
				ManagementReservation: reservation, Applier: applier},
				NFLogGroup: settings.NFLogGroup, NFQueueGroup: settings.NFQueueGroup, ResetInjector: &session.Fake{}})
			if err != nil {
				t.Fatal(err)
			}
			e.gate.own(tc.owned)
			before := *e.compiler
			preview, err := e.PreviewRuleset(snap, settings)
			if err != nil {
				t.Fatal(err)
			}
			if *e.compiler != before || e.gate.installed || e.CurrentRules() != nil || applier.ruleset != "" {
				t.Fatal("preview mutated live enforcement")
			}
			if preview.Runtime.IEC104EnvelopeOpen != tc.open {
				t.Fatalf("runtime = %+v", preview.Runtime)
			}
			if err := e.ApplyRules(context.Background(), snap); err != nil {
				t.Fatal(err)
			}
			if preview.Ruleset != applier.ruleset {
				t.Fatalf("preview differs from apply:\n%s\napply:\n%s", preview.Ruleset, applier.ruleset)
			}
			for _, want := range []string{"table inet candidate_table", "group 203", "tcp dport 502 queue num 207", "ip daddr 10.99.99.2 tcp dport 8080 accept"} {
				if !strings.Contains(preview.Ruleset, want) {
					t.Fatalf("missing %q:\n%s", want, preview.Ruleset)
				}
			}
			before = *e.compiler
			lastStatus := e.RulesetStatus()
			// A preview for a different candidate must not alter the installed
			// compiler, rules, gate decision or last-apply status.
			other := enforce.CompilerSettings{TableName: "other", NFQueueGroup: 209}
			otherPreview, err := e.PreviewRuleset(snap, other)
			if err != nil || otherPreview.Runtime.IEC104EnvelopeOpen || *e.compiler != before || e.RulesetStatus() != lastStatus {
				t.Fatalf("isolated preview = %+v, err=%v", otherPreview.Runtime, err)
			}
			if !strings.Contains(otherPreview.Ruleset, "table inet other") || applier.ruleset != preview.Ruleset {
				t.Fatal("candidate settings ignored or preview applied")
			}
		})
	}
}

func TestRulesetPreviewRejectsManagementShadow(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"),
		Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, ManagementReservation: r}})
	if err != nil {
		t.Fatal(err)
	}
	snap := rules.Snapshot{ZoneIfaces: map[string][]string{"lan": {"eth7"}},
		NAT: rules.NATConfig{PortForwards: []rules.PortForward{{Enabled: true, Proto: "tcp", ListenPort: 8080, IngressZone: "lan"}}}}
	if preview, err := e.PreviewRuleset(snap, enforce.CompilerSettings{}); err == nil || preview.Ruleset != "" {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
}
