// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The shipped RangerDanger US policies (the TestRangerDangerUSPoliciesLoad
// fixtures) decide every probe as before: under allow precedence, and
// under the first-match order the evaluator used until now.
func TestRangerDangerUSPolicyOutcomes(t *testing.T) {
	type probe struct {
		name             string
		srcZone, dstZone string
		src, dst         string
		proto, port      string
		modbusFC         int // -1: no ICS message
		wantAction       rules.Action
		wantRule         string // "" means the default decided
	}
	l4 := -1
	for file, probes := range map[string][]probe{
		"substation-improved.json": {
			{"enterprise to vendor https", "wan", "dmz", "10.10.10.5", "10.20.20.5", "tcp", "443", l4, rules.ActionAllow, "enterprise-to-vendor-only"},
			{"enterprise to OT modbus", "wan", "lan1", "10.10.10.5", "10.30.30.20", "tcp", "502", l4, rules.ActionDeny, "deny-enterprise-to-ot"},
			{"vendor to OT ssh", "dmz", "lan1", "10.20.20.5", "10.30.30.20", "tcp", "22", l4, rules.ActionAllow, "vendor-to-ot-restricted"},
			{"vendor to field modbus", "dmz", "lan2", "10.20.20.5", "10.40.40.10", "tcp", "502", l4, rules.ActionDeny, "deny-vendor-to-field"},
			{"RTAC read coils", "lan1", "lan2", "10.30.30.20", "10.40.40.10", "tcp", "502", 3, rules.ActionAllow, "rtac-to-field-modbus"},
			{"RTAC write multiple registers", "lan1", "lan2", "10.30.30.20", "10.40.40.10", "tcp", "502", 16, rules.ActionDeny, "deny-ot-to-field-direct"},
			{"other OT host read", "lan1", "lan2", "10.30.30.21", "10.40.40.10", "tcp", "502", 3, rules.ActionDeny, "deny-ot-to-field-direct"},
			{"RTAC http", "lan1", "lan2", "10.30.30.20", "10.40.40.10", "tcp", "8080", l4, rules.ActionAllow, "rtac-to-field-http"},
			{"GPS ntp", "lan1", "lan2", "10.30.30.50", "10.40.40.10", "udp", "123", l4, rules.ActionAllow, "gps-to-field-ntp"},
			{"other ntp", "lan1", "lan2", "10.30.30.51", "10.40.40.10", "udp", "123", l4, rules.ActionDeny, ""},
			{"OT intrazone node-red", "lan1", "lan1", "10.30.30.21", "10.30.30.22", "tcp", "1881", l4, rules.ActionAllow, "ot-intrazone-ops"},
		},
		"substation-weak.json": {
			{"enterprise to OT modbus", "wan", "lan1", "10.10.10.5", "10.30.30.20", "tcp", "502", l4, rules.ActionAllow, "enterprise-to-ot-weak"},
			{"enterprise to field rdp", "wan", "lan2", "10.10.10.5", "10.40.40.10", "tcp", "3389", l4, rules.ActionDeny, ""},
			{"OT to field write", "lan1", "lan2", "10.30.30.20", "10.40.40.10", "tcp", "502", 16, rules.ActionAllow, "ot-to-field-broad"},
		},
	} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "cp", "config", "testdata", "rangerdanger", file))
			if err != nil {
				t.Fatal(err)
			}
			var cfg config.Config
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			snap, err := compile.CompileSnapshot(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			ev := rules.NewEvaluator(&snap)
			for _, p := range probes {
				ctx := rules.EvalContext{SrcZone: p.srcZone, DstZone: p.dstZone, SrcIP: net.ParseIP(p.src), DstIP: net.ParseIP(p.dst), Proto: p.proto, Port: p.port}
				if p.modbusFC >= 0 {
					ctx.ICS = &rules.ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: uint8(p.modbusFC), Direction: "request"}
				}
				action, entry := ev.EvaluateMatch(ctx)
				got := ""
				if entry != nil {
					got = entry.ID
				}
				if action != p.wantAction || got != p.wantRule {
					t.Errorf("%s: %s by %q, want %s by %q", p.name, action, got, p.wantAction, p.wantRule)
				}
				if fa, fr := firstMatch(&snap, ctx); fa != action || fr != got {
					t.Errorf("%s: first-match order gives %s by %q, precedence %s by %q", p.name, fa, fr, action, got)
				}
			}
		})
	}
}

// firstMatch is the evaluator's former order: the first matching rule as
// configured, else the default.
func firstMatch(snap *rules.Snapshot, ctx rules.EvalContext) (rules.Action, string) {
	for _, e := range snap.Firewall {
		if rules.PreviewMatch(e, ctx) {
			return e.Action, e.ID
		}
	}
	return snap.Default, ""
}
