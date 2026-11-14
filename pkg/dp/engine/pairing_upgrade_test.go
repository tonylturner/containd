// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestPairingUpgrade exercises persisted selector-free policy through the same
// compiler and installer used by replay. The live harness separately restarts
// management against its unchanged database; this test does not model boot I/O.
func TestPairingUpgrade(t *testing.T) {
	for _, p := range runtimePairCases() {
		for _, mode := range []string{"enforce", "monitor"} {
			for _, def := range []config.Action{config.ActionAllow, config.ActionDeny} {
				t.Run(p.protocol+"/"+mode+"/"+string(def), func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.DataPlane.DPIEnabled, cfg.DataPlane.DPIMode = true, mode
					cfg.DataPlane.NFQueueGroup = 101
					cfg.Firewall.DefaultAction = def
					cfg.Firewall.Rules = []config.Rule{{ID: "legacy", Action: config.ActionAllow,
						Protocols: []config.Protocol{{Name: "tcp", Port: strconv.Itoa(int(p.port))}},
						ICS:       config.ICSPredicate{Protocol: p.protocol, Mode: mode}}}
					stored, err := json.Marshal(cfg)
					if err != nil {
						t.Fatal(err)
					}
					var replay config.Config
					if err := json.Unmarshal(stored, &replay); err != nil {
						t.Fatal(err)
					}
					snap, err := compile.CompileSnapshot(&replay)
					if err != nil {
						t.Fatal(err)
					}
					e := runtimePairEngine(t, snap, true)
					if err := e.ApplyRules(context.Background(), snap); err != nil {
						t.Fatal(err)
					}
					preview, err := e.PreviewRuleset(snap, enforce.CompilerSettings{})
					if err != nil {
						t.Fatal(err)
					}
					warnings := e.RulesetStatus().Warnings
					if !reflect.DeepEqual(warnings, preview.Warnings) {
						t.Fatalf("installed/preview warnings differ: %+v / %+v", warnings, preview.Warnings)
					}
					if (len(warnings) > 0) != (mode == "enforce") {
						t.Fatalf("cutover warnings: %+v", warnings)
					}
					rulePreview := e.PreviewRule(PreviewRuleRequest{Entry: snap.Firewall[0]})
					if mode == "enforce" && len(rulePreview.Warnings) == 0 {
						t.Fatal("rule preview omitted cutover warning")
					}
					inlineHandshake(t, e, 41000, p.port)
					got := e.HandlePacket(runtimePairPacket(p, true, 500, p.reply))
					want := capture.Drop
					if mode == "monitor" {
						want = capture.Repeat
					}
					if got.Action != want {
						t.Fatalf("unmatched legacy reply: %+v", got)
					}
					if mode == "enforce" && got.Reason != string(pairUnpaired) {
						t.Fatalf("wrong rejection: %+v", got)
					}
					if e.sessions.pairingTotal != 0 {
						t.Fatal("replay minted authority without a request")
					}
					again, err := json.Marshal(&replay)
					if err != nil || !reflect.DeepEqual(stored, again) {
						t.Fatal("replay mutated stored configuration", err)
					}
				})
			}
		}
	}
	t.Run("explicit-classes-reconnect", func(t *testing.T) {
		p := runtimePairCases()[2]
		old := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}
		e := runtimePairEngine(t, old, true)
		inlineHandshake(t, e, 41000, p.port)
		if d := e.HandlePacket(runtimePairPacket(p, false, 100, startdtAct)); d.Action != capture.Drop || d.Reason != string(sessionRequired) {
			t.Fatalf("legacy session blanket: %+v", d)
		}
		session := runtimePairRule(p, "enforce")
		session.ID, session.ICS.MessageClass = "session", "session"
		old.Firewall = append([]rules.Entry{session}, old.Firewall...)
		if err := e.ApplyRules(context.Background(), old); err != nil {
			t.Fatal(err)
		}
		inlineHandshake(t, e, 41001, p.port)
		pkt := runtimePairPacket(p, false, 100, startdtAct)
		pkt.SrcPort = 41001
		if d := e.HandlePacket(pkt); d.Action != capture.Repeat {
			t.Fatalf("explicit rule on fresh connection: %+v", d)
		}
	})
}
