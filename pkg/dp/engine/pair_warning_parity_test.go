// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDS34CutoverWarningPreviewParity(t *testing.T) {
	e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	snap := rules.Snapshot{Default: rules.ActionDeny, DPIEnabled: true, DPIMode: "enforce",
		Firewall: []rules.Entry{{ID: "read", Action: rules.ActionAllow,
			Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}}}}
	preview, err := e.PreviewRuleset(snap, enforce.CompilerSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	applied := e.RulesetStatus().Warnings
	if len(applied) != 1 {
		t.Fatalf("missing installed cutover warning: %+v", applied)
	}
	if !reflect.DeepEqual(preview.Warnings, applied) {
		t.Fatalf("preview warnings %+v differ from installed cutover warnings %+v", preview.Warnings, applied)
	}
}

func TestDenyListPolicyNonAdmitsEveryRequest(t *testing.T) {
	p := runtimePairCases()[0]
	deny := runtimePairRule(p, "enforce")
	deny.ID, deny.Action, deny.ICS.FunctionCode = "deny-writes", rules.ActionDeny, []uint8{5, 6, 15, 16}
	snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{deny}}
	e := runtimePairEngine(t, snap, true)
	inlineHandshake(t, e, 41000, p.port)
	d := sendInline(e, runtimePairPacket(p, false, 100, p.request)) // FC3 read
	warnings := pairingCutoverWarnings(&snap)
	t.Logf("FC3 read under DENY-writes + default ALLOW: %+v nonAdmit=%t; cutover warnings=%d", d, d.Mark&markabi.NonAdmitMark != 0, len(warnings))
	if d.Mark&markabi.NonAdmitMark != 0 && len(warnings) == 0 {
		t.Errorf("every request is non-admitted (kernel deny_clean) and reset, with no cutover warning for the policy")
	}
}

func TestMissingRequestAllowCutoverWarnings(t *testing.T) {
	p := runtimePairCases()[0]
	for _, kind := range []string{"absent", "plain", "monitor", "response", "session", "other-zone", "identity", "explicit"} {
		t.Run(kind, func(t *testing.T) {
			deny := runtimePairRule(p, "enforce")
			deny.Action, deny.ID = rules.ActionDeny, "deny"
			deny.SourceZones = []string{"lan"}
			snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{deny}}
			if kind != "absent" {
				allow := deny
				allow.Action, allow.ID = rules.ActionAllow, "allow"
				switch kind {
				case "plain":
					allow.ICS = rules.ICSPredicate{}
				case "monitor":
					allow.ICS.Mode = "monitor"
				case "response":
					allow.ICS.Direction = "response"
				case "session":
					allow.ICS.MessageClass = "session"
				case "other-zone":
					allow.SourceZones = []string{"dmz"}
				case "identity":
					allow.Identities = []string{"operator"}
				}
				snap.Firewall = append(snap.Firewall, allow)
			}
			found := false
			for _, warning := range pairingCutoverWarnings(&snap) {
				if warning.RuleID == deny.ID && strings.Contains(warning.Message, "no explicit ICS request ALLOW") {
					found = true
				}
			}
			if found != (kind != "explicit") {
				t.Fatalf("missing-request warning=%v for %s", found, kind)
			}
		})
	}
}
