// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"reflect"
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
