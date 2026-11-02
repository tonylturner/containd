// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestAccountingScript(t *testing.T) {
	a := NewAccounting("fw", map[string]string{"eth0": "a", "eth1": "b", "eth2": "b"})
	script, err := a.Script()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet fw_acct", "hook forward priority 100; policy accept;", `"eth0" . "eth1" : "pair_1_2"`, `"eth0" . "eth2" : "pair_1_2"`, "counter name meta iifname . meta oifname map @device_pairs"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q: %s", want, script)
		}
	}
	if len(a.Pairs) != 2 {
		t.Fatalf("pairs: %+v", a.Pairs)
	}
	for _, forbidden := range []string{`"eth0" . "eth0"`, `"eth1" . "eth2"`, "counter pair_1_1", "counter pair_2_2"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("same-zone accounting: %s", forbidden)
		}
	}
	for _, verdict := range []string{" drop", " reject", " return", " jump", " goto", " queue"} {
		if strings.Contains(script, verdict) {
			t.Errorf("accounting contains verdict %s", verdict)
		}
	}
	if !a.Matches("fw", map[string]string{"eth2": "b", "eth0": "a", "eth1": "b"}) || a.Matches("other", map[string]string{"eth0": "a"}) {
		t.Fatal("membership equality")
	}
	b := NewAccounting("fw", map[string]string{"eth0": "a", "eth1": "b", "eth2": "b"})
	if a.Epoch == b.Epoch {
		t.Fatal("build reused epoch")
	}
	text, err := NewCompiler().CompileFirewall(&rules.Snapshot{Default: rules.ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "_acct") {
		t.Fatal("policy compile touches accounting")
	}
}

func TestAccountingNames(t *testing.T) {
	for _, table := range []string{"", strings.Repeat("a", maxTableName)} {
		if _, err := NewAccounting(table, nil).Script(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewAccounting("fw", map[string]string{"bad*": "a"}).Script(); err == nil {
		t.Fatal("invalid interface accepted")
	}
}
