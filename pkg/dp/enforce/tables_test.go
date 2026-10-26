// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// tableRef matches each table a script names.
var tableRef = regexp.MustCompile(`(?m)(?:^|\s)(?:table|chain|set|rule|element) inet (\w+)`)

func TestCompileFirewallTouchesOnlyOwnedTables(t *testing.T) {
	for _, tc := range []struct{ table, policy, blocks string }{
		{"", "containd", "containd_blocks"},
		{"fw", "fw", "fw_blocks"},
	} {
		c := NewCompiler()
		c.TableName = tc.table
		text, err := c.CompileFirewall(&rules.Snapshot{Default: rules.ActionDeny})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "ruleset") {
			t.Fatalf("table %q: script acts on the whole ruleset:\n%s", tc.table, text)
		}
		for _, m := range tableRef.FindAllStringSubmatch(text, -1) {
			if m[1] != tc.policy && m[1] != tc.blocks {
				t.Fatalf("table %q: script touches foreign table %s:\n%s", tc.table, m[1], text)
			}
		}
		// The policy table is replaced, whether or not it exists.
		if !strings.HasPrefix(text, DeleteTable(tc.policy)+"table inet "+tc.policy+" {\n") {
			t.Fatalf("table %q: policy table is not replaced atomically:\n%s", tc.table, text)
		}
		// The blocks table and its elements are kept: no delete or flush of
		// either set.
		for _, keep := range []string{"delete table inet " + tc.blocks, "flush set", "flush table"} {
			if strings.Contains(text, keep) {
				t.Fatalf("table %q: apply discards temporary blocks (%q):\n%s", tc.table, keep, text)
			}
		}
		policy := text[:strings.Index(text, "add table inet "+tc.blocks)]
		if strings.Contains(policy, "@block_") {
			t.Fatalf("table %q: policy table references block sets:\n%s", tc.table, policy)
		}
		for _, want := range []string{
			"add chain inet " + tc.blocks + " forward { type filter hook forward priority -10; policy accept; }\n",
			"flush chain inet " + tc.blocks + " forward\n",
			"add rule inet " + tc.blocks + " forward ip saddr @block_hosts drop\n",
			"add rule inet " + tc.blocks + " forward ip daddr @block_hosts drop\n",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("table %q: missing %q:\n%s", tc.table, want, text)
			}
		}
		assertDeclaredSets(t, text)
	}
}

func TestRetireTablesOnlyOnRename(t *testing.T) {
	old, same, renamed := NewCompiler(), NewCompiler(), NewCompiler()
	renamed.TableName = "containd_blocks"
	if got := old.RetireTables(same); got != "" {
		t.Fatalf("same tables retired: %q", got)
	}
	want := DeleteTable("containd") + DeleteTable("containd_blocks")
	if got := old.RetireTables(renamed); got != want {
		t.Fatalf("retire = %q, want %q", got, want)
	}
	if got := old.DeleteTables(); got != want {
		t.Fatalf("delete = %q, want %q", got, want)
	}
}

func TestClearBlocksFlushesBothSets(t *testing.T) {
	c := NewCompiler()
	c.TableName = "fw"
	text := c.ClearBlocks()
	for _, want := range []string{"add table inet fw_blocks\n", "flush set inet fw_blocks block_hosts\n", "flush set inet fw_blocks block_flows\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "inet fw ") || strings.Contains(text, "delete") {
		t.Fatalf("clearing blocks touches the policy table or deletes:\n%s", text)
	}
}

func TestNftUpdaterTargetsBlocksTable(t *testing.T) {
	u := NewNftUpdater("fw")
	host := strings.Join(u.buildBlockHostArgs(net.ParseIP("10.1.2.3"), time.Second), " ")
	flow := strings.Join(u.buildBlockFlowArgs(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), "tcp", "502", 0), " ")
	if !strings.HasPrefix(host, "add element inet fw_blocks block_hosts ") || !strings.HasPrefix(flow, "add element inet fw_blocks block_flows ") {
		t.Fatalf("host=%q flow=%q", host, flow)
	}
	if got := NewNftUpdater("").TableName; got != "containd_blocks" {
		t.Fatalf("default blocks table = %q", got)
	}
}
