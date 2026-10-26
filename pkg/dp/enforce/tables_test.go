// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// tableRef matches each table a script names.
var tableRef = regexp.MustCompile(`(?m)(?:^|\s)(?:table|chain|set|rule|element) inet (\w+)`)

func TestCompileFirewallTouchesOnlyOwnedTables(t *testing.T) {
	for _, tc := range []struct{ table, policy, blocks string }{
		{"", "containd_policy", "containd"},
		{"fw", "fw_policy", "fw"},
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
		// The dynamic table and its elements are kept: no delete or flush of
		// any set.
		for _, keep := range []string{"delete table inet " + tc.blocks + "\n", "flush set", "flush table"} {
			if strings.Contains(text, keep) {
				t.Fatalf("table %q: apply discards temporary blocks (%q):\n%s", tc.table, keep, text)
			}
		}
		policy := text[:strings.Index(text, "add table inet "+tc.blocks+"\n")]
		if strings.Contains(policy, "@block_") || strings.Contains(policy, "@revoke") {
			t.Fatalf("table %q: policy table references dynamic sets:\n%s", tc.table, policy)
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
	renamed.TableName = "containd_policy"
	if got := old.RetireTables(same); got != "" {
		t.Fatalf("same tables retired: %q", got)
	}
	want := DeleteTable("containd_policy") + DeleteTable("containd")
	if got := old.RetireTables(renamed); got != want {
		t.Fatalf("retire = %q, want %q", got, want)
	}
	if got := old.DeleteTables(); got != want {
		t.Fatalf("delete = %q, want %q", got, want)
	}
}

func TestClearBlocksFlushesEveryDynamicSet(t *testing.T) {
	c := NewCompiler()
	c.TableName = "fw"
	text := c.ClearBlocks()
	for _, want := range []string{"add table inet fw\n", "flush set inet fw block_hosts\n", "flush set inet fw block_flows\n",
		"flush set inet fw revoke4\n", "flush set inet fw revoke6\n", "flush set inet fw revoke_service4\n", "flush set inet fw revoke_service6\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "fw_policy") || strings.Contains(text, "delete") {
		t.Fatalf("clearing blocks touches the policy table or deletes:\n%s", text)
	}
}

func TestNftUpdaterTargetsDynamicTable(t *testing.T) {
	u := NewNftUpdater("fw")
	host := strings.Join(u.buildBlockHostArgs(net.ParseIP("10.1.2.3"), time.Second), " ")
	flow := strings.Join(u.buildBlockFlowArgs(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), "tcp", "502", 0), " ")
	if !strings.HasPrefix(host, "add element inet fw block_hosts ") || !strings.HasPrefix(flow, "add element inet fw block_flows ") {
		t.Fatalf("host=%q flow=%q", host, flow)
	}
	if got := NewNftUpdater("").TableName; got != "containd" {
		t.Fatalf("default dynamic table = %q", got)
	}
}

func TestTableNameRuleIsSharedByCompilerAndUpdater(t *testing.T) {
	entry := conntrack.Entry{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: "1234", Dport: "443",
		ReplySrc: "192.0.2.2", ReplyDst: "192.0.2.1", ReplySport: "443", ReplyDport: "1234"}
	for name, ok := range map[string]bool{
		"containd": true, "Fw-1": true, "fw_2": true, "_x": true, strings.Repeat("a", maxTableName): true,
		"1fw": false, "-fw": false, "fw.1": false, "fw 1": false, "fw;flush": false, strings.Repeat("a", maxTableName+1): false,
	} {
		if err := ValidateTableName(name); (err == nil) != ok {
			t.Fatalf("ValidateTableName(%q) = %v, want ok=%v", name, err, ok)
		}
		c := NewCompiler()
		c.TableName = name
		if _, err := c.CompileFirewall(&rules.Snapshot{}); (err == nil) != ok {
			t.Fatalf("compile with table %q: %v", name, err)
		}
		if _, err := NewNftUpdater(name).revocationBatch([]conntrack.Entry{entry}, "connection", time.Minute); (err == nil) != ok {
			t.Fatalf("revocation with table %q: %v", name, err)
		}
		if !ok {
			u := &NftUpdater{Path: "/nonexistent/nft", TableName: name}
			if err := u.BlockHostTemp(context.Background(), net.ParseIP("10.0.0.1"), time.Second); err == nil || !strings.Contains(err.Error(), "invalid nft table name") {
				t.Fatalf("block with table %q: %v", name, err)
			}
		}
	}
	if err := ValidateTableName(""); err == nil {
		t.Fatal("empty table name accepted")
	}
}

func TestValidateTableNameRejectsKeywordsAndForeignTables(t *testing.T) {
	for name, ok := range map[string]bool{
		"table": false, "inet": false, "ip": false, "accept": false, "auto-merge": false, "rt0": false,
		"tunnel": false, DHCPRedirectTable: false, "Table": true, "INET": true, "auto_merge": true,
		"rt1": true, "tunnels": true, "table_x": true, "containd_dhcp_policy": true, "containd_policy": true,
	} {
		if err := ValidateTableName(name); (err == nil) != ok {
			t.Errorf("ValidateTableName(%q) = %v, want ok=%v", name, err, ok)
		}
	}
	// A valid name's policy table is valid too: "_policy" ends no keyword
	// and not the DHCP redirect table.
	for w := range nftKeywords {
		if strings.HasSuffix(w, "_policy") || ValidateTableName(w) == nil {
			t.Errorf("keyword %q: accepted or a policy table name", w)
		}
	}
	if strings.HasSuffix(DHCPRedirectTable, "_policy") {
		t.Errorf("%s ends in _policy", DHCPRedirectTable)
	}
}
