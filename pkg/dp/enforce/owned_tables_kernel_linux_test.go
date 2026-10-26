// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// foreignNAT stands in for a table another owner keeps in the namespace,
// shaped like the embedded-DNS rules Docker installs through iptables-nft.
const foreignNAT = `table ip foreign_nat {
  chain DOCKER_OUTPUT {
    ip daddr 127.0.0.11 udp dport 53 dnat to 127.0.0.11:53053
  }
  chain OUTPUT {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.11 jump DOCKER_OUTPUT
  }
}
`

// tableExists reports whether the namespace holds table family name.
func (l *netnsLab) tableExists(family, name string) bool {
	return exec.CommandContext(l.ctx, "nft", "list", "table", family, name).Run() == nil
}

// TestKernelOwnedTablesKeepForeignStateAndBlocks applies a policy twice, with
// its tables absent and then present, around a foreign table and a
// temporary host block and a connection revocation. Neither apply touches
// the foreign table, the block keeps dropping forwarded traffic and the
// revocation stays installed across the second apply, and deleting
// containd's tables leaves the foreign one.
func TestKernelOwnedTablesKeepForeignStateAndBlocks(t *testing.T) {
	lab := newNetnsLab(t, "own", 50, 60*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.60.0/24", "via", "198.18.50.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.50.0/24", "via", "198.18.60.1")
	lab.serveTarget(t, "198.18.60.2", 18050)
	lab.nft(t, foreignNAT)
	t.Cleanup(func() { lab.nft(t, "delete table ip foreign_nat\n") })
	foreign := lab.run(t, "nft", "list", "table", "ip", "foreign_nat")

	c := NewCompiler()
	lab.nft(t, c.DeleteTables())
	if lab.tableExists("inet", "containd") || lab.tableExists("inet", "containd_blocks") {
		t.Fatal("containd tables survived their deletion")
	}
	snap := &rules.Snapshot{Default: rules.ActionAllow}
	lab.apply(t, c, snap) // tables absent
	if err := lab.probe("198.18.60.2", 18050, "198.18.50.2"); err != nil {
		t.Fatalf("policy admits nothing: %v", err)
	}
	if err := NewNftUpdater("").BlockHostTemp(lab.ctx, net.ParseIP("198.18.60.2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := lab.probe("198.18.60.2", 18050, "198.18.50.2"); err == nil {
		t.Fatal("blocked host reachable")
	}
	revoked := conntrack.Entry{Proto: "tcp", Src: "198.18.50.2", Dst: "198.18.60.3", Sport: "41000", Dport: "18051",
		ReplySrc: "198.18.60.3", ReplyDst: "198.18.50.2", ReplySport: "18051", ReplyDport: "41000"}
	if err := NewNftUpdater("").RevokeConnections(lab.ctx, []conntrack.Entry{revoked}, "client-service", time.Hour); err != nil {
		t.Fatal(err)
	}
	lab.apply(t, c, snap) // tables present
	if got := lab.run(t, "nft", "list", "table", "ip", "foreign_nat"); got != foreign {
		t.Fatalf("foreign table changed:\n%s\nwant:\n%s", got, foreign)
	}
	if set := lab.run(t, "nft", "list", "set", "inet", "containd_blocks", "block_hosts"); !strings.Contains(set, "198.18.60.2") {
		t.Fatalf("block lost by the second apply:\n%s", set)
	}
	if err := lab.probe("198.18.60.2", 18050, "198.18.50.2"); err == nil {
		t.Fatal("block stopped dropping after the second apply")
	}
	for _, set := range []string{"revoke4", "revoke_service4"} {
		if listing := lab.run(t, "nft", "list", "set", "inet", "containd_blocks", set); !strings.Contains(listing, "198.18.60.3") {
			t.Fatalf("revocation lost by the second apply:\n%s", listing)
		}
	}

	lab.nft(t, c.ClearBlocks())
	if err := lab.probe("198.18.60.2", 18050, "198.18.50.2"); err != nil {
		t.Fatalf("cleared block still drops: %v", err)
	}

	if err := NewNftUpdater("").BlockHostTemp(lab.ctx, net.ParseIP("198.18.60.2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	lab.nft(t, c.DeleteTables())
	if lab.tableExists("inet", "containd") || lab.tableExists("inet", "containd_blocks") {
		t.Fatalf("containd tables survived their deletion:\n%s", lab.run(t, "nft", "list", "tables"))
	}
	if got := lab.run(t, "nft", "list", "table", "ip", "foreign_nat"); got != foreign {
		t.Fatalf("deleting containd's tables changed the foreign table:\n%s", got)
	}
	if err := lab.probe("198.18.60.2", 18050, "198.18.50.2"); err != nil {
		t.Fatalf("traffic still blocked without containd's tables: %v", err)
	}
}

// TestKernelRenamedTablesRetireInOneTransaction renames the policy table to
// the old blocks table's name and back. The retirement precedes the new
// ruleset in one transaction, so neither direction collides.
func TestKernelRenamedTablesRetireInOneTransaction(t *testing.T) {
	lab := newNetnsLab(t, "ren", 70, 30*time.Second)
	snap := &rules.Snapshot{Default: rules.ActionAllow}
	short, long := NewCompiler(), NewCompiler()
	long.TableName = "containd_blocks"
	t.Cleanup(func() { lab.nft(t, short.DeleteTables()+long.DeleteTables()) })
	lab.apply(t, short, snap)
	for _, step := range []struct{ from, to *Compiler }{{short, long}, {long, short}} {
		text, err := step.to.CompileFirewall(snap)
		if err != nil {
			t.Fatal(err)
		}
		lab.nft(t, step.from.RetireTables(step.to)+text)
		listing := lab.run(t, "nft", "list", "tables")
		want := []string{"table inet " + step.to.TableName + "\n", "table inet " + BlocksTable(step.to.TableName) + "\n"}
		if strings.Count(listing, "table inet ") != 2 || !strings.Contains(listing, want[0]) || !strings.Contains(listing, want[1]) {
			t.Fatalf("after renaming %s to %s:\n%s", step.from.TableName, step.to.TableName, listing)
		}
		if chain := lab.run(t, "nft", "list", "chain", "inet", step.to.TableName, "input"); !strings.Contains(chain, "policy drop") {
			t.Fatalf("policy table %s lacks its input chain:\n%s", step.to.TableName, chain)
		}
	}
}
