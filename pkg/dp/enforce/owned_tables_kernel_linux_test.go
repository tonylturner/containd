// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

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
// temporary host block. Neither apply touches the foreign table, the block
// keeps dropping forwarded traffic across the second apply, and deleting
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
