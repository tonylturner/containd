// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dhcpd

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestRedirectScriptReplacesOnlyItsTable(t *testing.T) {
	script := redirectScript([]string{"lan0", "lan1"})
	want := "add table inet containd_dhcp\ndelete table inet containd_dhcp\ntable inet containd_dhcp {\n"
	if !strings.HasPrefix(script, want) {
		t.Fatalf("script does not replace the table whether or not it exists:\n%s", script)
	}
	for _, dev := range []string{"lan0", "lan1"} {
		if !strings.Contains(script, `iifname "`+dev+`" udp dport 67 redirect to :1067`) {
			t.Fatalf("missing redirect for %s:\n%s", dev, script)
		}
	}
	if strings.Count(script, "inet ") != strings.Count(script, "inet containd_dhcp") {
		t.Fatalf("script touches another table:\n%s", script)
	}
}

// TestKernelRedirectScriptAppliesWithTableAbsentAndPresent needs root and
// nft in a disposable network namespace, for example:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/dhcpd.test ./pkg/dp/dhcpd
//	docker run --rm --cap-add NET_ADMIN -e CONTAIND_KERNEL_TESTS=1 -v "$PWD/build:/w" alpine:3.21 \
//	  sh -c 'apk add -q nftables && /w/dhcpd.test -test.run Kernel -test.v'
func TestKernelRedirectScriptAppliesWithTableAbsentAndPresent(t *testing.T) {
	if os.Getenv("CONTAIND_KERNEL_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_KERNEL_TESTS=1 as root in a disposable network namespace with nft")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nft := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
		return string(out), err
	}
	if _, err := nft("list", "table", "inet", enforce.DHCPRedirectTable); err == nil {
		t.Fatal("the namespace already holds the redirect table")
	}
	for _, devs := range [][]string{{"lan0"}, {"lan1"}} {
		if err := ensureRedirect(ctx, devs, true); err != nil {
			t.Fatal(err)
		}
		table, err := nft("list", "table", "inet", enforce.DHCPRedirectTable)
		if err != nil || !strings.Contains(table, `iifname "`+devs[0]+`" udp dport 67 redirect to :1067`) || strings.Count(table, "redirect") != 1 {
			t.Fatalf("redirect table after applying %v (%v):\n%s", devs, err, table)
		}
	}
	// Disabling removes the table and succeeds again once it is absent.
	for i := 0; i < 2; i++ {
		if err := ensureRedirect(ctx, nil, false); err != nil {
			t.Fatal(err)
		}
		if _, err := nft("list", "table", "inet", enforce.DHCPRedirectTable); err == nil {
			t.Fatal("disabling kept the redirect table")
		}
	}
}
