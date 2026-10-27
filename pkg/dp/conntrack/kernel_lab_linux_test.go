// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// routedLab is a client and a server namespace routed through the test's own
// namespace, which runs the containd firewall. The client namespace also
// holds otherClient; vip, on the router's client link, exists only with NAT.
type routedLab struct {
	clientNS, serverNS                                           string
	client, server, routerClient, routerServer, vip, otherClient string
}

// newRoutedLab builds the lab, with IPv6 or IPv4 addressing, and applies the
// containd firewall (default allow) plus the extra rules nat returns for the
// lab, if any. Stale entries of earlier labs are deleted first.
func newRoutedLab(t *testing.T, ctx context.Context, v6 bool, nat func(*routedLab) string) *routedLab {
	t.Helper()
	// Conntrack outlives namespaces. Remove only this harness's stale
	// tuples before reusing its deliberately tiny SNAT port pool.
	old, err := conntrack.List(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range old {
		if !strings.HasPrefix(e.Src, "10.91.") && !strings.HasPrefix(e.Src, "fd91:") {
			continue
		}
		original, err := e.Original()
		if err != nil {
			t.Fatal(err)
		}
		if err := conntrack.Delete(ctx, original); err != nil && !errors.Is(err, syscall.ENOENT) {
			t.Fatal(err)
		}
	}

	run := func(args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	suffix := strconv.Itoa(os.Getpid())
	lab := &routedLab{clientNS: "ctc" + suffix, serverNS: "cts" + suffix,
		client: "10.91.1.2", server: "10.91.2.2", routerClient: "10.91.1.1", routerServer: "10.91.2.1", vip: "10.91.1.100", otherClient: "10.91.1.3"}
	prefix, family := "/24", "-4"
	if v6 {
		lab.client, lab.server, lab.routerClient, lab.routerServer, lab.vip, lab.otherClient = "fd91:1::2", "fd91:2::2", "fd91:1::1", "fd91:2::1", "", "fd91:1::3"
		prefix, family = "/64", "-6"
	}
	for _, ns := range []string{lab.clientNS, lab.serverNS} {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}
	for _, link := range []struct{ name, ns, local, remote string }{{"ctclient", lab.clientNS, lab.routerClient, lab.client}, {"ctserver", lab.serverNS, lab.routerServer, lab.server}} {
		run("ip", "link", "add", link.name, "type", "veth", "peer", "name", link.name+"p")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", link.name).Run() })
		run("ip", "link", "set", link.name+"p", "netns", link.ns)
		if v6 {
			// Static link-local addresses keep DAD transitions out of
			// the transport test. Neighbor discovery still runs through
			// the real firewall; no permanent neighbor entries are used.
			run("ip", "link", "set", link.name, "addrgenmode", "none")
			run("ip", "-n", link.ns, "link", "set", link.name+"p", "addrgenmode", "none")
			run("ip", "-6", "addr", "add", "fe80::1/64", "dev", link.name, "nodad")
			run("ip", "-n", link.ns, "-6", "addr", "add", "fe80::2/64", "dev", link.name+"p", "nodad")
		}
		args := []string{"ip", family, "addr", "add", link.local + prefix, "dev", link.name}
		if v6 {
			args = append(args, "nodad")
		}
		run(args...)
		run("ip", "link", "set", link.name, "up")
		run("ip", "-n", link.ns, "link", "set", "lo", "up")
		args = []string{"ip", "-n", link.ns, family, "addr", "add", link.remote + prefix, "dev", link.name + "p"}
		if v6 {
			args = append(args, "nodad")
		}
		run(args...)
		run("ip", "-n", link.ns, "link", "set", link.name+"p", "up")
		run("ip", "-n", link.ns, family, "route", "add", "default", "via", link.local)
	}
	if lab.vip != "" {
		run("ip", "addr", "add", lab.vip+"/32", "dev", "ctclient")
	}
	alias := []string{"ip", "-n", lab.clientNS, family, "addr", "add", lab.otherClient + prefix, "dev", "ctclientp"}
	if v6 {
		alias = append(alias, "nodad")
	}
	run(alias...)
	for _, key := range []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"} {
		out, err := exec.CommandContext(ctx, "sysctl", "-n", key).Output()
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			t.Fatalf("set %s=1 using docker --sysctl before running: %s %v", key, out, err)
		}
	}
	text, err := enforce.NewCompiler().CompileFirewall(&rules.Snapshot{Default: rules.ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	if nat != nil {
		text += "add chain inet containd test_dnat { type nat hook prerouting priority dstnat; }\n"
		text += "add chain inet containd test_snat { type nat hook postrouting priority srcnat; }\n"
		text += nat(lab)
	}
	if err := enforce.NewNftApplier().Apply(ctx, text); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
			t.Logf("rules: %s", out)
			for _, cmd := range [][]string{{"ip", "-6", "addr"}, {"ip", "-6", "route"}, {"ip", "-6", "neigh"}, {"ip", "-n", lab.clientNS, "-6", "route"}, {"ip", "-n", lab.clientNS, "-6", "neigh"}, {"ip", "-n", lab.serverNS, "-6", "route"}, {"ip", "-n", lab.serverNS, "-6", "neigh"}} {
				out, _ := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
				t.Logf("%v: %s", cmd, out)
			}
		}
	})
	return lab
}
