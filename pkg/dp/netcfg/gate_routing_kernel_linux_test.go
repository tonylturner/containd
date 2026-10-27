// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGateRoutingKernel installs the gate policy rule and local route next
// to management-pin-shaped objects, foreign objects in the gate table and
// stale gate variants. Reinstalling must not touch the kernel, the variants
// must be replaced, and removal must leave every other object alone. It
// runs in the disposable container routingKernelContext describes.
func TestGateRoutingKernel(t *testing.T) {
	ctx := routingKernelContext(t)
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	table := fmt.Sprint(GateRoutingTable)
	proto := fmt.Sprint(GateRouteProtocol)
	mark := fmt.Sprintf("0x%x/0x%x", GateLocalMark, GateLocalMark)
	ip("link", "set", "lo", "up")
	ip("link", "add", "gateprobe", "type", "dummy")
	defer ip("link", "del", "gateprobe")
	ip("link", "set", "gateprobe", "up")
	// The management guard adds its pin rule without a protocol and its
	// route with ManagementRouteProtocol; both shapes must survive.
	pinRules := [][]string{
		{"-4", "rule", "priority", "1", "from", "10.99.99.2", "to", "10.99.99.10", "lookup", fmt.Sprint(ManagementTable)},
		{"-4", "rule", "priority", "1", "from", "10.99.99.2", "to", "10.99.99.3", "lookup", fmt.Sprint(ManagementTable), "protocol", fmt.Sprint(ManagementRouteProtocol)},
	}
	for _, r := range pinRules {
		ip(append([]string{r[0], r[1], "add"}, r[2:]...)...)
		defer ip(append([]string{r[0], r[1], "del"}, r[2:]...)...)
	}
	ip("-4", "route", "add", "10.99.99.10/32", "dev", "gateprobe", "table", fmt.Sprint(ManagementTable), "protocol", fmt.Sprint(ManagementRouteProtocol))
	defer ip("-4", "route", "del", "10.99.99.10/32", "dev", "gateprobe", "table", fmt.Sprint(ManagementTable))
	// Foreign objects in the gate table carry another protocol.
	ip("-4", "rule", "add", "priority", "5", "fwmark", "0x2/0x2", "lookup", table, "protocol", "static")
	defer ip("-4", "rule", "del", "priority", "5", "fwmark", "0x2/0x2", "lookup", table, "protocol", "static")
	ip("-6", "route", "add", "2001:db8::/64", "dev", "gateprobe", "table", table, "protocol", "static")
	defer ip("-6", "route", "del", "2001:db8::/64", "dev", "gateprobe", "table", table)
	gateLines := func(family string) (rules, routes []string) {
		for _, line := range strings.Split(ip(family, "rule", "show"), "\n") {
			if strings.Contains(line, "lookup "+table) && strings.Contains(line, "proto "+proto) {
				rules = append(rules, line)
			}
		}
		for _, line := range strings.Split(ip(family, "route", "show", "table", table), "\n") {
			if strings.Contains(line, "proto "+proto) {
				routes = append(routes, line)
			}
		}
		return rules, routes
	}
	// Stale gate variants: wrong priority and mark, an extra selector, a
	// prefixed local route and the right route via the wrong device.
	ip("-4", "rule", "add", "priority", "7", "fwmark", "0x1/0x1", "lookup", table, "protocol", proto)
	ip("-6", "rule", "add", "priority", "1", "to", "2001:db8::/64", "fwmark", mark, "lookup", table, "protocol", proto)
	ip("-4", "route", "add", "local", "192.0.2.0/24", "dev", "lo", "table", table, "protocol", proto)
	ip("-4", "route", "add", "local", "default", "dev", "gateprobe", "table", table, "protocol", proto)
	ip("-6", "route", "add", "local", "2001:db8:1::/64", "dev", "lo", "table", table, "protocol", proto)
	// Restore the container baseline for the other kernel tests even when
	// an assertion fails with gate objects or variants installed.
	defer func() {
		if err := RemoveGateRouting(ctx); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		for _, family := range []string{"-4", "-6"} {
			if rules, routes := gateLines(family); len(rules)+len(routes) != 0 {
				t.Errorf("%s gate objects left behind: %q %q", family, rules, routes)
			}
		}
	}()
	pinBaseline := ip("-4", "rule", "show") + ip("-4", "route", "show", "table", fmt.Sprint(ManagementTable))
	pinState := func() string {
		var lines []string
		for _, line := range strings.Split(ip("-4", "rule", "show"), "\n") {
			if strings.Contains(line, "lookup "+fmt.Sprint(ManagementTable)) {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n") + "\n" + ip("-4", "route", "show", "table", fmt.Sprint(ManagementTable))
	}
	wantPin := pinState()
	if strings.Count(wantPin, "lookup "+fmt.Sprint(ManagementTable)) != 2 || !strings.Contains(pinBaseline, "10.99.99.10 dev gateprobe") {
		t.Fatalf("pin fixtures missing:\n%s", pinBaseline)
	}
	state := func() string {
		return ip("-4", "rule", "show") + ip("-6", "rule", "show") + ip("-4", "route", "show", "table", table) + ip("-6", "route", "show", "table", table)
	}
	if err := EnsureGateRouting(ctx); err != nil {
		t.Fatal(err)
	}
	installed := state()
	t.Logf("installed:\n%s", installed)
	for _, family := range []string{"-4", "-6"} {
		rules, routes := gateLines(family)
		if len(rules) != 1 || !strings.HasPrefix(rules[0], "1:") || !strings.Contains(rules[0], "from all fwmark "+mark+" lookup "+table) {
			t.Fatalf("%s gate rules after install: %q", family, rules)
		}
		if len(routes) != 1 || !strings.HasPrefix(routes[0], "local default dev lo ") {
			t.Fatalf("%s gate routes after install: %q", family, routes)
		}
	}
	if !strings.Contains(installed, "fwmark 0x2/0x2 lookup "+table) || !strings.Contains(installed, "2001:db8::/64 dev gateprobe") {
		t.Fatalf("foreign objects in the gate table were touched:\n%s", installed)
	}
	if got := pinState(); got != wantPin {
		t.Fatalf("management pin changed:\n%s\nwant:\n%s", got, wantPin)
	}
	// Observe mutations, not only equal dumps: a second install must send
	// nothing the kernel multicasts to route and rule listeners.
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	for _, group := range []int{unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE} {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, group); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsureGateRouting(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _, err := unix.Recvfrom(fd, make([]byte, 65536), 0); err != unix.EAGAIN {
		t.Fatalf("second install produced a netlink mutation (%d bytes, %v)", n, err)
	}
	if got := state(); got != installed {
		t.Fatalf("second install changed kernel state:\n%s\nwant:\n%s", got, installed)
	}
	if err := RemoveGateRouting(ctx); err != nil {
		t.Fatal(err)
	}
	removed := state()
	for _, family := range []string{"-4", "-6"} {
		if rules, routes := gateLines(family); len(rules) != 0 || len(routes) != 0 {
			t.Fatalf("%s gate objects after removal: %q %q", family, rules, routes)
		}
	}
	if !strings.Contains(removed, "fwmark 0x2/0x2 lookup "+table) || !strings.Contains(removed, "2001:db8::/64 dev gateprobe") {
		t.Fatalf("removal touched foreign objects in the gate table:\n%s", removed)
	}
	if got := pinState(); got != wantPin {
		t.Fatalf("removal changed the management pin:\n%s\nwant:\n%s", got, wantPin)
	}
	// Drain the first removal's notifications before watching the second.
	for {
		if _, _, err := unix.Recvfrom(fd, make([]byte, 65536), 0); err == unix.EAGAIN {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveGateRouting(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _, err := unix.Recvfrom(fd, make([]byte, 65536), 0); err != unix.EAGAIN {
		t.Fatalf("second removal produced a netlink mutation (%d bytes, %v)", n, err)
	}
	if got := state(); got != removed {
		t.Fatalf("second removal changed kernel state:\n%s\nwant:\n%s", got, removed)
	}
}
