// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestRoutingKernelForeignIntent(t *testing.T) {
	ctx := routingKernelContext(t)
	for _, scenario := range []string{"identical", "different"} {
		t.Run(scenario, func(t *testing.T) {
			ns := fmt.Sprintf("route-intent-%s", scenario)
			out, err := exec.CommandContext(ctx, "ip", "netns", "add", ns).CombinedOutput()
			if err != nil {
				t.Fatalf("netns add: %v %s", err, out)
			}
			defer func() {
				if out, err := exec.CommandContext(ctx, "ip", "netns", "del", ns).CombinedOutput(); err != nil {
					t.Errorf("netns del: %v %s", err, out)
				}
			}()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run=^TestRoutingForeignIntentHelper$", "-test.v")
			child.Env = append(os.Environ(), "CONTAIND_FOREIGN_ROUTE_HELPER="+scenario)
			if out, err := child.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", scenario, err, out)
			}
		})
	}
}

func TestRoutingForeignIntentHelper(t *testing.T) {
	scenario := os.Getenv("CONTAIND_FOREIGN_ROUTE_HELPER")
	if scenario == "" {
		t.Skip("isolated namespace subprocess helper")
	}
	ctx := routingKernelContext(t)
	t.Setenv("CONTAIND_ROUTING_STATE_PATH", filepath.Join(t.TempDir(), "displaced.json"))
	command := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
		return string(out)
	}
	command("link", "add", "quickstart0", "type", "dummy")
	command("link", "set", "quickstart0", "up")
	command("addr", "add", "198.19.0.1/24", "dev", "quickstart0")
	command("route", "add", "default", "via", "198.19.0.2", "dev", "quickstart0", "proto", "boot", "src", "198.19.0.1", "mtu", "1400")
	command("rule", "add", "priority", "15000", "from", "198.19.2.0/24", "lookup", "201", "protocol", "static")
	baselineRoutes := command("-4", "route", "show", "table", "all")
	baselineRules := command("-4", "rule", "show")
	gateway := "198.19.0.2"
	if scenario == "different" {
		gateway = "198.19.0.3"
	}
	intent := config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "default", Gateway: gateway, Iface: "quickstart0", Table: 0}}, Rules: []config.PolicyRule{{Priority: 15000, Src: "198.19.2.0/24", Table: 201}}}
	apply := func(c config.RoutingConfig) {
		t.Helper()
		if err := ApplyRouting(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if scenario == "different" {
		journal := os.Getenv("CONTAIND_ROUTING_STATE_PATH")
		t.Setenv("CONTAIND_ROUTING_STATE_PATH", "/proc/self/containd-routing-state.json")
		if err := ApplyRouting(ctx, intent); err == nil {
			t.Fatal("displaced a foreign route without a writable journal")
		}
		if command("-4", "route", "show", "table", "all") != baselineRoutes {
			t.Fatal("journal failure changed the foreign route")
		}
		t.Setenv("CONTAIND_ROUTING_STATE_PATH", journal)
		broken := intent
		broken.Routes = []config.StaticRoute{{Dst: "default", Gateway: "203.0.113.1", Iface: "quickstart0"}}
		if err := ApplyRouting(ctx, broken); err == nil {
			t.Fatal("accepted an unreachable next hop")
		}
		if command("-4", "route", "show", "table", "all") != baselineRoutes {
			t.Fatal("failed replacement changed the foreign route")
		}
		apply(config.RoutingConfig{})
	}
	apply(intent)
	assertOwnership := func() {
		t.Helper()
		routes, err := kernelRoutes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		owned := 0
		for _, r := range routes {
			if r.proto == routeProtoContaind {
				owned++
			}
		}
		want := 0
		if scenario == "different" {
			want = 1
		}
		if owned != want {
			t.Fatalf("owned routes=%d want %d", owned, want)
		}
		rules, err := kernelRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.proto == routeProtoContaind {
				t.Fatalf("identical foreign rule adopted: %+v", r)
			}
		}
	}
	assertOwnership()
	if scenario == "different" {
		if !strings.Contains(command("route", "show", "default"), "via 198.19.0.3") {
			t.Fatal("foreign default not displaced")
		}
		// A second next-hop change must retain the original foreign default.
		intent.Routes[0].Gateway = "198.19.0.4"
		apply(intent)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV4_RULE}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		apply(intent)
		if _, _, err := unix.Recvfrom(fd, make([]byte, 65536), 0); err != unix.EAGAIN {
			t.Fatalf("reapply mutated foreign/owned state: %v", err)
		}
	}
	assertOwnership()
	// Ordinary removal and a subsequent displacement must also retain the
	// foreign baseline; the restarted-process removal is exercised below.
	apply(config.RoutingConfig{})
	if command("-4", "route", "show", "table", "all") != baselineRoutes || command("-4", "rule", "show") != baselineRules {
		t.Fatal("ordinary removal changed the foreign baseline")
	}
	apply(intent)
	if command("-4", "rule", "show") != baselineRules {
		t.Fatal("foreign rule duplicated or changed")
	}
	// Removal by a restarted process must restore the complete foreign payload,
	// not merely its next hop; preferred source and MTU are checked in the dump.
	restart := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestRoutingRestartHelper$", "-test.v")
	restart.Env = append(os.Environ(), "CONTAIND_ROUTING_RESTART_HELPER=1")
	if out, err := restart.CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	if got := command("-4", "route", "show", "table", "all"); got != baselineRoutes {
		t.Fatalf("foreign default not preserved/restored:\n%s\nwant:\n%s", got, baselineRoutes)
	}
	if got := command("-4", "rule", "show"); got != baselineRules {
		t.Fatalf("foreign rule not preserved:\n%s", got)
	}
	apply(config.RoutingConfig{})
	if scenario == "different" {
		apply(intent)
		command("route", "replace", "default", "via", "198.19.0.5", "dev", "quickstart0", "proto", "static")
		external := command("-4", "route", "show", "table", "all")
		if err := ApplyRouting(ctx, config.RoutingConfig{}); err == nil || !strings.Contains(err.Error(), "restore displaced") {
			t.Fatalf("expected restore conflict: %v", err)
		}
		if command("-4", "route", "show", "table", "all") != external {
			t.Fatal("overwrote an externally changed foreign route")
		}
		state, err := loadDisplacedRoutes()
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Routes) != 1 {
			t.Fatal("restore conflict lost the displaced route record")
		}
		command("route", "del", "default", "via", "198.19.0.5", "dev", "quickstart0")
		apply(config.RoutingConfig{})
		if command("-4", "route", "show", "table", "all") != baselineRoutes {
			t.Fatal("could not retry restoration after conflict resolution")
		}
	}
	command("route", "add", "blackhole", "203.0.113.0/24", "table", "201", "proto", "static")
	before := command("-4", "route", "show", "table", "all")
	err = ApplyRouting(ctx, config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "203.0.113.0/24", Iface: "quickstart0", Table: 201}}})
	if err == nil || !strings.Contains(err.Error(), "203.0.113.0/24 table 201") {
		t.Fatalf("missing contextual collision error: %v", err)
	}
	if command("-4", "route", "show", "table", "all") != before {
		t.Fatal("unsupported foreign route was changed")
	}
}
