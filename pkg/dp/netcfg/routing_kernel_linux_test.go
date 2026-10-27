// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

// routingKernelContext gates the routing kernel tests, which change routes
// and policy rules and create network namespaces: they run only when
// CONTAIND_NETNS_KERNEL_TEST=1 as root in a disposable Linux container with
// NET_ADMIN, SYS_ADMIN and iproute2, such as:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/netcfg.test ./pkg/dp/netcfg
//	docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 -v "$PWD/build:/w" alpine:3.21 \
//	  sh -c "apk add -q iproute2 && /w/netcfg.test -test.run RoutingKernel -test.v"
func routingKernelContext(t *testing.T) context.Context {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 as root in a disposable Linux container with NET_ADMIN and iproute2")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRoutingKernelConvergence(t *testing.T) {
	ctx := routingKernelContext(t)
	cmd := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	cmd("link", "add", "routeprobe", "type", "dummy")
	defer cmd("link", "del", "routeprobe")
	cmd("link", "set", "routeprobe", "up")
	cmd("addr", "add", "198.18.0.1/24", "dev", "routeprobe")
	cmd("route", "add", "198.18.1.0/24", "dev", "routeprobe", "proto", "static")
	cmd("rule", "add", "priority", "15000", "from", "198.18.1.0/24", "lookup", "202", "protocol", "static")
	defer cmd("rule", "del", "priority", "15000", "from", "198.18.1.0/24", "lookup", "202", "protocol", "static")
	baselineRoutes := cmd("-4", "route", "show", "table", "all")
	baselineRules := cmd("-4", "rule", "show")
	intent := config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "198.18.2.0/24", Iface: "routeprobe", Table: 201}, {Dst: "198.18.4.0/24", Gateway: "198.18.0.2", Table: 201}}}
	for _, p := range []int{1, 100, 15000, 40000, 65535} {
		intent.Rules = append(intent.Rules, config.PolicyRule{Priority: p, Src: "198.18.2.0/24", Table: 201})
	}
	apply := func(c config.RoutingConfig) {
		t.Helper()
		if err := ApplyRouting(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	intent.Rules = append(intent.Rules, config.PolicyRule{Priority: 30000, Src: "0.0.0.0/0", Dst: "0.0.0.0/0", Table: 201})
	apply(intent)
	installedRoutes := cmd("-4", "route", "show", "table", "all")
	installedRules := cmd("-4", "rule", "show")
	// Observe mutations, not just equivalent final dumps: unchanged intent must
	// not churn routes/rules and trigger another ownership reconciliation.
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
			t.Fatalf("idempotent apply produced a netlink mutation: %v", err)
		}
		if cmd("-4", "route", "show", "table", "all") != installedRoutes || cmd("-4", "rule", "show") != installedRules {
			t.Fatal("reapply changed kernel state")
		}
	}
	// Delete a subset through the ordinary commit path, retaining another entry.
	reduced := intent
	reduced.Rules = append([]config.PolicyRule(nil), intent.Rules[3:]...)
	apply(reduced)
	for _, p := range []int{1, 100, 15000} {
		for _, line := range strings.Split(cmd("-4", "rule", "show"), "\n") {
			if strings.HasPrefix(line, fmt.Sprint(p)+":") && strings.Contains(line, "198.18.2.0/24") {
				t.Fatalf("removed rule survived: %s", line)
			}
		}
	}
	// A kernel failure can occur after deleting stale intent. Replaying running
	// config is the existing commit recovery mechanism.
	broken := config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "198.18.3.0/24", Gateway: "203.0.113.1", Iface: "routeprobe"}}}
	if err := ApplyRouting(ctx, broken); err == nil {
		t.Fatal("unreachable gateway unexpectedly applied")
	}
	apply(intent)
	if cmd("-4", "route", "show", "table", "all") != installedRoutes || cmd("-4", "rule", "show") != installedRules {
		t.Fatal("replay failed to restore running intent")
	}
	// Ordinary empty commit removes every owned route and rule as well.
	apply(config.RoutingConfig{})
	if cmd("-4", "route", "show", "table", "all") != baselineRoutes || cmd("-4", "rule", "show") != baselineRules {
		t.Fatal("empty commit did not restore foreign-only state")
	}
	apply(intent)
	// A fresh process has no in-memory ownership history, as at engine restart.
	restart := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestRoutingRestartHelper$", "-test.v")
	restart.Env = append(os.Environ(), "CONTAIND_ROUTING_RESTART_HELPER=1")
	if out, err := restart.CombinedOutput(); err != nil {
		t.Fatalf("restart: %v: %s", err, out)
	}
	if got := cmd("-4", "route", "show", "table", "all"); got != baselineRoutes {
		t.Fatalf("route cleanup affected foreign entries:\n%s\nwant:\n%s", got, baselineRoutes)
	}
	if got := cmd("-4", "rule", "show"); got != baselineRules {
		t.Fatalf("rule cleanup affected foreign entries:\n%s\nwant:\n%s", got, baselineRules)
	}
	apply(config.RoutingConfig{})
	// An identical foreign route satisfies intent without being adopted.
	if err := ApplyRouting(ctx, config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "198.18.1.0/24", Iface: "routeprobe"}}}); err != nil {
		t.Fatalf("identical foreign route rejected: %v", err)
	}
	apply(config.RoutingConfig{})
	if cmd("-4", "route", "show", "table", "all") != baselineRoutes {
		t.Fatal("identical foreign route changed or adopted")
	}
}

func TestRoutingRestartHelper(t *testing.T) {
	if os.Getenv("CONTAIND_ROUTING_RESTART_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	ctx := routingKernelContext(t)
	if err := ApplyRoutingReplace(ctx, config.RoutingConfig{}); err != nil {
		t.Fatal(err)
	}
}
