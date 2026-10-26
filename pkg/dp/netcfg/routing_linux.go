// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"syscall"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

const (
	// routeProtoContaind marks routes installed by containd so we can safely reconcile them.
	// This is a local netns concern (container/appliance); it avoids deleting host/system routes.
	routeProtoContaind = 98

	// Automatic priorities are defaults, not ownership evidence.
	managedRulePriorityBase = 10000
)

func applyRouting(ctx context.Context, routing config.RoutingConfig) error {
	// Resolve the whole intent before changing the kernel. Recovery of a partial
	// kernel failure remains the caller's running-config rollback responsibility.
	gwByName := map[string]config.Gateway{}
	for _, gw := range routing.Gateways {
		gwByName[strings.TrimSpace(gw.Name)] = gw
	}
	var routes []kernelRoute
	for _, r := range routing.Routes {
		kr, err := resolveRoute(r, gwByName)
		if err != nil {
			return err
		}
		routes = append(routes, kr)
	}
	var rules []kernelRule
	for i, r := range routing.Rules {
		kr, err := resolveRule(r, i)
		if err != nil {
			return err
		}
		rules = append(rules, kr)
	}
	oldRoutes, err := managedRoutes(ctx)
	if err != nil {
		return err
	}
	oldRules, err := managedRules(ctx)
	if err != nil {
		return err
	}
	for _, r := range oldRoutes {
		if !slices.ContainsFunc(routes, func(w kernelRoute) bool { return routeMatchesIntent(r, w) }) {
			if err := deleteKernelRoutes(ctx, []kernelRoute{r}); err != nil {
				return err
			}
		}
	}
	for _, r := range oldRules {
		if !slices.ContainsFunc(rules, func(w kernelRule) bool { return ownedRulesEqual(r, w) }) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := delRule(r); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
				return err
			}
		}
	}
	for _, r := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if slices.ContainsFunc(oldRoutes, func(w kernelRoute) bool { return routeMatchesIntent(w, r) }) {
			continue
		}
		if err := addRoute(r); err != nil {
			return err
		}
	}
	for _, r := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if slices.ContainsFunc(oldRules, func(w kernelRule) bool { return ownedRulesEqual(r, w) }) {
			continue
		}
		if err := addRule(r); err != nil {
			return err
		}
	}
	return nil
}

func routeMatchesIntent(got, want kernelRoute) bool {
	// A gateway-only route lets the kernel select its output interface. Its
	// resolved OIF must not cause deletion/re-addition on every reconcile.
	return got.dst.Equal(want.dst) && got.dstLen == want.dstLen && got.gateway.Equal(want.gateway) && (want.ifIndex == 0 || got.ifIndex == want.ifIndex) && got.table == want.table && got.metric == want.metric && got.proto == want.proto
}

func ownedRulesEqual(a, b kernelRule) bool {
	return a.priority == b.priority && a.table == b.table && a.src.Equal(b.src) && a.srcLen == b.srcLen && a.dst.Equal(b.dst) && a.dstLen == b.dstLen && a.proto == b.proto
}

func readNetlinkAck(fd int, seq uint32) error {
	return readAck(fd, seq, true)
}

// Routing must report collisions instead of replacing or adopting foreign entries.
func readRoutingAck(fd int, seq uint32) error {
	return readAck(fd, seq, false)
}

func readAck(fd int, seq uint32, allowExists bool) error {
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		if m.Header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(m.Data) < 4 {
			return errors.New("netlink error")
		}
		code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
		if code == 0 {
			return nil
		}
		if allowExists && -code == int32(unix.EEXIST) {
			return nil
		}
		return unix.Errno(-code)
	}
	return nil
}
