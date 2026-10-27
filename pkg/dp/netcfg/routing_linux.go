// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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

var routingApplyMu sync.Mutex

func applyRouting(ctx context.Context, routing config.RoutingConfig) error {
	routingApplyMu.Lock()
	defer routingApplyMu.Unlock()
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
	state, err := loadDisplacedRoutes()
	if err != nil {
		return err
	}
	oldRoutes, err := kernelRoutes(ctx)
	if err != nil {
		return err
	}
	oldRules, err := kernelRules(ctx)
	if err != nil {
		return err
	}
	for _, r := range oldRoutes {
		if r.proto == routeProtoContaind && !slices.ContainsFunc(routes, func(w kernelRoute) bool { return routeMatchesIntent(r, w) }) {
			if err := deleteKernelRoutes(ctx, []kernelRoute{r}); err != nil {
				return err
			}
		}
	}
	for _, r := range oldRules {
		if r.proto == routeProtoContaind && !slices.ContainsFunc(rules, func(w kernelRule) bool { return ownedRulesEqual(r, w) }) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := delRule(r); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
				return err
			}
		}
	}
	if err := state.restoreRemoved(ctx, routes); err != nil {
		return err
	}
	for _, r := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Refresh after stale deletions/restorations and earlier intent entries.
		current, err := kernelRoutes(ctx)
		if err != nil {
			return err
		}
		var collisions []kernelRoute
		satisfied := false
		for _, got := range current {
			if !sameRouteKey(got, r) {
				continue
			}
			if routeMatchesIntent(got, r) && restorableRoute(got) {
				satisfied = true
				break
			}
			collisions = append(collisions, got)
		}
		if satisfied {
			continue
		}
		if len(collisions) > 1 || (len(collisions) == 1 && !restorableRoute(collisions[0])) {
			return fmt.Errorf("apply %s: unsupported or ambiguous foreign route collision", routeDescription(r))
		}
		replace := len(collisions) == 1
		if replace && collisions[0].proto != routeProtoContaind {
			if err := state.remember(collisions[0]); err != nil {
				return fmt.Errorf("journal displaced %s: %w", routeDescription(r), err)
			}
		}
		if err := putRoute(r, replace); err != nil {
			return fmt.Errorf("apply %s: %w", routeDescription(r), err)
		}
	}

	for _, r := range rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if slices.ContainsFunc(oldRules, func(w kernelRule) bool { return ruleMatchesIntent(w, r) }) {
			continue
		}
		if err := addRule(r); err != nil {
			return fmt.Errorf("apply rule priority %d table %d src %s/%d dst %s/%d: %w", r.priority, r.table, r.src, r.srcLen, r.dst, r.dstLen, err)
		}
	}
	return nil
}

func routeMatchesIntent(got, want kernelRoute) bool {
	// A gateway-only route lets the kernel select its output interface. Its
	// resolved OIF must not cause deletion/re-addition on every reconcile.
	return got.dst.Equal(want.dst) && got.dstLen == want.dstLen && got.gateway.Equal(want.gateway) && (want.ifIndex == 0 || got.ifIndex == want.ifIndex) && got.table == want.table && got.metric == want.metric && got.tos == want.tos
}

func ruleMatchesIntent(a, b kernelRule) bool {
	return a.simple && a.priority == b.priority && a.table == b.table && a.src.Equal(b.src) && a.srcLen == b.srcLen && a.dst.Equal(b.dst) && a.dstLen == b.dstLen
}

func ownedRulesEqual(a, b kernelRule) bool {
	return a.priority == b.priority && a.table == b.table && a.src.Equal(b.src) && a.srcLen == b.srcLen && a.dst.Equal(b.dst) && a.dstLen == b.dstLen && a.proto == b.proto
}

func readNetlinkAck(fd int, seq uint32) error {
	return readAck(fd, seq, true)
}

// Unresolved routing collisions must be reported, never silently adopted.
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
		code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
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

// Verify a route dump completed rather than accepting a partial snapshot.
func routeDumpError(m syscall.NetlinkMessage) error {
	if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
		return fmt.Errorf("interrupted routing dump")
	}
	if m.Header.Type == unix.NLMSG_DONE && len(m.Data) >= 4 {
		code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
		if code != 0 {
			return unix.Errno(-code)
		}
	}
	return nil
}
