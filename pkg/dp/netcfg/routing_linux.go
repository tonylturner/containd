// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"syscall"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

const (
	// routeProtoContaind marks routes installed by containd so we can safely reconcile them.
	// This is a local netns concern (container/appliance); it avoids deleting host/system routes.
	routeProtoContaind = 98

	// managedRulePriorityBase is the default priority base used for auto-assigned rules.
	// We treat this range as "managed by containd" for safe reconcile.
	managedRulePriorityBase = 10000
	managedRulePriorityMax  = 19999
)

func applyRouting(ctx context.Context, routing config.RoutingConfig, opts ApplyRoutingOptions) error {
	if opts.Replace {
		if err := deleteManagedRoutes(ctx); err != nil {
			return err
		}
		if err := deleteManagedRules(ctx); err != nil {
			return err
		}
	}

	gwByName := map[string]config.Gateway{}
	for _, gw := range routing.Gateways {
		name := strings.TrimSpace(gw.Name)
		if name == "" {
			continue
		}
		gwByName[name] = gw
	}

	for _, r := range routing.Routes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := addRoute(r, gwByName); err != nil {
			return err
		}
	}
	for i, rule := range routing.Rules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := addRule(rule, i); err != nil {
			return err
		}
	}
	return nil
}

func readNetlinkAck(fd int, seq uint32) error {
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
		if -code == int32(unix.EEXIST) {
			return nil
		}
		return unix.Errno(-code)
	}
	return nil
}
