// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// zoneWatchRetry is the wait before resubscribing after a failure.
const zoneWatchRetry = time.Second

// watch subscribes the cache to the link and address changes of the
// engine's network namespace until ctx ends, resubscribing after a
// failure, which it reports to onError. While it is not subscribed, the
// cache reads the interfaces on every lookup.
func (c *zoneCache) watch(ctx context.Context, onError func(error)) {
	for {
		err := c.watchOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if onError != nil {
			onError(fmt.Errorf("zone cache: interface change notifications: %w", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(zoneWatchRetry):
		}
	}
}

// watchOnce holds one subscription until ctx ends or a read fails.
func (c *zoneCache) watchOnce(ctx context.Context) error {
	sock, err := subscribeInterfaceChanges()
	if err != nil {
		return err
	}
	defer sock.Close()
	// Closing the socket ends a blocked read.
	stop := context.AfterFunc(ctx, func() { _ = sock.Close() })
	defer stop()
	c.subscribed()
	defer c.unsubscribed()
	buf := make([]byte, 64<<10)
	for {
		_, err := sock.Read(buf)
		switch {
		case err == nil:
			// Any link or address notification may change a zone's
			// networks; they are not parsed.
			c.changed()
		case errors.Is(err, unix.ENOBUFS):
			// The socket overflowed: notifications were lost.
			c.changed()
		default:
			return err
		}
	}
}

// subscribeInterfaceChanges opens a route netlink socket subscribed to
// link and IPv4 and IPv6 address notifications. The socket is
// non-blocking, so its reads wait in the runtime poller and Close ends
// them.
func subscribeInterfaceChanges() (*os.File, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	// nl_groups is a bitmask of 1 << (group - 1).
	groups := uint32(1<<(unix.RTNLGRP_LINK-1) | 1<<(unix.RTNLGRP_IPV4_IFADDR-1) | 1<<(unix.RTNLGRP_IPV6_IFADDR-1))
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return os.NewFile(uintptr(fd), "rtnetlink"), nil
}
