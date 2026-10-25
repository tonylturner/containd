// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"golang.org/x/sys/unix"
)

// StartManagementGuard subscribes BEFORE the initial scan and before returning
// permission to start services. Failed/overflowed subscriptions are visibly
// faulted, resubscribed and fully rescanned. A bounded receive wait permits Close.
func StartManagementGuard(ctx context.Context, r *mgmtpath.Reservation, notify func(ManagementFault)) (*ManagementGuard, error) {
	if r == nil {
		return nil, nil
	}
	fd, err := subscribeManagement()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &ManagementGuard{reservation: r, notify: notify, health: managementHealth(r), cancel: cancel, done: make(chan struct{})}
	if err := g.Reconcile(ctx); err != nil {
		cancel()
		unix.Close(fd)
		return nil, err
	}
	go g.watch(ctx, fd)
	return g, nil
}
func subscribeManagement() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	// nl_groups is a BITMASK, not a set of RTNLGRP ordinal values.
	groups := uint32(1<<(unix.RTNLGRP_IPV4_IFADDR-1) | 1<<(unix.RTNLGRP_IPV4_ROUTE-1) | 1<<(unix.RTNLGRP_IPV4_RULE-1) | 1<<(unix.RTNLGRP_LINK-1))
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}
func (g *ManagementGuard) watch(ctx context.Context, fd int) {
	defer close(g.done)
	defer g.setActive(false)
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	buf := make([]byte, 1<<20)
	for ctx.Err() == nil {
		if fd < 0 {
			next, err := subscribeManagement()
			if err != nil {
				g.setError(err)
				g.fault(managementFaultError(err))
				// Re-scan even during a subscription outage; never silently stop guarding.
				_ = g.Reconcile(ctx)
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
				continue
			}
			fd = next
			g.setActive(true)
			_ = g.Reconcile(ctx)
		}
		changed, err := managementChanged(fd, buf)
		if err != nil {
			g.setActive(false)
			g.setError(err)
			g.fault(managementFaultError(err))
			unix.Close(fd)
			fd = -1
			continue
		}
		if changed {
			_ = g.Reconcile(ctx)
		}
	}
}
func managementChanged(fd int, buf []byte) (bool, error) {
	polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(polls, 100)
	if errors.Is(err, unix.EINTR) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if polls[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		return false, fmt.Errorf("management subscription failed/overflowed")
	}
	n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		return false, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return false, fmt.Errorf("management subscription truncated")
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return false, err
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_OVERRUN {
			return false, fmt.Errorf("management subscription overrun")
		}
		if m.Header.Type == unix.NLMSG_ERROR {
			if err := netlinkMessageError(m.Data); err != nil {
				return false, err
			}
		}
	}
	return len(msgs) > 0, nil
}
