// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package session

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// rawInjector writes resets through one raw IPPROTO_RAW socket. The kernel
// treats IPPROTO_RAW as IP_HDRINCL, so the spoofed source in the header is
// sent as written; the routing table picks the egress interface.
type rawInjector struct {
	mu sync.RWMutex // read: a send is using fd; write: Close
	fd int          // -1 after Close
}

// NewInjector opens the raw socket. It needs CAP_NET_RAW; without it the
// error wraps the socket failure (for example EPERM).
func NewInjector() (Injector, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("session: open raw IPv4 socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("session: set IP_HDRINCL: %w", err)
	}
	return &rawInjector{fd: fd}, nil
}

func (in *rawInjector) SendRST(r Reset) error {
	pkt, err := buildRST(r)
	if err != nil {
		return err
	}
	in.mu.RLock()
	defer in.mu.RUnlock()
	if in.fd < 0 {
		return net.ErrClosed
	}
	if err := unix.Sendto(in.fd, pkt, 0, &unix.SockaddrInet4{Addr: r.Dst.Addr().Unmap().As4()}); err != nil {
		return fmt.Errorf("session: send RST %s -> %s seq %d: %w", r.Src, r.Dst, r.Seq, err)
	}
	return nil
}

func (in *rawInjector) Close() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.fd < 0 {
		return nil
	}
	err := unix.Close(in.fd)
	in.fd = -1
	return err
}
