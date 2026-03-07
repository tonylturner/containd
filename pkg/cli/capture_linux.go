// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func captureToPCAP(ctx context.Context, ifaceName string, duration time.Duration, outPath string) (int, error) {
	if ifaceName == "" {
		return 0, fmt.Errorf("iface required")
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be > 0")
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	const snaplen = 65535
	if err := writePCAPGlobalHeader(f, snaplen); err != nil {
		return 0, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("unknown interface %q: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(unix.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	if err := unix.SetNonblock(fd, true); err != nil {
		return 0, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return 0, err
	}

	end := time.Now().Add(duration)
	buf := make([]byte, snaplen)
	pkts := 0

	for {
		if time.Now().After(end) {
			break
		}
		select {
		case <-ctx.Done():
			return pkts, ctx.Err()
		default:
		}

		timeout := int(end.Sub(time.Now()).Milliseconds())
		if timeout > 250 {
			timeout = 250
		}
		if timeout < 0 {
			timeout = 0
		}
		pollfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollfds, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return pkts, err
		}
		if n == 0 || pollfds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		rn, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return pkts, err
		}
		if rn <= 0 {
			continue
		}
		data := buf[:rn]
		if err := writePCAPPacket(f, time.Now(), data); err != nil {
			return pkts, err
		}
		pkts++
	}

	return pkts, nil
}

func htons16(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
