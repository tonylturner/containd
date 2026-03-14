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
	if err := validateCaptureRequest(ifaceName, duration); err != nil {
		return 0, err
	}
	f, err := createPCAPOutput(outPath)
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
	fd, err := openCaptureSocket(iface.Index)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	return capturePackets(ctx, f, fd, duration, snaplen)
}

func validateCaptureRequest(ifaceName string, duration time.Duration) error {
	if ifaceName == "" {
		return fmt.Errorf("iface required")
	}
	if duration <= 0 {
		return fmt.Errorf("duration must be > 0")
	}
	return nil
}

func createPCAPOutput(outPath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return nil, err
	}
	return os.Create(outPath)
}

func openCaptureSocket(ifindex int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(unix.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return 0, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func capturePackets(ctx context.Context, f *os.File, fd int, duration time.Duration, snaplen int) (int, error) {
	end := time.Now().Add(duration)
	buf := make([]byte, snaplen)
	pkts := 0

	for {
		if captureDeadlineReached(end) {
			break
		}
		select {
		case <-ctx.Done():
			return pkts, ctx.Err()
		default:
		}

		pollfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollfds, capturePollTimeout(end))
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

func captureDeadlineReached(end time.Time) bool {
	return time.Now().After(end)
}

func capturePollTimeout(end time.Time) int {
	timeout := int(end.Sub(time.Now()).Milliseconds())
	if timeout > 250 {
		return 250
	}
	if timeout < 0 {
		return 0
	}
	return timeout
}

func htons16(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
