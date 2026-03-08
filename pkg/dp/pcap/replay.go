// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package pcap

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func replayFile(ctx context.Context, path string, iface *net.Interface, ratePPS int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	snaplen, err := readPCAPGlobalHeader(f)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return err
	}

	delay := time.Duration(0)
	if ratePPS > 0 {
		delay = time.Second / time.Duration(ratePPS)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, data, err := readPCAPPacket(f, snaplen)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(data) == 0 {
			continue
		}
		if err := unix.Sendto(fd, data, 0, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}
