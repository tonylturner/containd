// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

func enableForwarding() error {
	// These sysctls are per-netns on Linux.
	if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		// In some containerized environments (notably Docker Desktop / VM-backed runtimes),
		// kernel sysctls may be mounted read-only or blocked. Forwarding is still often
		// effectively enabled in the underlying VM; do not fail interface application
		// just because we can't write the sysctl from inside the container.
		if isSysctlWriteBlocked(err) {
			return nil
		}
		return fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	// Best-effort: enable v6 forwarding for future dual-stack. Not all kernels expose this.
	_ = writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	return nil
}

func isSysctlWriteBlocked(err error) bool {
	if err == nil {
		return false
	}
	// Common error types include *os.PathError wrapping syscall.Errno.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES || errno == syscall.EROFS
	}
	return os.IsPermission(err)
}

func writeSysctl(path, val string) error {
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("empty sysctl value")
	}
	if !strings.HasSuffix(val, "\n") {
		val += "\n"
	}
	return os.WriteFile(path, []byte(val), 0o644)
}

func addDefaultRoute(ifIndex int, gateway string) error {
	ip := net.ParseIP(strings.TrimSpace(gateway))
	if ip == nil {
		return fmt.Errorf("invalid gateway %q", gateway)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 gateways supported for now: %q", gateway)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  0,
		Src_len:  0,
		Tos:      0,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
		Flags:    0,
	}
	_ = binary.Write(&req, binary.LittleEndian, rtm)

	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	addRtAttr(&req, unix.RTA_OIF, oif)
	addRtAttr(&req, unix.RTA_GATEWAY, ip4)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

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
