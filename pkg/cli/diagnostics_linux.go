// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	tracerouteImpl = tracerouteUDPv4Linux
}

const (
	minPollTimeoutMillis = 25
	maxPollTimeoutMillis = 250
)

func tracerouteUDPv4Linux(ctx context.Context, out io.Writer, host string, dst net.IP, maxHops int) error {
	dst4 := dst.To4()
	if dst4 == nil {
		return fmt.Errorf("only IPv4 is supported for now")
	}

	conn, fd, err := openTracerouteSocket()
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Fprintf(out, "traceroute to %s (%s), %d hops max (udp/%d)\n", host, dst4.String(), maxHops, tracerouteBasePort)

	for ttl := 1; ttl <= maxHops; ttl++ {
		reached, err := runTracerouteHop(ctx, out, conn, fd, dst4, ttl)
		if err != nil {
			return err
		}
		if reached {
			break
		}
	}

	return nil
}

const (
	tracerouteBasePort           = 33434
	tracerouteProbesPerHop       = 3
	tracerouteProbeTimeout       = 2 * time.Second
	tracerouteDrainTimeout       = 10 * time.Millisecond
	icmpTypeDestUnreach          = 3
	icmpCodePortUnreach          = 3
	originICMP             uint8 = 2 // SO_EE_ORIGIN_ICMP
)

func openTracerouteSocket() (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, 0, err
	}
	fd, err := tracerouteSocketFD(conn)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1); err != nil {
		conn.Close()
		return nil, 0, err
	}
	return conn, fd, nil
}

func tracerouteSocketFD(conn *net.UDPConn) (int, error) {
	var fd int
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if err := raw.Control(func(s uintptr) {
		fd = int(s)
	}); err != nil {
		return 0, err
	}
	if fd == 0 {
		return 0, fmt.Errorf("failed to get UDP socket fd")
	}
	return fd, nil
}

func runTracerouteHop(ctx context.Context, out io.Writer, conn *net.UDPConn, fd int, dst net.IP, ttl int) (bool, error) {
	if err := tracerouteContext(ctx); err != nil {
		return false, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
		return false, fmt.Errorf("set TTL=%d: %w", ttl, err)
	}

	fmt.Fprintf(out, "%2d  ", ttl)
	peerIP := ""
	reached := false
	for probe := 0; probe < tracerouteProbesPerHop; probe++ {
		hopIP, hopReached, rtt, ok, err := runTracerouteProbe(ctx, conn, fd, dst, ttl, probe)
		if err != nil {
			return false, err
		}
		if !ok {
			fmt.Fprint(out, "* ")
			continue
		}
		if peerIP == "" && hopIP != "" {
			peerIP = hopIP
			fmt.Fprintf(out, "%s  ", peerIP)
		}
		fmt.Fprintf(out, "%s ", rtt.Round(time.Millisecond))
		if hopReached {
			reached = true
		}
	}
	fmt.Fprintln(out)
	return reached, nil
}

func runTracerouteProbe(ctx context.Context, conn *net.UDPConn, fd int, dst net.IP, ttl, probe int) (string, bool, time.Duration, bool, error) {
	if err := tracerouteContext(ctx); err != nil {
		return "", false, 0, false, err
	}

	port := tracerouteBasePort + ttl + probe
	start := time.Now()
	if _, err := conn.WriteToUDP([]byte{0}, &net.UDPAddr{IP: dst, Port: port}); err != nil {
		return "", false, 0, false, nil
	}

	hopIP, serr, ok := recvIPv4ErrQueue(ctx, fd, time.Now().Add(tracerouteProbeTimeout))
	if !ok || serr == nil {
		return "", false, 0, false, nil
	}
	reached := serr.Origin == originICMP && serr.Type == icmpTypeDestUnreach && serr.Code == icmpCodePortUnreach
	rtt := time.Since(start)
	_, _, _ = recvIPv4ErrQueue(ctx, fd, time.Now().Add(tracerouteDrainTimeout))
	return hopIP, reached, rtt, true, nil
}

func tracerouteContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func recvIPv4ErrQueue(ctx context.Context, fd int, deadline time.Time) (hopIP string, serr *unix.SockExtendedErr, ok bool) {
	buf := make([]byte, 256)
	oob := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return "", nil, false
		default:
		}

		now := time.Now()
		if !deadline.After(now) {
			return "", nil, false
		}

		remaining := deadline.Sub(now)
		timeoutMs := int(remaining / time.Millisecond)
		if timeoutMs < minPollTimeoutMillis {
			timeoutMs = minPollTimeoutMillis
		}
		if timeoutMs > maxPollTimeoutMillis {
			timeoutMs = maxPollTimeoutMillis
		}

		pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR}}
		n, err := unix.Poll(pfds, timeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return "", nil, false
		}
		if n == 0 {
			continue
		}

		_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return "", nil, false
		}

		cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return "", nil, false
		}
		for _, cmsg := range cmsgs {
			if cmsg.Header.Level != unix.SOL_IP || cmsg.Header.Type != unix.IP_RECVERR {
				continue
			}
			serr2, offender, ok2 := parseSockExtendedErrIPv4(cmsg.Data)
			if !ok2 || serr2 == nil {
				continue
			}
			return offender, serr2, true
		}
	}
}

func parseSockExtendedErrIPv4(data []byte) (*unix.SockExtendedErr, string, bool) {
	serrSize := int(unsafe.Sizeof(unix.SockExtendedErr{}))
	offSize := int(unsafe.Sizeof(unix.RawSockaddrInet4{}))
	if len(data) < serrSize {
		return nil, "", false
	}

	serr := *(*unix.SockExtendedErr)(unsafe.Pointer(&data[0]))
	off := data[serrSize:]
	if len(off) < offSize {
		return &serr, "", true
	}

	rsa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&off[0]))
	if rsa.Family != unix.AF_INET {
		return &serr, "", true
	}
	ip := net.IPv4(rsa.Addr[0], rsa.Addr[1], rsa.Addr[2], rsa.Addr[3]).String()
	return &serr, ip, true
}
