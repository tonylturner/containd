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

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	var fd int
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	if err := raw.Control(func(s uintptr) {
		fd = int(s)
	}); err != nil {
		return err
	}
	if fd == 0 {
		return fmt.Errorf("failed to get UDP socket fd")
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1); err != nil {
		return err
	}

	const (
		basePort              = 33434
		probesPerHop          = 3
		probeTimeout          = 2 * time.Second
		icmpTypeDestUnreach   = 3
		icmpTypeTimeExceeded  = 11
		icmpCodePortUnreach   = 3
		originICMP            = 2 // SO_EE_ORIGIN_ICMP
	)

	fmt.Fprintf(out, "traceroute to %s (%s), %d hops max (udp/%d)\n", host, dst4.String(), maxHops, basePort)

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return fmt.Errorf("set TTL=%d: %w", ttl, err)
		}

		fmt.Fprintf(out, "%2d  ", ttl)
		peerIP := ""
		reached := false

		for probe := 0; probe < probesPerHop; probe++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			port := basePort + ttl + probe
			start := time.Now()
			if _, err := conn.WriteToUDP([]byte{0}, &net.UDPAddr{IP: dst4, Port: port}); err != nil {
				fmt.Fprint(out, "* ")
				continue
			}

			hopIP, serr, ok := recvIPv4ErrQueue(ctx, fd, time.Now().Add(probeTimeout))
			if !ok || serr == nil {
				fmt.Fprint(out, "* ")
				continue
			}

			if peerIP == "" && hopIP != "" {
				peerIP = hopIP
				fmt.Fprintf(out, "%s  ", peerIP)
			}

			fmt.Fprintf(out, "%s ", time.Since(start).Round(time.Millisecond))

			// Consider ourselves "reached" when destination returns port unreachable.
			if serr.Origin == originICMP && serr.Type == icmpTypeDestUnreach && serr.Code == icmpCodePortUnreach {
				reached = true
			}

			// Drain any extra errors quickly to avoid stale reads on the next probe.
			_, _, _ = recvIPv4ErrQueue(ctx, fd, time.Now().Add(10*time.Millisecond))
		}

		if peerIP == "" {
			// If we didn't get a hop IP, we still want consistent output.
			_ = peerIP
		}
		fmt.Fprintln(out)

		if reached {
			break
		}
	}

	return nil
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
