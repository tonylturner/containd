// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var tracerouteImpl = tracerouteICMPv4

func isRawSocketDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && (errors.Is(opErr.Err, syscall.EPERM) || errors.Is(opErr.Err, syscall.EACCES)) {
		return true
	}
	return false
}

func showIPRoute() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		routes, err := listIPv4Routes()
		if err != nil {
			return err
		}
		if len(routes) == 0 {
			fmt.Fprintln(out, "No routes.")
			return nil
		}
		ifaceNames := map[int]string{}
		for _, r := range routes {
			if r.IfIndex != 0 {
				if _, ok := ifaceNames[r.IfIndex]; !ok {
					ifaceNames[r.IfIndex] = strconv.Itoa(r.IfIndex)
					iface, err := net.InterfaceByIndex(r.IfIndex)
					if err == nil && iface != nil && iface.Name != "" {
						ifaceNames[r.IfIndex] = iface.Name
					}
				}
			}
		}
		t := newTable("DEST", "GATEWAY", "IFACE", "METRIC")
		for _, r := range routes {
			dest := r.Dst
			if dest == "" {
				dest = "default"
			}
			gw := r.Gateway
			if gw == "" {
				gw = "—"
			}
			iface := "—"
			if r.IfIndex != 0 {
				iface = firstNonEmpty(ifaceNames[r.IfIndex], strconv.Itoa(r.IfIndex))
			}
			metric := "—"
			if r.Priority != nil {
				metric = strconv.Itoa(*r.Priority)
			}
			t.addRow(dest, gw, iface, metric)
		}
		t.render(out)
		return nil
	}
}

type ipv4Route struct {
	Dst      string
	Gateway  string
	IfIndex  int
	Priority *int
	Table    *int
}

func rawSocketHint(err error) error {
	if err == nil {
		return nil
	}
	// Most common in containers without CAP_NET_RAW.
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%w (raw sockets not permitted; try CAP_NET_RAW via docker-compose cap_add: [NET_RAW] or allow unprivileged ping via net.ipv4.ping_group_range)", err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && (errors.Is(opErr.Err, syscall.EPERM) || errors.Is(opErr.Err, syscall.EACCES)) {
		return fmt.Errorf("%w (raw sockets not permitted; try CAP_NET_RAW via docker-compose cap_add: [NET_RAW] or allow unprivileged ping via net.ipv4.ping_group_range)", err)
	}
	return err
}

func listenICMPv4(addr string) (*icmp.PacketConn, error) {
	// Prefer raw ICMP; fallback to unprivileged ICMP datagram if blocked.
	pc, err := icmp.ListenPacket("ip4:icmp", addr)
	if err == nil {
		return pc, nil
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		pc2, err2 := icmp.ListenPacket("udp4", addr)
		if err2 == nil {
			return pc2, nil
		}
		return nil, rawSocketHint(err2)
	}
	return nil, err
}

func icmpV4DstAddr(pc *icmp.PacketConn, ip net.IP, echoID int) net.Addr {
	if pc == nil {
		return &net.IPAddr{IP: ip}
	}
	// When using "udp4" (datagram ICMP), the underlying net.PacketConn expects
	// a UDPAddr and uses the port field as the ICMP identifier.
	if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: ip, Port: echoID & 0xffff}
	}
	return &net.IPAddr{IP: ip}
}

func diagPing() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: diag ping <host> [count]")
		}
		host := args[0]
		count := 4
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 && v <= 20 {
				count = v
			}
		}
		ip, err := resolveIPv4(host)
		if err != nil {
			return err
		}

		c, err := listenICMPv4("0.0.0.0")
		if err != nil {
			if isRawSocketDenied(err) {
				return tcpPingFallback(ctx, out, host, ip, count)
			}
			return err
		}
		defer c.Close()

		id := os.Getpid() & 0xffff
		dstAddr := icmpV4DstAddr(c, ip, id)
		var rtts []time.Duration
		fmt.Fprintf(out, "PING %s (%s):\n", host, ip.String())
		for i := 0; i < count; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			seq := i + 1
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("containd")},
			}
			b, _ := msg.Marshal(nil)
			start := time.Now()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.WriteTo(b, dstAddr); err != nil {
				if isRawSocketDenied(err) {
					// Some environments allow opening a UDP-based ICMP socket but deny sending/receiving.
					// Fall back to a TCP connect probe so "diag ping" remains useful in containers.
					return tcpPingFallback(ctx, out, host, ip, count)
				}
				fmt.Fprintf(out, "seq=%d send error: %v\n", seq, err)
				continue
			}
			buf := make([]byte, 1500)
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				if isRawSocketDenied(err) {
					return tcpPingFallback(ctx, out, host, ip, count)
				}
				fmt.Fprintf(out, "seq=%d timeout\n", seq)
				continue
			}
			rtt := time.Since(start)
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				fmt.Fprintf(out, "seq=%d parse error: %v\n", seq, err)
				continue
			}
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				rtts = append(rtts, rtt)
				fmt.Fprintf(out, "seq=%d from=%s time=%s\n", seq, peer.String(), rtt.Round(time.Millisecond))
			default:
				fmt.Fprintf(out, "seq=%d from=%s type=%v time=%s\n", seq, peer.String(), rm.Type, rtt.Round(time.Millisecond))
			}
			time.Sleep(250 * time.Millisecond)
		}
		if len(rtts) == 0 {
			fmt.Fprintln(out, "no replies")
			return nil
		}
		var sum time.Duration
		min := rtts[0]
		max := rtts[0]
		for _, d := range rtts {
			sum += d
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}
		avg := sum / time.Duration(len(rtts))
		fmt.Fprintf(out, "min/avg/max = %s/%s/%s\n", min.Round(time.Millisecond), avg.Round(time.Millisecond), max.Round(time.Millisecond))
		return nil
	}
}

func diagTraceroute() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: diag traceroute <host> [max_hops]")
		}
		host := args[0]
		maxHops := 20
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 && v <= 64 {
				maxHops = v
			}
		}
		dst, err := resolveIPv4(host)
		if err != nil {
			return err
		}
		return tracerouteImpl(ctx, out, host, dst, maxHops)
	}
}

func tracerouteICMPv4(ctx context.Context, out io.Writer, host string, dst net.IP, maxHops int) error {
	pc, err := listenICMPv4("0.0.0.0")
	if err != nil {
		if isRawSocketDenied(err) {
			return fmt.Errorf("%w\n%s", err, "traceroute requires raw sockets for ICMP (or use Linux UDP traceroute where available)")
		}
		return err
	}
	defer pc.Close()

	id := os.Getpid() & 0xffff
	dstAddr := icmpV4DstAddr(pc, dst, id)
	ipc := pc.IPv4PacketConn()
	if ipc == nil {
		return fmt.Errorf("traceroute unavailable: IPv4 packet conn not supported")
	}
	mode := "raw"
	if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		mode = "udp4"
	}
	limitNote := ""
	if mode == "udp4" {
		limitNote = " (limited: intermediate hops may be hidden)"
	}
	fmt.Fprintf(out, "traceroute to %s (%s), %d hops max (icmp/%s)%s\n", host, dst.String(), maxHops, mode, limitNote)
	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ipc.SetTTL(ttl); err != nil {
			return fmt.Errorf("set TTL=%d: %w", ttl, err)
		}
		peerIP := ""
		reached := false

		fmt.Fprintf(out, "%2d  ", ttl)
		for probe := 0; probe < 3; probe++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			seq := ttl*10 + probe
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("containd-trace")},
			}
			b, _ := msg.Marshal(nil)
			start := time.Now()
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := pc.WriteTo(b, dstAddr); err != nil {
				fmt.Fprintf(out, "send=%v ", err)
				continue
			}

			buf := make([]byte, 1500)
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				fmt.Fprint(out, "* ")
				continue
			}
			rtt := time.Since(start).Round(time.Millisecond)
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				fmt.Fprint(out, "? ")
				continue
			}

			if peerIP == "" {
				switch p := peer.(type) {
				case *net.IPAddr:
					peerIP = p.IP.String()
				case *net.UDPAddr:
					peerIP = p.IP.String()
				default:
					peerIP = peer.String()
				}
				if peerIP == "" {
					peerIP = peer.String()
				}
				fmt.Fprintf(out, "%s  ", peerIP)
			}
			fmt.Fprintf(out, "%s ", rtt)

			if rm.Type == ipv4.ICMPTypeEchoReply {
				reached = true
			}
		}
		fmt.Fprintln(out)
		if reached {
			break
		}
	}
	return nil
}

func tcpPingFallback(ctx context.Context, out io.Writer, host string, ip net.IP, count int) error {
	ports := []int{443, 80, 22}
	fmt.Fprintf(out, "PING %s (%s):\n", host, ip.String())
	fmt.Fprintf(out, "note: ICMP not permitted; using TCP connect probes to %v\n", ports)
	var rtts []time.Duration
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		seq := i + 1
		var (
			ok  bool
			rtt time.Duration
		)
		for _, port := range ports {
			target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
			start := time.Now()
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp4", target)
			rtt = time.Since(start)
			if err == nil {
				_ = conn.Close()
				ok = true
				break
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			// Connection refused or other immediate errors still indicate reachability.
			ok = true
			break
		}
		if !ok {
			fmt.Fprintf(out, "seq=%d timeout\n", seq)
		} else {
			rtts = append(rtts, rtt)
			fmt.Fprintf(out, "seq=%d time=%s\n", seq, rtt.Round(time.Millisecond))
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(rtts) == 0 {
		fmt.Fprintln(out, "no replies")
		return nil
	}
	var sum time.Duration
	min := rtts[0]
	max := rtts[0]
	for _, d := range rtts {
		sum += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	avg := sum / time.Duration(len(rtts))
	fmt.Fprintf(out, "min/avg/max = %s/%s/%s\n", min.Round(time.Millisecond), avg.Round(time.Millisecond), max.Round(time.Millisecond))
	return nil
}

func diagTCPTraceroute() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 2 {
			return fmt.Errorf("usage: diag tcptraceroute <host> <port> [max_hops]")
		}
		host := args[0]
		port := strings.TrimSpace(args[1])
		if port == "" {
			return fmt.Errorf("invalid port")
		}
		maxHops := 20
		if len(args) >= 3 {
			if v, err := strconv.Atoi(args[2]); err == nil && v > 0 && v <= 64 {
				maxHops = v
			}
		}
		dst, err := resolveIPv4(host)
		if err != nil {
			return err
		}

		target := net.JoinHostPort(dst.String(), port)
		fmt.Fprintf(out, "tcptraceroute to %s (%s), port %s, %d hops max (limited: intermediate hops may be hidden)\n", host, dst.String(), port, maxHops)

		for ttl := 1; ttl <= maxHops; ttl++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			fmt.Fprintf(out, "%2d  ", ttl)
			reached := false
			for probe := 0; probe < 3; probe++ {
				start := time.Now()
				d := net.Dialer{
					Timeout: 2 * time.Second,
					Control: func(network, address string, c syscall.RawConn) error {
						var ctrlErr error
						if err := c.Control(func(fd uintptr) {
							ctrlErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
						}); err != nil {
							return err
						}
						return ctrlErr
					},
				}
				conn, err := d.DialContext(ctx, "tcp4", target)
				if err == nil {
					_ = conn.Close()
					fmt.Fprintf(out, "%s ", time.Since(start).Round(time.Millisecond))
					reached = true
					continue
				}
				// For low TTLs, many environments simply time out rather than returning ICMP Time Exceeded.
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Timeout() {
					fmt.Fprint(out, "* ")
					continue
				}
				fmt.Fprint(out, "* ")
			}
			fmt.Fprintln(out)
			if reached {
				break
			}
		}
		return nil
	}
}

func diagCapture() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 1 {
			return fmt.Errorf("usage: diag capture <iface> [seconds] [file]")
		}
		ifaceName := args[0]
		seconds := 10
		if len(args) >= 2 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 && v <= 300 {
				seconds = v
			}
		}
		outPath := ""
		if len(args) >= 3 {
			outPath = args[2]
		}
		if outPath == "" {
			ts := time.Now().UTC().Format("20060102T150405Z")
			outPath = filepath.Join("/data", "pcaps", fmt.Sprintf("%s_%s.pcap", ts, ifaceName))
		}

		n, err := captureToPCAP(ctx, ifaceName, time.Duration(seconds)*time.Second, outPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "captured %d packets to %s\n", n, outPath)
		return nil
	}
}

func resolveIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, fmt.Errorf("only IPv4 is supported for now")
	}
	ipaddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, err
	}
	if ipaddr == nil || ipaddr.IP == nil {
		return nil, fmt.Errorf("failed to resolve %q", host)
	}
	return ipaddr.IP.To4(), nil
}
