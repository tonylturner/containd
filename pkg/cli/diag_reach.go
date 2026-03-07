// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func diagReach(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 2 {
			return fmt.Errorf("usage: diag reach <src_iface> <dst_host|dst_ip|dst_iface> [tcp_port] | diag reach <src_iface> <dst> <tcp|udp|icmp> [port]")
		}
		src := strings.TrimSpace(args[0])
		dst := strings.TrimSpace(args[1])
		if src == "" || dst == "" {
			return fmt.Errorf("usage: diag reach <src_iface> <dst_host|dst_ip|dst_iface> [tcp_port] | diag reach <src_iface> <dst> <tcp|udp|icmp> [port]")
		}

		proto := "tcp"
		port := 0
		if len(args) >= 3 {
			a2 := strings.TrimSpace(args[2])
			if a2 != "" {
				// Backward compatible: diag reach <src> <dst> <port>
				if p, err := strconv.Atoi(a2); err == nil {
					if p < 1 || p > 65535 {
						return fmt.Errorf("invalid port: %q", args[2])
					}
					proto = "tcp"
					port = p
				} else {
					switch strings.ToLower(a2) {
					case "tcp", "udp", "icmp":
						proto = strings.ToLower(a2)
					default:
						return fmt.Errorf("invalid protocol %q (expected tcp|udp|icmp)", a2)
					}
					if len(args) >= 4 && strings.TrimSpace(args[3]) != "" {
						if proto == "icmp" {
							return fmt.Errorf("icmp does not take a port")
						}
						p, err := strconv.Atoi(strings.TrimSpace(args[3]))
						if err != nil || p < 1 || p > 65535 {
							return fmt.Errorf("invalid port: %q", args[3])
						}
						port = p
					}
				}
			}
		}

		dev, srcIP, err := resolveSourceInterfaceIPv4(ctx, store, src)
		if err != nil {
			return err
		}

		dstIP, dstIsIface, dstDev, err := resolveDestIPv4(ctx, store, dst)
		if err != nil {
			return err
		}

		fmt.Fprintf(out, "reachability from %s (%s) to %s (%s)\n\n", src, srcIP.String(), dst, dstIP.String())

		routeLocal, routeErr := probeRoute(ctx, dev, srcIP, dstIP)
		t := newTable("CHECK", "STATUS", "DETAILS")
		if routeErr != nil {
			t.addRow("route", "error", routeErr.Error())
		} else {
			t.addRow("route", "ok", "local="+routeLocal)
		}

		switch proto {
		case "tcp":
			switch {
			case port != 0:
				status, detail := probeTCP(ctx, dev, srcIP, dstIP, port, true)
				t.addRow("tcp", status, detail)
			case dstIsIface:
				// For interface destinations, a blank port runs a safe self-test.
				status, detail := probeTCPSelf(ctx, srcIP, dstIP, 0)
				t.addRow("tcp", status, detail)
			default:
				t.addRow("tcp", "skipped", "no port provided")
			}
		case "udp":
			switch {
			case port != 0:
				status, detail := probeUDP(ctx, dev, srcIP, dstIP, port, true)
				t.addRow("udp", status, detail)
			case dstIsIface:
				status, detail := probeUDPSelf(ctx, dev, srcIP, dstIP, 0)
				t.addRow("udp", status, detail)
			default:
				t.addRow("udp", "skipped", "no port provided")
			}
		case "icmp":
			status, detail := probeICMPOnce(ctx, srcIP, dstIP)
			t.addRow("icmp", status, detail)
		default:
			_ = dstDev
			t.addRow("tcp", "error", "invalid protocol")
		}

		t.render(out)
		return nil
	}
}

func resolveSourceInterfaceIPv4(ctx context.Context, store config.Store, src string) (dev string, ip net.IP, err error) {
	dev = src
	// If the user passed a logical interface name and it's configured, prefer its binding.
	if store != nil {
		if cfg, err2 := store.Load(ctx); err2 == nil && cfg != nil {
			for _, iface := range cfg.Interfaces {
				if strings.EqualFold(strings.TrimSpace(iface.Name), src) {
					if d := strings.TrimSpace(iface.Device); d != "" {
						dev = d
					}
					break
				}
			}
		}
	}
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return "", nil, fmt.Errorf("source interface is empty")
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return dev, nil, fmt.Errorf("source interface %q not found: %w", dev, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return dev, nil, fmt.Errorf("read addresses for %q: %w", dev, err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil {
			continue
		}
		// Skip link-local.
		if v4[0] == 169 && v4[1] == 254 {
			continue
		}
		return dev, v4, nil
	}
	return dev, nil, fmt.Errorf("no IPv4 address found on %q", dev)
}

func resolveDestIPv4(ctx context.Context, store config.Store, dst string) (ip net.IP, isIface bool, dev string, err error) {
	dst = strings.TrimSpace(dst)
	if dst == "" {
		return nil, false, "", fmt.Errorf("destination is empty")
	}
	// IP literal?
	if ip2 := net.ParseIP(dst); ip2 != nil {
		if v4 := ip2.To4(); v4 != nil {
			return v4, false, "", nil
		}
	}

	// Config logical interface name?
	if store != nil {
		if cfg, err2 := store.Load(ctx); err2 == nil && cfg != nil {
			for _, iface := range cfg.Interfaces {
				if strings.EqualFold(strings.TrimSpace(iface.Name), dst) {
					dev2 := strings.TrimSpace(firstNonEmpty(iface.Device, iface.Name))
					ip2, err3 := ipv4OnInterface(dev2)
					if err3 == nil && ip2 != nil {
						return ip2, true, dev2, nil
					}
				}
			}
		}
	}

	// Kernel interface name?
	if ip2, err2 := ipv4OnInterface(dst); err2 == nil && ip2 != nil {
		return ip2, true, dst, nil
	}

	// Hostname/DNS.
	ip2, err2 := resolveIPv4(dst)
	if err2 != nil {
		return nil, false, "", err2
	}
	return ip2, false, "", nil
}

func ipv4OnInterface(dev string) (net.IP, error) {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return nil, fmt.Errorf("interface is empty")
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil {
			continue
		}
		if v4[0] == 169 && v4[1] == 254 {
			continue
		}
		return v4, nil
	}
	return nil, fmt.Errorf("no IPv4 address found on %q", dev)
}

func probeRoute(ctx context.Context, dev string, srcIP net.IP, dstIP net.IP) (local string, err error) {
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.UDPAddr{
			IP: srcIP,
		},
		Control: bindToDeviceControl(dev),
	}
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dstIP.String(), "33434"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().String(), nil
}

func probeTCP(ctx context.Context, dev string, srcIP net.IP, dstIP net.IP, port int, bindDev bool) (status string, detail string) {
	start := time.Now()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: srcIP,
		},
	}
	if bindDev {
		d.Control = bindToDeviceControl(dev)
	}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port)))
	rtt := time.Since(start).Round(time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return "open", "connected in " + rtt.String()
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "timeout", "no response after " + rtt.String()
	}
	// Connection refused indicates reachability but closed port.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused", "reachable (connection refused) in " + rtt.String()
	}
	return "error", fmt.Sprintf("%v (%s)", err, rtt.String())
}

func probeTCPSelf(ctx context.Context, srcIP net.IP, dstIP net.IP, port int) (status string, detail string) {
	// Start a short-lived listener on the destination IP, then connect from the source IP.
	// This validates that the kernel can route/connect between those addresses even when no
	// service is running on the destination.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port)))
	if err != nil {
		return "error", "listen failed: " + err.Error()
	}
	defer ln.Close()

	actualPort := 0
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		actualPort = ta.Port
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		c, err := ln.Accept()
		if err == nil && c != nil {
			_ = c.Close()
		}
	}()

	start := time.Now()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: srcIP,
		},
	}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(actualPort)))
	rtt := time.Since(start).Round(time.Millisecond)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return "timeout", "no response after " + rtt.String()
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return "refused", "reachable (connection refused) in " + rtt.String()
		}
		return "error", fmt.Sprintf("%v (%s)", err, rtt.String())
	}
	_ = conn.Close()
	<-done
	if port == 0 {
		return "ok", fmt.Sprintf("self-test connected to %s:%d in %s", dstIP.String(), actualPort, rtt.String())
	}
	return "ok", "self-test connected in " + rtt.String()
}

func probeUDP(ctx context.Context, dev string, srcIP net.IP, dstIP net.IP, port int, bindDev bool) (status string, detail string) {
	start := time.Now()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.UDPAddr{
			IP: srcIP,
		},
	}
	if bindDev {
		d.Control = bindToDeviceControl(dev)
	}
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port)))
	rtt := time.Since(start).Round(time.Millisecond)
	if err != nil {
		return "error", fmt.Sprintf("%v (%s)", err, rtt.String())
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("containd")); err != nil {
		return "error", fmt.Sprintf("send failed: %v (%s)", err, rtt.String())
	}
	// UDP has no handshake; if we could send, that's "reachable enough" for many cases.
	return "sent", "datagram sent in " + rtt.String()
}

func probeUDPSelf(ctx context.Context, dev string, srcIP net.IP, dstIP net.IP, port int) (status string, detail string) {
	// Start a short-lived UDP listener on the destination IP, send a datagram from the source IP,
	// and confirm it was received. This gives a deterministic signal even without a real service.
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port)))
	if err != nil {
		return "error", "listen failed: " + err.Error()
	}
	defer pc.Close()
	udpAddr, _ := pc.LocalAddr().(*net.UDPAddr)
	actualPort := 0
	if udpAddr != nil {
		actualPort = udpAddr.Port
	}

	recv := make(chan error, 1)
	go func() {
		_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _, err := pc.ReadFrom(buf)
		recv <- err
	}()

	start := time.Now()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.UDPAddr{
			IP: srcIP,
		},
		Control: bindToDeviceControl(dev),
	}
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(actualPort)))
	if err != nil {
		return "error", "dial failed: " + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("containd")); err != nil {
		return "error", "send failed: " + err.Error()
	}
	err = <-recv
	rtt := time.Since(start).Round(time.Millisecond)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return "timeout", "no response after " + rtt.String()
		}
		return "error", fmt.Sprintf("%v (%s)", err, rtt.String())
	}
	if port == 0 {
		return "ok", fmt.Sprintf("self-test received on %s:%d in %s", dstIP.String(), actualPort, rtt.String())
	}
	return "ok", "self-test received in " + rtt.String()
}

func probeICMPOnce(ctx context.Context, srcIP net.IP, dstIP net.IP) (status string, detail string) {
	// Best-effort single ICMP echo. In many container labs ICMP is blocked; surface that clearly.
	ip4 := dstIP.To4()
	if ip4 == nil {
		return "error", "only IPv4 is supported"
	}
	// Prefer raw ICMP; fallback to unprivileged datagram ICMP if allowed.
	pc, err := listenICMPv4("0.0.0.0")
	if err != nil {
		if isRawSocketDenied(err) {
			return "blocked", "raw sockets not permitted for icmp"
		}
		return "error", err.Error()
	}
	defer pc.Close()

	id := (time.Now().Nanosecond() & 0xffff)
	dstAddr := icmpV4DstAddr(pc, ip4, id)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("containd-reach")},
	}
	b, _ := msg.Marshal(nil)
	start := time.Now()
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc.WriteTo(b, dstAddr); err != nil {
		if isRawSocketDenied(err) {
			return "blocked", "raw sockets not permitted for icmp"
		}
		return "error", err.Error()
	}
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	rtt := time.Since(start).Round(time.Millisecond)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return "timeout", "no response after " + rtt.String()
		}
		if isRawSocketDenied(err) {
			return "blocked", "raw sockets not permitted for icmp"
		}
		return "error", fmt.Sprintf("%v (%s)", err, rtt.String())
	}
	rm, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return "error", fmt.Sprintf("parse error: %v (%s)", err, rtt.String())
	}
	if rm.Type == ipv4.ICMPTypeEchoReply {
		return "ok", "echo reply in " + rtt.String()
	}
	return "error", fmt.Sprintf("unexpected icmp type: %v (%s)", rm.Type, rtt.String())
}
