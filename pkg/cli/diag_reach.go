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

	"github.com/containd/containd/pkg/cp/config"
)

func diagReach(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) < 2 {
			return fmt.Errorf("usage: diag reach <src_iface> <dst_host|dst_ip> [tcp_port]")
		}
		src := strings.TrimSpace(args[0])
		dst := strings.TrimSpace(args[1])
		if src == "" || dst == "" {
			return fmt.Errorf("usage: diag reach <src_iface> <dst_host|dst_ip> [tcp_port]")
		}

		var port int
		if len(args) >= 3 && strings.TrimSpace(args[2]) != "" {
			p, err := strconv.Atoi(strings.TrimSpace(args[2]))
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid tcp_port: %q", args[2])
			}
			port = p
		}

		dev, srcIP, err := resolveSourceInterfaceIPv4(ctx, store, src)
		if err != nil {
			return err
		}

		dstIP, err := resolveIPv4(dst)
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

		if port != 0 {
			status, detail := probeTCP(ctx, dev, srcIP, dstIP, port)
			t.addRow("tcp", status, detail)
		} else {
			t.addRow("tcp", "skipped", "no port provided")
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

func probeTCP(ctx context.Context, dev string, srcIP net.IP, dstIP net.IP, port int) (status string, detail string) {
	start := time.Now()
	d := net.Dialer{
		Timeout: 2 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: srcIP,
		},
		Control: bindToDeviceControl(dev),
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

