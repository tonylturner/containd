package cli

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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

		c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		defer c.Close()

		id := os.Getpid() & 0xffff
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
			if _, err := c.WriteTo(b, &net.IPAddr{IP: ip}); err != nil {
				fmt.Fprintf(out, "seq=%d send error: %v\n", seq, err)
				continue
			}
			buf := make([]byte, 1500)
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
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

		pc, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		defer pc.Close()

		id := os.Getpid() & 0xffff
		ipc := pc.IPv4PacketConn()
		fmt.Fprintf(out, "traceroute to %s (%s), %d hops max\n", host, dst.String(), maxHops)
		for ttl := 1; ttl <= maxHops; ttl++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			_ = ipc.SetTTL(ttl)
			seq := ttl
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("containd-trace")},
			}
			b, _ := msg.Marshal(nil)
			start := time.Now()
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := pc.WriteTo(b, &net.IPAddr{IP: dst}); err != nil {
				fmt.Fprintf(out, "%2d  send error: %v\n", ttl, err)
				continue
			}

			buf := make([]byte, 1500)
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				fmt.Fprintf(out, "%2d  *\n", ttl)
				continue
			}
			rtt := time.Since(start).Round(time.Millisecond)
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				fmt.Fprintf(out, "%2d  %s  (parse error)\n", ttl, peer.String())
				continue
			}
			fmt.Fprintf(out, "%2d  %s  %s\n", ttl, peer.String(), rtt)
			if rm.Type == ipv4.ICMPTypeEchoReply {
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

func writePCAPGlobalHeader(w io.Writer, snaplen uint32) error {
	// https://wiki.wireshark.org/Development/LibpcapFileFormat
	type hdr struct {
		Magic        uint32
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32
		SigFigs      uint32
		SnapLen      uint32
		Network      uint32
	}
	h := hdr{
		Magic:        0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      snaplen,
		Network:      1, // LINKTYPE_ETHERNET
	}
	return binary.Write(w, binary.LittleEndian, h)
}

func writePCAPPacket(w io.Writer, ts time.Time, data []byte) error {
	type rec struct {
		TsSec   uint32
		TsUsec  uint32
		InclLen uint32
		OrigLen uint32
	}
	r := rec{
		TsSec:   uint32(ts.Unix()),
		TsUsec:  uint32(ts.Nanosecond() / 1000),
		InclLen: uint32(len(data)),
		OrigLen: uint32(len(data)),
	}
	if err := binary.Write(w, binary.LittleEndian, r); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
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
