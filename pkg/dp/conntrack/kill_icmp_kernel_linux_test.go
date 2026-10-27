// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// pingers are a client peer's continuous echo flows, by name, each with its
// count of answered requests.
type pingers map[string]*atomic.Int64

// start pings dst from src every 20 ms with identifier id until the peer
// exits, counting the echo replies from dst that carry id.
func (p pingers) start(name, src, dst string, id int) error {
	network, proto, request, reply := "ip4:icmp", 1, icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	if strings.Contains(dst, ":") {
		network, proto, request, reply = "ip6:ipv6-icmp", 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	// A raw socket bound to src sees every ICMP message to src; the
	// identifier separates the flows.
	conn, err := icmp.ListenPacket(network, src)
	if err != nil {
		return err
	}
	answered := &atomic.Int64{}
	p[name] = answered
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || m.Type != reply || from.String() != dst {
				continue
			}
			if echo, ok := m.Body.(*icmp.Echo); ok && echo.ID == id {
				answered.Add(1)
			}
		}
	}()
	go func() {
		peer := &net.IPAddr{IP: net.ParseIP(dst)}
		for seq := 0; ; seq++ {
			// The kernel computes the ICMPv6 checksum of raw sockets.
			msg, err := (&icmp.Message{Type: request, Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: []byte("containd")}}).Marshal(nil)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(msg, peer)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	return nil
}

func (p pingers) replies(name string) string {
	if answered := p[name]; answered != nil {
		return strconv.FormatInt(answered.Load(), 10)
	}
	return "no ping " + name
}

// udpProbe sends one datagram from src to dst, a closed port, and returns the
// read error, which is "connection refused" when the port-unreachable error
// arrives.
func udpProbe(src, dst, sport string) error {
	local, err := net.ResolveUDPAddr("udp", net.JoinHostPort(src, sport))
	if err != nil {
		return err
	}
	remote, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp", local, remote)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err := c.Write([]byte("x")); err != nil {
		return err
	}
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		return fmt.Errorf("closed port answered")
	}
	return err
}

// TestKernelConntrackKillICMP kills continuous pings through the routed lab
// (see TestKernelConntrackKill for the container to run it in). A killed ping
// gets no replies and leaves no entry for the interval, while another
// identifier to the same host keeps going under connection scope and stops
// under client-service scope, and another client keeps going under both. An
// ICMP error about a UDP flow whose ports equal the killed ping's identifier
// and type still arrives.
func TestKernelConntrackKillICMP(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	const selectedID, neighborID = 0x5a01, 0x5a02
	for _, tc := range []struct {
		name, scope string
		v6, nat     bool
	}{{"NAT exact", "connection", false, true}, {"NAT service", "client-service", false, true}, {"IPv6 exact", "connection", true, false}, {"IPv6 service", "client-service", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			var nat func(*routedLab) string
			if tc.nat {
				// The reply tuple of each flow to the VIP is the server's
				// answer to the router's SNAT address.
				nat = func(lab *routedLab) string {
					return fmt.Sprintf("add rule inet containd test_dnat ip daddr %s meta l4proto { icmp, udp } dnat ip to %s\n", lab.vip, lab.server) +
						fmt.Sprintf("add rule inet containd test_snat iifname ctclient ip daddr %s meta l4proto { icmp, udp } snat ip to %s\n", lab.server, lab.routerServer)
				}
			}
			lab := newRoutedLab(t, ctx, tc.v6, nat)
			proto, echo, echoReply := "icmp", 8, "0"
			if tc.v6 {
				proto, echo, echoReply = "icmpv6", 128, "129"
			}
			dest := lab.server
			if tc.nat {
				dest = lab.vip
			}
			p := startPeer(t, ctx, lab.clientNS, "client", lab.client)
			// A UDP flow whose ports are the selected ping's identifier and
			// type * 256 + code, the fields of the ICMP revocation key.
			probe := fmt.Sprintf("udpprobe %s %s %d", lab.client, net.JoinHostPort(dest, strconv.Itoa(echo<<8)), selectedID)
			if got := p.command(t, probe); !strings.Contains(got, "connection refused") {
				t.Fatalf("port unreachable baseline: %s", got)
			}
			flows := []struct {
				name, src string
				id        int
			}{{"selected", lab.client, selectedID}, {"neighbor", lab.client, neighborID}, {"otherclient", lab.otherClient, selectedID}}
			counts := func() map[string]int {
				out := map[string]int{}
				for _, f := range flows {
					n, err := strconv.Atoi(p.command(t, "replies "+f.name))
					if err != nil {
						t.Fatal(err)
					}
					out[f.name] = n
				}
				return out
			}
			// flowing reports which pings got replies during window.
			flowing := func(window time.Duration) map[string]bool {
				before := counts()
				time.Sleep(window)
				out := map[string]bool{}
				for name, n := range counts() {
					out[name] = n > before[name]
				}
				return out
			}
			for _, f := range flows {
				if got := p.command(t, fmt.Sprintf("ping %s %s %s %d", f.name, f.src, dest, f.id)); got != "ok" {
					t.Fatal(got)
				}
			}
			if got := flowing(time.Second); !got["selected"] || !got["neighbor"] || !got["otherclient"] {
				t.Fatalf("pings not answered before kill: %v", got)
			}
			find := func(src string, id int) *conntrack.Entry {
				t.Helper()
				entries, err := conntrack.List(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if e.Proto == proto && e.Src == src && e.Dst == dest && e.ICMPID == strconv.Itoa(id) {
						return &e
					}
				}
				return nil
			}
			e := find(lab.client, selectedID)
			if e == nil || e.ICMPType != strconv.Itoa(echo) || e.ICMPCode != "0" || e.ReplyICMPType != echoReply || e.ReplyICMPCode != "0" || e.ReplyICMPID == "" {
				t.Fatalf("ping entry %+v", e)
			}
			if tc.nat && (e.ReplySrc != lab.server || e.ReplyDst != lab.routerServer) {
				t.Fatalf("missing NAT tuple %+v", e)
			}

			result, err := conntrack.Kill(ctx, conntrack.KillRequest{DeleteRequest: conntrack.DeleteRequest{Proto: proto, Src: lab.client, Dst: dest, ICMPID: selectedID, ICMPType: echo}, Scope: tc.scope, DurationSecs: 2}, enforce.NewNftUpdater("containd").RevokeConnections)
			killed := time.Now()
			matched := 1
			if tc.scope == "client-service" {
				matched = 2
			}
			if err != nil || !result.ConntrackDeleted || !result.RevocationInstalled || result.Matched != matched || result.Closure != "matching packets dropped" {
				t.Fatalf("kill %+v: %v", result, err)
			}
			// Replies in flight at the kill land before the window starts.
			time.Sleep(200 * time.Millisecond)
			got := flowing(600 * time.Millisecond)
			if got["selected"] || got["neighbor"] != (tc.scope == "connection") || !got["otherclient"] {
				t.Fatalf("%s revocation: pings answered %v", tc.scope, got)
			}
			if e := find(lab.client, selectedID); e != nil {
				t.Fatalf("killed ping has an entry again: %+v", e)
			}
			if e := find(lab.client, neighborID); (e == nil) != (tc.scope == "client-service") {
				t.Fatalf("%s revocation: neighbor entry %+v", tc.scope, e)
			}
			if got := p.command(t, probe); !strings.Contains(got, "connection refused") {
				t.Fatalf("ICMP error about a UDP flow was revoked: %s", got)
			}
			time.Sleep(time.Until(killed.Add(2300 * time.Millisecond)))
			if got := flowing(time.Second); !got["selected"] || !got["neighbor"] || !got["otherclient"] {
				t.Fatalf("revocation did not expire: %v", got)
			}
		})
	}
}
