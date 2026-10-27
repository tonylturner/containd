// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// The helper is re-executed in an endpoint's network namespace. Commands and
// replies are piped, avoiding listener readiness sleeps and machine ports.
func TestKernelConntrackPeer(t *testing.T) {
	role := os.Getenv("CONTAIND_CONNTRACK_PEER")
	if role == "" {
		t.Skip("subprocess helper")
	}
	if role == "server" {
		runServerPeer(t)
		return
	}

	conns := map[string]net.Conn{}
	pings := pingers{}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		var err error
		reply := "ok"
		switch fields[0] {
		case "ping":
			id, _ := strconv.Atoi(fields[4])
			err = pings.start(fields[1], fields[2], fields[3], id)
		case "replies":
			reply = pings.replies(fields[1])
		case "stray":
			id, _ := strconv.Atoi(fields[3])
			err = sendStrays(fields[1], fields[2], id)
		case "udpprobe":
			err = udpProbe(fields[1], fields[2], fields[3])
		case "dial":
			port, _ := strconv.Atoi(fields[3])
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(os.Getenv("CONTAIND_CONNTRACK_ADDRESS")), Port: port}, Control: func(_, _ string, c syscall.RawConn) error {
				var sockErr error
				err := c.Control(func(fd uintptr) {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				})
				if err != nil {
					return err
				}
				return sockErr
			}}
			if len(fields) > 4 {
				d.LocalAddr.(*net.TCPAddr).IP = net.ParseIP(fields[4])
			}
			var c net.Conn
			c, err = d.Dial("tcp", fields[2])
			if err == nil {
				conns[fields[1]] = c
			}
		case "echo":
			c := conns[fields[1]]
			if c == nil {
				err = fmt.Errorf("no connection")
				break
			}
			if err = c.SetDeadline(time.Now().Add(time.Second)); err == nil {
				_, err = c.Write([]byte("x"))
				if err == nil {
					b := make([]byte, 1)
					_, err = io.ReadFull(c, b)
					if err == nil && b[0] != 'x' {
						err = fmt.Errorf("bad echo")
					}
				}
			}
		case "close":
			if c := conns[fields[1]]; c != nil {
				if tcp, ok := c.(*net.TCPConn); ok {
					if err = tcp.SetLinger(0); err != nil {
						break
					}
				}
				err = c.Close()
				delete(conns, fields[1])
			}
		}
		if err != nil {
			reply = err.Error()
		}
		if err := json.NewEncoder(os.Stdout).Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type serverConnection struct {
	conn net.Conn
	done chan struct{}
	err  error
}

func runServerPeer(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", os.Getenv("CONTAIND_CONNTRACK_ADDRESS"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	conns := map[string]*serverConnection{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			state := &serverConnection{conn: c, done: make(chan struct{})}
			port := strconv.Itoa(c.RemoteAddr().(*net.TCPAddr).Port)
			mu.Lock()
			conns[port] = state
			mu.Unlock()
			go func() { _, state.err = io.Copy(c, c); _ = c.Close(); close(state.done) }()
		}
	}()
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		mu.Lock()
		state := conns[fields[1]]
		mu.Unlock()
		reply := "no connection"
		if state != nil {
			if fields[0] == "probe" {
				if err := state.conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := state.conn.Write([]byte("p")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-state.done:
				reply = "closed"
				if state.err != nil {
					reply = state.err.Error()
				}
			case <-time.After(3 * time.Second):
				reply = "server did not close"
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

type peer struct {
	input  io.WriteCloser
	output *bufio.Scanner
}

func startPeer(t *testing.T, ctx context.Context, ns, role, addr string) *peer {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, binary, "-test.run=^TestKernelConntrackPeer$")
	cmd.Env = append(os.Environ(), "CONTAIND_CONNTRACK_PEER="+role, "CONTAIND_CONNTRACK_ADDRESS="+addr)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stderr.Len() != 0 {
			t.Errorf("peer stderr: %s", stderr.String())
		}
	})
	p := &peer{input: input, output: bufio.NewScanner(output)}
	if role == "server" && (!p.output.Scan() || p.output.Text() != "ready") {
		t.Fatal("server failed to become ready")
	}
	return p
}
func (p *peer) command(t *testing.T, line string) string {
	t.Helper()
	if _, err := fmt.Fprintln(p.input, line); err != nil {
		t.Fatal(err)
	}
	if !p.output.Scan() {
		t.Fatalf("peer stopped: %v", p.output.Err())
	}
	var reply string
	if err := json.Unmarshal(p.output.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

// Run in one disposable container with NET_ADMIN, SYS_ADMIN and nft/ip
// installed. Namespace creation/setns requires SYS_ADMIN in addition to
// NET_ADMIN, and the test needs IPv4 and IPv6 forwarding, which Docker sets
// only with --sysctl:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/conntrack.test ./pkg/dp/conntrack
//	docker run --rm --privileged --sysctl net.ipv4.ip_forward=1 \
//	  --sysctl net.ipv6.conf.all.forwarding=1 -e CONTAIND_NETNS_KERNEL_TEST=1 \
//	  -v "$PWD/build:/w" alpine:3.21 sh -c \
//	  'apk add -q nftables iproute2 conntrack-tools && /w/conntrack.test -test.run Kernel -test.v'
func TestKernelConntrackKill(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	for _, tc := range []struct {
		name, scope string
		v6, nat     bool
	}{{"NAT exact", "connection", false, true}, {"NAT service", "client-service", false, true}, {"IPv6 exact", "connection", true, false}, {"IPv6 service", "client-service", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			var nat func(*routedLab) string
			if tc.nat {
				nat = func(lab *routedLab) string {
					return fmt.Sprintf("add rule inet containd test_dnat ip daddr %s tcp dport 25000 dnat ip to %s:25000\n", lab.vip, lab.server) +
						fmt.Sprintf("add rule inet containd test_snat iifname ctclient ip daddr %s meta l4proto tcp snat ip to %s:50000-50002\n", lab.server, lab.routerServer)
				}
			}
			lab := newRoutedLab(t, ctx, tc.v6, nat)
			client, server, routerServer, otherClient := lab.client, lab.server, lab.routerServer, lab.otherClient
			serverPeer := startPeer(t, ctx, lab.serverNS, "server", net.JoinHostPort(server, "25000"))
			p := startPeer(t, ctx, lab.clientNS, "client", client)
			dest := server
			if tc.nat {
				dest = lab.vip
			}
			address := net.JoinHostPort(dest, "25000")
			for _, key := range []struct {
				name string
				port int
			}{{"selected", 41001}, {"neighbor", 41002}} {
				if got := p.command(t, fmt.Sprintf("dial %s %s %d", key.name, address, key.port)); got != "ok" {
					t.Fatal(got)
				}
				if got := p.command(t, "echo "+key.name); got != "ok" {
					t.Fatal(got)
				}
			}
			// An unrelated service key must remain untouched even for broad revocations.
			startPeer(t, ctx, lab.serverNS, "server", net.JoinHostPort(server, "25001"))
			if got := p.command(t, "dial other "+net.JoinHostPort(server, "25001")+" 41003"); got != "ok" {
				t.Fatal(got)
			}
			if got := p.command(t, "echo other"); got != "ok" {
				t.Fatal(got)
			}
			if got := p.command(t, "dial otherclient "+address+" 41006 "+otherClient); got != "ok" {
				t.Fatal(got)
			}
			if got := p.command(t, "echo otherclient"); got != "ok" {
				t.Fatal(got)
			}
			entries, err := conntrack.List(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			selectedReplyPort := ""
			probePorts := []string{}
			for _, e := range entries {
				if e.Proto == "tcp" && e.Src == client && e.Dst == dest && e.Dport == "25000" && (tc.scope == "client-service" || e.Sport == "41001") {
					probePorts = append(probePorts, e.ReplyDport)
				}
				if e.Src == client && e.Dst == dest && e.Sport == "41001" && e.Dport == "25000" {
					found = true
					selectedReplyPort = e.ReplyDport
					if tc.nat && (e.ReplySrc != server || e.ReplyDst != routerServer) {
						t.Fatalf("missing NAT tuple %+v", e)
					}
				}
			}
			if !found {
				t.Fatalf("connection absent in dump: %+v", entries)
			}
			// A positive limit ends the dump early with exactly that many entries.
			if limited, err := conntrack.List(ctx, 1); err != nil || len(limited) != 1 || len(entries) < 2 {
				t.Fatalf("limited dump: %d of %d entries: %v", len(limited), len(entries), err)
			}
			result, err := conntrack.Kill(ctx, conntrack.KillRequest{DeleteRequest: conntrack.DeleteRequest{Proto: "tcp", Src: client, Dst: dest, Sport: 41001, Dport: 25000}, Scope: tc.scope, DurationSecs: 2}, enforce.NewNftUpdater("containd").RevokeConnections)
			if err != nil || !result.ConntrackDeleted || !result.RevocationInstalled {
				t.Fatalf("kill %+v: %v", result, err)
			}
			if got := p.command(t, "echo selected"); !strings.Contains(got, "connection reset") {
				t.Fatalf("killed connection did not receive a reset: %s", got)
			}
			for _, port := range probePorts {
				if got := serverPeer.command(t, "probe "+port); !strings.Contains(got, "connection reset") {
					t.Fatalf("server did not receive a reset on its next packet: %s", got)
				}
			}
			_ = p.command(t, "close selected")
			if got := p.command(t, "dial reconnect "+address+" 41001"); !strings.Contains(got, "connection refused") {
				t.Fatalf("same tuple reconnect was not rejected: %s", got)
			}
			if got := p.command(t, "echo other"); got != "ok" {
				t.Fatalf("neighbor service disrupted: %s", got)
			}
			if got := p.command(t, "echo otherclient"); got != "ok" {
				t.Fatalf("neighbor client disrupted: %s", got)
			}
			fresh := p.command(t, "dial fresh "+address+" 41004")
			neighbor := p.command(t, "echo neighbor")
			if tc.scope == "connection" {
				if fresh != "ok" || neighbor != "ok" {
					t.Fatalf("neighbor disrupted: fresh=%s existing=%s", fresh, neighbor)
				}
			} else {
				if !strings.Contains(fresh, "connection refused") || neighbor == "ok" {
					t.Fatalf("service revocation incomplete: fresh=%s existing=%s", fresh, neighbor)
				}
			}
			if tc.nat && tc.scope == "connection" {
				// All three SNAT slots were occupied before kill. The fresh
				// source port must reuse the deleted flow's translated port,
				// without inheriting its revocation.
				entries, err := conntrack.List(ctx, 0)
				if err != nil {
					t.Fatal(err)
				}
				reused := false
				for _, e := range entries {
					if e.Src == client && e.Dst == dest && e.Sport == "41004" && e.ReplyDport == selectedReplyPort {
						reused = true
					}
				}
				if !reused {
					t.Fatal("fresh connection did not reuse the revoked NAT port")
				}
				if got := p.command(t, "echo fresh"); got != "ok" {
					t.Fatalf("NAT port reuse inherited a revocation: %s", got)
				}
				_ = p.command(t, "close fresh")
				if got := serverPeer.command(t, "wait "+selectedReplyPort); !strings.Contains(got, "connection reset") {
					t.Fatalf("fresh fixture did not close before releasing its NAT slot: %s", got)
				}
				// Free the closed fixture's conntrack mapping, not the nft
				// revocation, so pool exhaustion cannot mask timeout expiry.
				if err := conntrack.Delete(ctx, conntrack.DeleteRequest{Proto: "tcp", Src: client, Dst: dest, Sport: 41004, Dport: 25000}); err != nil && !errors.Is(err, syscall.ENOENT) {
					t.Fatal(err)
				}
			}
			time.Sleep(2200 * time.Millisecond)
			if got := p.command(t, "dial expired "+address+" 41005"); got != "ok" {
				t.Fatalf("revocation did not expire: %s", got)
			}
			if got := p.command(t, "echo expired"); got != "ok" {
				t.Fatal(got)
			}
		})
	}
}
