// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func admissionKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opt-in disposable privileged Linux container")
	}
}

func admissionNFT(t *testing.T, script string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
}

func TestEngineKernelParitySweepAfterFlip(t *testing.T) {
	admissionKernel(t)
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	snap := rules.Snapshot{Default: rules.ActionAllow}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.gate.release(); err != nil {
			t.Error(err)
		}
	})
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var clients []*net.UDPConn
	for range 2 {
		c, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clients = append(clients, c)
	}
	oldP := e.CurrentRules().AdmissionParity
	nextP := oldP ^ markabi.ParityBit
	const keep = uint32(0xa5000000) | enforce.GateCtMark | 7<<enforce.GateZoneCtShift | markabi.OwnedForwardCtBit
	seeds := []uint32{keep | markabi.AdmittedBit | oldP, keep | markabi.AdmittedBit | nextP}
	var script strings.Builder
	script.WriteString("table inet admission_seed { chain out { type filter hook output priority -5; policy accept;\n")
	for i, c := range clients {
		fmt.Fprintf(&script, "udp sport %d udp dport %d ct mark set 0x%08x\n",
			c.LocalAddr().(*net.UDPAddr).Port, server.LocalAddr().(*net.UDPAddr).Port, seeds[i])
	}
	script.WriteString("}\n}\n")
	admissionNFT(t, script.String())
	t.Cleanup(func() { admissionNFT(t, "delete table inet admission_seed") })
	for _, c := range clients {
		if _, err := c.Write([]byte("seed")); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want []uint32) {
		t.Helper()
		entries, err := conntrack.List(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range clients {
			found := false
			for _, entry := range entries {
				if entry.Src == "127.0.0.1" && entry.Proto == "udp" &&
					entry.Sport == strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port) &&
					entry.Dport == strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port) {
					found = true
					if entry.Mark != strconv.FormatUint(uint64(want[i]), 10) {
						t.Fatalf("entry %d mark=%s want=0x%08x", i, entry.Mark, want[i])
					}
				}
			}
			if !found {
				t.Fatalf("entry %d missing", i)
			}
		}
	}
	check(seeds)
	snap.Default = rules.ActionDeny
	if err := e.ApplyRules(context.Background(), snap); err != nil || e.CurrentRules().AdmissionParity != nextP {
		t.Fatalf("flip: %v, parity=%x", err, e.CurrentRules().AdmissionParity)
	}
	check([]uint32{keep | oldP, seeds[1]})
	snap.Version = "effective-noop"
	if err := e.ApplyRules(context.Background(), snap); err != nil || e.CurrentRules().AdmissionParity != nextP {
		t.Fatalf("no-op: %v", err)
	}
	check([]uint32{keep | oldP, seeds[1]})
	snap.Default = rules.ActionAllow
	if err := e.ApplyRules(context.Background(), snap); err != nil || e.CurrentRules().AdmissionParity != oldP {
		t.Fatalf("second flip: %v", err)
	}
	check([]uint32{keep | oldP, keep | nextP})
}

type heldKernelCapture struct {
	*capture.Manager
	handler capture.Handler
}

func (c heldKernelCapture) Start(ctx context.Context, _ capture.Handler) error {
	return c.Manager.Start(ctx, c.handler)
}

func TestEngineKernelApplyRetiresHeldQueueAndKeepsBinding(t *testing.T) {
	ctx := newFirstCommandLab(t)
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true}, NFQueueGroup: fcQueue})
	if err != nil {
		t.Fatal(err)
	}
	packets := make(chan capture.Packet, 8)
	e.capture = heldKernelCapture{e.capture.(*capture.Manager), func(pkt capture.Packet) capture.Decision {
		packets <- pkt
		if string(pkt.Payload) == "held" {
			return capture.Decision{Action: capture.Hold}
		}
		return capture.Decision{Action: capture.Repeat, Mark: markabi.Continue(pkt.Mark, false)}
	}}
	if err := e.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fresh, err := New(Config{})
		if err == nil {
			err = e.Reconfigure(fresh)
		}
		if err != nil {
			t.Error(err)
		}
	})
	snap := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
		ID: "queued", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "44818"}},
		ICS: rules.ICSPredicate{Protocol: "cip", Mode: "enforce"},
	}}}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	var server *net.UDPConn
	if err := inNetns(fcServerNS, func() (err error) {
		server, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(fcServerIP), Port: 44818})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var client *net.UDPConn
	if err := inNetns(fcClientNS, func() (err error) {
		client, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(fcServerIP), Port: 44818})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	next := func() capture.Packet {
		t.Helper()
		select {
		case pkt := <-packets:
			return pkt
		case <-time.After(3 * time.Second):
			t.Fatal("queue did not deliver")
			return capture.Packet{}
		}
	}
	if _, err := client.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	held := next()
	if held.Queue == nil || held.Queue.Conntrack == nil || held.Queue.IngressDevice != "fc0" || held.Queue.EgressDevice != "fc1" {
		t.Fatalf("missing receive-time context: %+v", held.Queue)
	}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if err := e.capture.Settler().Settle(capture.Resolution{Token: held.Token, Verdict: capture.VerdictRepeat})[0]; !errors.Is(err, capture.ErrUnknownToken) {
		t.Fatalf("flushed token was not retired: %v", err)
	}
	if _, err := client.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	fresh := next()
	if fresh.Token.Generation() != held.Token.Generation() {
		t.Fatal("apply rebound the queue")
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil || string(buf[:n]) != "fresh" {
		t.Fatalf("post-apply delivery=%q err=%v", buf[:n], err)
	}
	if !e.IEC104Enforcement().Healthy {
		t.Fatalf("apply poisoned queue health: %+v", e.IEC104Enforcement())
	}
}

func TestEngineKernelLocalSecondaryAddressUpdate(t *testing.T) {
	ctx := newFirstCommandLab(t)
	fcRun(ctx, t, "ip", "addr", "add", "198.18.50.3/24", "dev", "fc0")
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	snap := rules.Snapshot{ZoneIfaces: map[string][]string{"client": {"fc0"}}}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.gate.release(); err != nil {
			t.Error(err)
		}
	})
	secondary := netip.MustParseAddr("198.18.50.3")
	if !slices.Contains(e.CurrentRules().LocalIPv4ByDevice["fc0"], secondary) {
		t.Fatal("discovery omitted secondary address")
	}
	fcRun(ctx, t, "ip", "addr", "del", "198.18.50.3/24", "dev", "fc0")
	if err := e.RefreshLocalAddresses(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(e.CurrentRules().LocalIPv4ByDevice["fc0"], secondary) || e.CurrentRules().AdmissionParity != 0 {
		t.Fatal("address removal did not update resolver independently of parity")
	}
	actual := fcRun(ctx, t, "nft", "list", "table", "inet", e.compiler.PolicyTable())
	if strings.Contains(actual, secondary.String()) {
		t.Fatalf("live address set retained removed secondary: %s", actual)
	}
}
