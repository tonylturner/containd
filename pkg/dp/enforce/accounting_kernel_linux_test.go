// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestAccountingKernel proves that the accounting hook sees delivered routed
// packets, not steering hits or connection openers. Each probe sends three UDP
// datagrams on one connection and waits for three replies (no retransmissions).
func TestAccountingKernel(t *testing.T) {
	for _, name := range []string{"IPv4", "IPv6", "NFQueueAccept", "NFQueueRepeat", "DNAT", "SNAT", "PolicyApply", "Rebuild"} {
		t.Run(name, func(t *testing.T) { testAccountingKernel(t, name) })
	}
	t.Run("BridgeNetfilter", testAccountingBridgeNetfilter)
}

func testAccountingKernel(t *testing.T, name string) {
	lab := newNetnsLab(t, "act", 180, 90*time.Second)

	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.190.0/24", "via", "198.18.180.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.180.0/24", "via", "198.18.190.1")
	client, server, seen := "198.18.180.2", "198.18.190.2", "198.18.180.2"
	family := "AF_INET"
	if name == "IPv6" {
		client, server, seen = "fd18:180::2", "fd18:190::2", "fd18:180::2"
		family = "AF_INET6"
		for i, ns := range []string{lab.client, lab.target} {
			subnet := 180 + i*10
			// Forwarded-packet neighbor discovery needs a preferred link-local
			// source. Veth auto-generated link-local addresses are still in DAD
			// here; make readiness deterministic instead of racing DAD/ND retries.
			lab.run(t, "ip", "-6", "addr", "flush", "dev", fmt.Sprintf("act%d", i), "scope", "link")
			lab.run(t, "ip", "-6", "addr", "add", "fe80::1/64", "dev", fmt.Sprintf("act%d", i), "nodad")
			lab.run(t, "ip", "-6", "-n", ns, "addr", "flush", "dev", fmt.Sprintf("actp%d", i), "scope", "link")
			lab.run(t, "ip", "-6", "-n", ns, "addr", "add", "fe80::2/64", "dev", fmt.Sprintf("actp%d", i), "nodad")
			lab.run(t, "ip", "-6", "addr", "add", fmt.Sprintf("fd18:%d::1/64", subnet), "dev", fmt.Sprintf("act%d", i), "nodad")
			lab.run(t, "ip", "-6", "-n", ns, "addr", "add", fmt.Sprintf("fd18:%d::2/64", subnet), "dev", fmt.Sprintf("actp%d", i), "nodad")
			lab.run(t, "ip", "-6", "-n", ns, "route", "add", fmt.Sprintf("fd18:%d::/64", 370-subnet), "via", fmt.Sprintf("fd18:%d::1", subnet))
		}
	}
	// Router-local neighbor discovery must pass too; the explicit forwarding
	// rule below supplies the policy counter used to prove the established path.
	snap := &rules.Snapshot{Default: rules.ActionAllow, ZoneIfaces: map[string][]string{"client": {"act0"}, "server": {"act1"}}, Firewall: []rules.Entry{{ID: "allow", SourceZones: []string{"client"}, DestZones: []string{"server"}, Action: rules.ActionAllow}}}
	destination, port := server, 18010
	if name == "DNAT" {
		destination, port, seen = "198.18.180.1", 18011, "198.18.190.1"
		snap.NAT = rules.NATConfig{Enabled: true}
		snap.ForwardMatches = map[string]rules.ForwardMatch{"probe": {Enabled: true, IngressDevices: []string{"act0"}, Protocol: "udp", ListenPort: 18011, Backend: netip.MustParseAddrPort("198.18.190.2:18010")}}
		snap.LocalIPv4ByDevice = map[string][]netip.Addr{"act0": {netip.MustParseAddr("198.18.180.1")}}
	}
	if name == "SNAT" {
		snap.NAT = rules.NATConfig{Enabled: true, EgressZone: "server", SourceZones: []string{"client"}}
		seen = "198.18.190.1"
	}
	c := NewCompiler()
	lab.apply(t, c, snap)
	a := NewAccounting(c.DynamicTable(), map[string]string{"act0": "client", "act1": "server"})
	install := func() {
		t.Helper()
		script, err := a.Script()
		if err != nil {
			t.Fatal(err)
		}
		lab.nft(t, script)
	}
	install()
	t.Cleanup(func() { lab.nft(t, DeleteTable(a.Table)) })
	var queued *atomic.Uint32
	if name == "NFQueueAccept" || name == "NFQueueRepeat" {
		queued = accountingQueue(t, lab.ctx, 93, name == "NFQueueRepeat")
		lab.nft(t, `table inet accounting_queue_test {
 chain forward { type filter hook forward priority 50; policy accept;
  iifname "act0" udp dport 18010 meta mark & 0x1 == 0 queue to 93
 }
}`)
		t.Cleanup(func() { lab.nft(t, DeleteTable("accounting_queue_test")) })
	}
	accountingUDPServer(t, lab, server, family)

	probe := func() {
		t.Helper()
		lab.run(t, "ip", "netns", "exec", lab.client, "python3", "-c", fmt.Sprintf(`import socket
s=socket.socket(socket.%s,socket.SOCK_DGRAM); s.settimeout(2); s.bind((%q,0)); s.connect((%q,%d))
for i in range(3):
 s.send(b"ping"); assert s.recv(128)==%q.encode()+b":ping"
`, family, client, destination, port, seen))
	}
	counters := func(want uint64) {
		t.Helper()
		values, err := NewNftApplier().ReadAccountingCounters(lab.ctx, a.Table)
		if err != nil {
			t.Fatal(err)
		}
		if len(values) != 2 {
			t.Fatal(values)
		}
		for _, p := range a.Pairs {
			v := values[p.Counter]
			if v.Packets != want || v.Bytes == 0 {
				t.Fatalf("%s -> %s: %+v, want %d packets", p.From, p.To, v, want)
			}
		}
	}
	probe()
	counters(3)
	if queued != nil && queued.Load() != 3 {
		t.Fatalf("queued %d times, want 3", queued.Load())
	}
	policyCounts, err := NewNftApplier().ReadCounters(lab.ctx, c.PolicyTable())
	if err != nil {
		t.Fatal(err)
	}
	if got := policyCounts[ruleCounterName("allow")].Packets; got >= 3 {
		t.Fatalf("no established fast path: policy hits %d, forwarded 3", got)
	}
	if name == "PolicyApply" {
		epoch := a.Epoch
		lab.apply(t, c, snap)
		counters(3)
		probe()
		counters(6)
		if a.Epoch != epoch {
			t.Fatal("policy apply changed epoch")
		}
	}
	if name == "Rebuild" {
		previous := a.Epoch
		a = NewAccounting(c.DynamicTable(), map[string]string{"act0": "client", "act1": "server"})
		install()
		if a.Epoch == previous {
			t.Fatal("rebuild reused epoch")
		}
		values, err := NewNftApplier().ReadAccountingCounters(lab.ctx, a.Table)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			if v.Packets != 0 || v.Bytes != 0 {
				t.Fatal("rebuild kept old counters")
			}
		}
		probe()
		counters(3)
	}
}

func accountingUDPServer(t *testing.T, lab *netnsLab, addr, family string) {
	t.Helper()
	cmd := exec.CommandContext(lab.ctx, "ip", "netns", "exec", lab.target, "python3", "-u", "-c", fmt.Sprintf(`import socket
s=socket.socket(socket.%s,socket.SOCK_DGRAM); s.bind((%q,18010)); print("ready",flush=True)
while True:
 d,a=s.recvfrom(128); s.sendto(a[0].encode()+b":"+d,a)
`, family, addr))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if !bufio.NewScanner(out).Scan() {
		t.Fatal("UDP server did not start")
	}
}

func accountingQueue(t *testing.T, ctx context.Context, queue uint16, repeat bool) *atomic.Uint32 {
	t.Helper()
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: queue, MaxPacketLen: 128, MaxQueueLen: 256, Copymode: nfqueue.NfQnlCopyPacket})
	if err != nil {
		t.Fatal(err)
	}
	run, cancel := context.WithCancel(ctx)
	count := &atomic.Uint32{}
	errs := make(chan error, 256)
	t.Cleanup(func() {
		cancel()
		_ = nf.Close()
		for {
			select {
			case err := <-errs:
				t.Error(err)
			default:
				return
			}
		}
	})
	if err := nf.RegisterWithErrorFunc(run, func(a nfqueue.Attribute) int {
		if a.PacketID != nil {
			verdict := nfqueue.NfAccept
			if repeat {
				verdict = nfqueue.NfRepeat
			}
			mark := uint32(1)
			if a.Mark != nil {
				mark |= *a.Mark
			}
			count.Add(1)
			if err := nf.SetVerdictWithOption(*a.PacketID, verdict, nfqueue.WithMark(mark)); err != nil {
				errs <- err
			}
		}
		return 0
	}, func(err error) int {
		if run.Err() != nil {
			return 1
		}
		errs <- err
		return 0
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
