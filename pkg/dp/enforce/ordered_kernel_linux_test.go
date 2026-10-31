// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func orderedLab(t *testing.T) *netnsLab {
	t.Helper()
	lab := newNetnsLab(t, "ord", 60, 90*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.70.0/24", "via", "198.18.60.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.60.0/24", "via", "198.18.70.1")
	return lab
}

func TestOrderedKernelFirstMatch(t *testing.T) {
	lab := orderedLab(t)
	lab.serveTarget(t, "198.18.70.2", 18001)
	for _, deny := range []rules.Action{rules.ActionDeny, rules.ActionReset} {
		for _, allowFirst := range []bool{false, true} {
			t.Run(fmt.Sprint(deny, allowFirst), func(t *testing.T) {
				entries := []rules.Entry{{ID: "z-deny", Action: deny}, {ID: "a-allow", Action: rules.ActionAllow}}
				if allowFirst {
					entries[0], entries[1] = entries[1], entries[0]
				}
				snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: entries}
				c := NewCompiler()
				lab.apply(t, c, snap)
				err := lab.probe("198.18.70.2", 18001, "198.18.60.2")
				if (err == nil) != allowFirst {
					t.Fatalf("allowFirst=%v: %v", allowFirst, err)
				}
				counts := lab.counts(t, c, snap)
				if counts[entries[0].ID].Packets == 0 || counts[entries[1].ID].Packets != 0 {
					t.Fatalf("wrong winner: %v", counts)
				}
			})
		}
	}
}

func TestOrderedKernelInspectionOrder(t *testing.T) {
	lab := orderedLab(t)
	lab.serveTarget(t, "198.18.70.2", 18001)
	queued := repeatPolicyQueue(t, lab.ctx, 94, false)
	for _, plainAction := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
		for _, inspectFirst := range []bool{false, true} {
			t.Run(fmt.Sprint(plainAction, inspectFirst), func(t *testing.T) {
				snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
					{ID: "plain", Action: plainAction, Protocols: []rules.Protocol{{Name: "tcp", Port: "18001"}}},
					{ID: "inspected", Action: rules.ActionDeny, Protocols: []rules.Protocol{{Name: "tcp", Port: "18001"}},
						ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", FunctionCode: []uint8{6}}},
				}}
				if inspectFirst {
					snap.Firewall[0], snap.Firewall[1] = snap.Firewall[1], snap.Firewall[0]
				}
				c := NewCompiler()
				c.QueueID = 94
				lab.apply(t, c, snap)
				before := queued.Load()
				err := lab.probe("198.18.70.2", 18001, "198.18.60.2")
				if want := inspectFirst || plainAction == rules.ActionAllow; (err == nil) != want {
					t.Fatalf("inspectionFirst=%v plain=%s: %v", inspectFirst, plainAction, err)
				}
				if queued.Load() == before {
					t.Fatal("S2 winner bypassed the independent inspection union")
				}
				counts := lab.counts(t, c, snap)
				if counts["inspected"].Packets == 0 || (counts["plain"].Packets == 0) != inspectFirst {
					t.Fatalf("wrong steering/admission attribution: %v", counts)
				}
			})
		}
	}
}

// This is a kernel continuation consumer, not an engine: every queued
// packet gets one synthetic marked repeat. Report verdict errors on the
// test goroutine, including errors encountered during queue shutdown.
func repeatPolicyQueue(t *testing.T, ctx context.Context, queue uint16, nonAdmit bool) *atomic.Uint32 {
	t.Helper()
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: queue, MaxPacketLen: 128, MaxQueueLen: 256, Copymode: nfqueue.NfQnlCopyPacket})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	count := &atomic.Uint32{}
	errs := make(chan error, 256)
	t.Cleanup(func() {
		cancel()
		_ = nf.Close()
		for {
			select {
			case err := <-errs:
				t.Errorf("repeat queue: %v", err)
			default:
				return
			}
		}
	})
	if err := nf.RegisterWithErrorFunc(runCtx, func(a nfqueue.Attribute) int {
		if a.PacketID != nil {
			mark := uint32(0)
			if a.Mark != nil {
				mark = *a.Mark
			}
			count.Add(1)
			if err := nf.SetVerdictWithOption(*a.PacketID, nfqueue.NfRepeat, nfqueue.WithMark(markabi.Continue(mark, nonAdmit))); err != nil {
				errs <- err
			}
		}
		return 0
	}, func(err error) int {
		if runCtx.Err() != nil {
			return 1
		}
		errs <- err
		return 0
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOrderedKernelNonAdmit(t *testing.T) {
	lab := orderedLab(t)
	repeatPolicyQueue(t, lab.ctx, 92, true)
	lab.runTarget(t, `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("198.18.70.2",18002)); print("ready",flush=True)
while True:
 d,a=s.recvfrom(64); s.sendto(d,a)
`)
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
		t.Run(string(action), func(t *testing.T) {
			snap := &rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{
				{ID: "terminal", Action: action, Protocols: []rules.Protocol{{Name: "udp", Port: "18002"}}},
				{ID: "observe", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "18002"}}, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
			}}
			c := NewCompiler()
			c.QueueID = 92
			lab.apply(t, c, snap)
			out := lab.runClient(t, `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.3); s.connect(("198.18.70.2",18002)); s.send(b"x")
try:
 s.recv(64); print("delivered")
except socket.timeout: print("drop")
except OSError: print("reject")
`)
			want := "drop"
			if action == rules.ActionReset {
				want = "reject"
			}
			if out != want {
				t.Fatalf("%s: got %s, want %s", action, out, want)
			}
			counts := lab.counts(t, c, snap)
			wantCount := uint64(1)
			if action == rules.ActionAllow {
				wantCount = 0 // a continuation-drop is not delivered ALLOW
			}
			if counts["terminal"].Packets != wantCount || counts["observe"].Packets != 1 {
				t.Fatalf("wrong continuation accounting: %v", counts)
			}
		})
	}
}

func TestOrderedKernelMetersOnce(t *testing.T) {
	lab := orderedLab(t)
	queued := repeatPolicyQueue(t, lab.ctx, 93, false)
	lab.runTarget(t, `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("198.18.70.2",18003)); print("ready",flush=True)
while True:
 d,a=s.recvfrom(64); s.sendto(d,a)
`)
	snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
		{ID: "police", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 100}},
		{ID: "tag", Action: rules.ActionTag},
		{ID: "allow", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "18003"}}},
		{ID: "observe", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "18003"}}, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
	}}
	c := NewCompiler()
	c.QueueID = 93
	lab.apply(t, c, snap)
	lab.runClient(t, `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect(("198.18.70.2",18003)); s.send(b"x"); assert s.recv(64)==b"x"
`)
	counts := lab.counts(t, c, snap)
	if queued.Load() != 1 || counts["police"].Packets != 2 || counts["tag"].Packets != 1 ||
		counts["allow"].Packets != 1 || counts["observe"].Packets != 1 {
		t.Fatalf("repeated traversal charged twice: queued=%d counts=%v", queued.Load(), counts)
	}
}

func TestOrderedKernelParityRematch(t *testing.T) {
	lab := orderedLab(t)
	_, server := startAddressSetPeer(t, lab, lab.target, `import socket
s=socket.socket(); s.bind(("198.18.70.2",18004)); s.listen(); print("ready")
c,_=s.accept()
while True:
 b=c.recv(64)
 if not b: break
 c.sendall(b)
`)
	addressSetPeerLine(t, server, "ready")
	c := NewCompiler()
	snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "allow", Action: rules.ActionAllow}}}
	lab.apply(t, c, snap)
	input, client := startAddressSetPeer(t, lab, lab.client, `import socket,sys
s=socket.socket(); s.settimeout(2); s.connect(("198.18.70.2",18004))
s.sendall(b"A"); assert s.recv(1)==b"A"; print("initial")
for name in ["fast","noop","stale","fast-again"]:
 assert sys.stdin.readline().strip()==name
 s.sendall(b"B"); assert s.recv(1)==b"B"; print(name)
assert sys.stdin.readline().strip()=="deny"
s.sendall(b"C"); s.settimeout(.3)
try:
 s.recv(1); print("delivered")
except socket.timeout: print("denied")
sys.stdin.readline()
`)
	addressSetPeerLine(t, client, "initial")
	if got := lab.counts(t, c, snap)["allow"].Packets; got != 1 {
		t.Fatalf("initial ALLOW count %d", got)
	}
	send := func(name string) {
		t.Helper()
		if _, err := fmt.Fprintln(input, name); err != nil {
			t.Fatal(err)
		}
		addressSetPeerLine(t, client, name)
	}
	send("fast")
	if got := lab.counts(t, c, snap)["allow"].Packets; got != 1 {
		t.Fatalf("matching parity rematched: %d", got)
	}
	// No-op reinstall keeps parity, and therefore leaves the existing
	// socket admitted even though the named counters restart.
	lab.apply(t, c, snap)
	send("noop")
	if got := lab.counts(t, c, snap)["allow"].Packets; got != 0 {
		t.Fatalf("same-parity reinstall rematched: %d", got)
	}
	snap.AdmissionParity = markabi.ParityBit
	lab.apply(t, c, snap)
	send("stale")
	if got := lab.counts(t, c, snap)["allow"].Packets; got != 1 {
		t.Fatalf("stale parity did not rematch once: %d", got)
	}
	send("fast-again")
	if got := lab.counts(t, c, snap)["allow"].Packets; got != 1 {
		t.Fatalf("new parity did not fast-path: %d", got)
	}
	snap.AdmissionParity = 0
	snap.Firewall = []rules.Entry{{ID: "deny", Action: rules.ActionDeny}}
	lab.apply(t, c, snap)
	if _, err := fmt.Fprintln(input, "deny"); err != nil {
		t.Fatal(err)
	}
	addressSetPeerLine(t, client, "denied")
	if got := lab.counts(t, c, snap)["deny"].Packets; got == 0 {
		t.Fatal("stale admission bypassed DENY")
	}
}

func TestOrderedKernelOwnedForwardAddressRemoval(t *testing.T) {
	lab := orderedLab(t)
	snap := &rules.Snapshot{
		Default:           rules.ActionDeny,
		ForwardMatches:    map[string]rules.ForwardMatch{"f": {Enabled: true, IngressDevices: []string{"ord0"}, Protocol: "tcp", ListenPort: 18005, Backend: netip.MustParseAddrPort("198.18.70.2:18006")}},
		LocalIPv4ByDevice: map[string][]netip.Addr{"ord0": {netip.MustParseAddr("198.18.60.1")}},
		Firewall:          []rules.Entry{{ID: "via", Action: rules.ActionAllow, ViaForwards: []string{"f"}}},
	}
	c := NewCompiler()
	lab.apply(t, c, snap)
	_, server := startAddressSetPeer(t, lab, lab.target, `import socket
s=socket.socket(); s.bind(("198.18.70.2",18006)); s.listen(); print("ready")
c,_=s.accept()
while True:
 b=c.recv(64)
 if not b: break
 c.sendall(b)
`)
	addressSetPeerLine(t, server, "ready")
	if err := lab.probe("198.18.70.2", 18006, "198.18.60.2"); err == nil {
		t.Fatal("direct backend access inherited via permission")
	}
	input, client := startAddressSetPeer(t, lab, lab.client, `import socket,sys
s=socket.socket(); s.settimeout(2); s.connect(("198.18.60.1",18005))
s.sendall(b"A"); assert s.recv(1)==b"A"; print("initial")
assert sys.stdin.readline().strip()=="remove"
s.sendall(b"B"); s.settimeout(.3)
try:
 s.recv(1); print("delivered")
except socket.timeout: print("blocked")
assert sys.stdin.readline().strip()=="restore"
s.settimeout(3); assert s.recv(1)==b"B"
s.sendall(b"C"); assert s.recv(1)==b"C"; print("restored")
sys.stdin.readline()
`)
	addressSetPeerLine(t, client, "initial")
	update, err := c.LocalAddressUpdate("ord0", nil)
	if err != nil {
		t.Fatal(err)
	}
	lab.nft(t, update)
	if _, err := fmt.Fprintln(input, "remove"); err != nil {
		t.Fatal(err)
	}
	addressSetPeerLine(t, client, "blocked")
	update, err = c.LocalAddressUpdate("ord0", snap.LocalIPv4ByDevice["ord0"])
	if err != nil {
		t.Fatal(err)
	}
	lab.nft(t, update)
	if _, err := fmt.Fprintln(input, "restore"); err != nil {
		t.Fatal(err)
	}
	addressSetPeerLine(t, client, "restored")
	if got := lab.counts(t, c, snap)["via"].Packets; got != 1 {
		t.Fatalf("owned per-packet rematches inflated ALLOW count: %d", got)
	}
}

func TestOrderedKernelManagementDenyAll(t *testing.T) {
	lab := orderedLab(t)
	lab.serveLocal(t, "198.18.60.1", 18080)
	c := gateCompiler()
	c.ManagementReservation = &mgmtpath.Reservation{Device: "ord0", Local: netip.MustParsePrefix("198.18.60.1/24"),
		Sources: []netip.Addr{netip.MustParseAddr("198.18.60.2")}, Port: 18080}
	snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "deny-all", Action: rules.ActionDeny}},
		Gate: rules.GateSelection{Enabled: true,
			Zones:   []rules.GateZone{{Name: "lan", Index: 1, Devices: []string{"ord1"}}},
			Include: []rules.GateEntry{{DestZones: []string{"lan"}, Ports: []rules.GatePortRange{{Lo: 18080, Hi: 18080}}}},
		}}
	lab.apply(t, c, snap)
	if err := lab.probe("198.18.60.1", 18080, "198.18.60.2"); err != nil {
		t.Fatalf("reserved management depended on S2: %v", err)
	}
	if got := lab.counts(t, c, snap)["deny-all"].Packets; got != 0 {
		t.Fatalf("management entered ordinary policy: %d", got)
	}
}
