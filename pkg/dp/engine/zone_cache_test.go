// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// fakeInterfaces is a namespace whose interface networks a test changes;
// it counts the address reads.
type fakeInterfaces struct {
	mu    sync.Mutex
	nets  map[string]string
	reads int
}

func (f *fakeInterfaces) addrs(name string) ([]net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	cidr, ok := f.nets[name]
	if !ok {
		return nil, fmt.Errorf("no interface %q", name)
	}
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return []net.Addr{&net.IPNet{IP: ip, Mask: network.Mask}}, nil
}

func (f *fakeInterfaces) set(name, cidr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nets[name] = cidr
}

func (f *fakeInterfaces) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// TestZoneCacheFollowsInterfaceChanges checks that the zone index is read
// once while a watcher is subscribed and rebuilt after each change it
// reports, for a new snapshot, and on every lookup while nothing watches.
func TestZoneCacheFollowsInterfaceChanges(t *testing.T) {
	ifaces := &fakeInterfaces{nets: map[string]string{"plc0": "10.1.0.1/24"}}
	c := &zoneCache{addrsFor: ifaces.addrs}
	snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"plant": {"plc0"}}}
	zoneOf := func(snap *rules.Snapshot, ip string) string {
		src, _ := c.resolve(snap, net.ParseIP(ip), nil)
		return src
	}
	expect := func(step string, snap *rules.Snapshot, ip, zone string, reads int) {
		t.Helper()
		if got := zoneOf(snap, ip); got != zone {
			t.Fatalf("%s: zone of %s = %q, want %q", step, ip, got, zone)
		}
		if got := ifaces.readCount(); got != reads {
			t.Fatalf("%s: %d interface reads, want %d", step, got, reads)
		}
	}

	expect("unwatched", snap, "10.1.0.5", "plant", 1)
	expect("unwatched again", snap, "10.1.0.5", "plant", 2)
	c.subscribed()
	expect("subscribed", snap, "10.1.0.5", "plant", 3)
	expect("cached", snap, "10.1.0.5", "plant", 3)
	ifaces.set("plc0", "10.2.0.1/24")
	expect("change not yet received", snap, "10.1.0.5", "plant", 3)
	c.changed()
	expect("after the change", snap, "10.1.0.5", "", 4)
	expect("cached after the change", snap, "10.2.0.5", "plant", 4)
	next := &rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"plc0"}}}
	expect("new snapshot", next, "10.2.0.5", "control", 5)
	expect("new snapshot cached", next, "10.2.0.5", "control", 5)
	c.unsubscribed()
	expect("unsubscribed", next, "10.2.0.5", "control", 6)
	expect("unsubscribed again", next, "10.2.0.5", "control", 7)
	c.subscribed()
	expect("subscribed again", next, "10.2.0.5", "control", 8)
}

// TestZoneCacheConcurrentChanges races lookups with changes: once the last
// change is reported, every lookup sees the networks it reported.
func TestZoneCacheConcurrentChanges(t *testing.T) {
	ifaces := &fakeInterfaces{nets: map[string]string{"plc0": "10.0.0.1/24"}}
	c := &zoneCache{addrsFor: ifaces.addrs}
	c.subscribed()
	snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"plant": {"plc0"}}}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.resolve(snap, net.ParseIP("10.0.0.5"), nil)
				}
			}
		}()
	}
	for i := 1; i <= 50; i++ {
		ifaces.set("plc0", fmt.Sprintf("10.%d.0.1/24", i))
		c.changed()
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if src, _ := c.resolve(snap, net.ParseIP("10.50.0.5"), nil); src != "plant" {
		t.Fatalf("zone after the last change = %q, want plant", src)
	}
}

// TestFailClosedRuleAllocatesNothing checks the per-packet scope lookup of
// an inline packet, with and without zoned rules, while the zone cache is
// subscribed.
func TestFailClosedRuleAllocatesNothing(t *testing.T) {
	for _, zoned := range []bool{false, true} {
		t.Run(fmt.Sprintf("zoned=%t", zoned), func(t *testing.T) {
			e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
			if err != nil {
				t.Fatal(err)
			}
			snap := firstCommandPolicy()
			if zoned {
				ifaces := &fakeInterfaces{nets: map[string]string{"cc0": testClient + "/24"}}
				e.zones.addrsFor = ifaces.addrs
				snap.ZoneIfaces = map[string][]string{"control": {"cc0"}}
				for i := range snap.Firewall {
					snap.Firewall[i].SourceZones = []string{"control"}
				}
			}
			e.zones.subscribed()
			e.LoadRules(snap)
			pkt := connSegment(false, 41000, dnp3Port, 1, ackPsh, dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}))
			pkt.Token = capture.NewToken(1, 1)
			state := e.trackFlow(pkt, time.Now())
			parsed := dpi.ParsedPacket{Proto: "tcp", SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
			if allocs := testing.AllocsPerRun(100, func() {
				if e.failClosedRule(pkt, state, &parsed) == nil {
					t.Fatal("flow out of scope")
				}
			}); allocs != 0 {
				t.Fatalf("failClosedRule allocates %v times per packet", allocs)
			}
		})
	}
}
