// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/capture"
)

type processorFunc func(capture.Packet)

func (f processorFunc) HandlePacket(p capture.Packet) { f(p) }

func TestTopologyRewrite(t *testing.T) {
	_, set := installedSet(t)
	topo := NewTopology([]string{"mgmt", "lan", "wan", "dmz"})
	for _, cap := range set.Captures {
		rec := cap.records[0]
		seen := map[string]bool{}
		for loop := uint64(0); loop < 100; loop++ {
			p, from, to, err := topo.rewrite(&cap, rec.packet, loop)
			if err != nil {
				t.Fatal(err)
			}
			client, server := topo.ResolveZones(cap.Family)
			wantFrom, wantTo := client, server
			if cap.role(rec.packet.SrcIP).Role == "server" {
				wantFrom, wantTo = server, client
				if p.SrcPort != rec.packet.SrcPort {
					t.Fatal("rewrote server port")
				}
			} else if p.DstPort != rec.packet.DstPort {
				t.Fatal("rewrote server port")
			}
			if from != wantFrom || to != wantTo || p.Interface != "demo:"+from {
				t.Fatalf("%s: zones %s->%s want %s->%s", cap.File, from, to, wantFrom, wantTo)
			}
			tuple := fmt.Sprintf("%s:%d>%s:%d", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
			if seen[tuple] {
				t.Fatalf("%s loop %d reused %s", cap.File, loop, tuple)
			}
			seen[tuple] = true
			for _, endpoint := range []struct {
				zone string
				ip   net.IP
			}{{from, p.SrcIP}, {to, p.DstIP}} {
				addrs, err := topo.ZoneAddresses("demo:" + endpoint.zone)
				if err != nil || !addrs[0].(*net.IPNet).Contains(endpoint.ip) {
					t.Fatalf("address outside topology: %+v %v", endpoint, err)
				}
			}
			if !bytes.Equal(p.Payload, rec.packet.Payload) || p.TCP != rec.packet.TCP {
				t.Fatal("changed payload or TCP metadata")
			}
			// Verify direction reversal preserves the rewritten flow identity.
			reverse := rec.packet
			reverse.SrcIP, reverse.DstIP = reverse.DstIP, reverse.SrcIP
			reverse.SrcPort, reverse.DstPort = reverse.DstPort, reverse.SrcPort
			r, rf, rt, err := topo.rewrite(&cap, reverse, loop)
			if err != nil || !r.SrcIP.Equal(p.DstIP) || !r.DstIP.Equal(p.SrcIP) || r.SrcPort != p.DstPort || r.DstPort != p.SrcPort || rf != to || rt != from {
				t.Fatalf("reverse changed identity: %+v %v", r, err)
			}
		}
	}
}

func TestTopologyFallback(t *testing.T) {
	for _, tc := range []struct {
		zones        []string
		family, a, b string
	}{
		{[]string{"mgmt", "plant", "outside"}, "modbus", "plant", "outside"},
		{[]string{"mgmt", "only"}, "it", "only", "only"},
		{[]string{"wan", "lan", "dmz"}, "it", "lan", "wan"},
		{[]string{"wan", "lan", "dmz"}, "cip", "dmz", "lan"},
		{[]string{"mgmt"}, "it", "", ""},
	} {
		topo := NewTopology(tc.zones)
		a, b := topo.ResolveZones(tc.family)
		if a != tc.a || b != tc.b {
			t.Fatalf("%v: %s -> %s", tc.zones, a, b)
		}
	}
	topo := NewTopology([]string{"mgmt", "lan"})
	for _, iface := range []string{"eth0", "demo:missing"} {
		if _, err := topo.ZoneAddresses(iface); err == nil {
			t.Fatalf("accepted %s", iface)
		}
	}
}

func TestRewriteDisjointCaptureAndLoopTuples(t *testing.T) {
	_, set := installedSet(t)
	topo := NewTopology([]string{"dmz", "lan", "wan"})
	seen := map[string]string{}
	for loop := uint64(0); loop < 10; loop++ {
		for _, cap := range set.Captures {
			iteration := fmt.Sprintf("%s/%d", cap.File, loop)
			for _, rec := range cap.records {
				p, _, _, err := topo.rewrite(&cap, rec.packet, loop)
				if err != nil {
					t.Fatal(err)
				}
				key := fmt.Sprintf("%d/%s:%d>%s:%d", p.Proto, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
				if old := seen[key]; old != "" && old != iteration {
					t.Fatalf("tuple shared by %s and %s", old, iteration)
				}
				seen[key] = iteration
			}
		}
	}
	// The mandated finite port range must wrap, but never exceed its bounds.
	cap := &set.Captures[0]
	rec := cap.records[0]
	p0, _, _, _ := topo.rewrite(cap, rec.packet, 0)
	pWrap, _, _, _ := topo.rewrite(cap, rec.packet, uint64(41000/len(cap.ports)))
	if p0.SrcPort != pWrap.SrcPort || p0.SrcPort < 20000 || p0.SrcPort > 60999 {
		t.Fatal("invalid finite port wrap")
	}
}

func TestPacedGap(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{
		{-time.Second, MinGap}, {0, MinGap}, {time.Millisecond, MinGap},
		{time.Second, time.Second}, {time.Minute, MaxGap},
	} {
		if got := PacedGap(tc.in); got != tc.want {
			t.Fatalf("%s -> %s want %s", tc.in, got, tc.want)
		}
	}
}

func TestRunCancellationJoin(t *testing.T) {
	_, set := installedSet(t)
	set.Captures = set.Captures[:1]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var c Counters
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- Run(ctx, set, NewTopology([]string{"dmz", "lan"}), processorFunc(func(p capture.Packet) {
			if p.Timestamp.Before(time.Now().Add(-time.Second)) {
				t.Error("packet was not retimed")
			}
			close(entered)
			<-release
		}), &c)
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Run returned before processor joined: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join promptly")
	}
	if samples := c.Samples("run1"); len(samples) != 0 {
		t.Fatal("stopped run published samples")
	}
}

func TestRunCancelDuringCapturePause(t *testing.T) {
	_, set := installedSet(t)
	set.Captures = set.Captures[:1]
	set.Captures[0].records = set.Captures[0].records[:1]
	var c Counters
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, set, NewTopology([]string{"dmz", "lan"}), processorFunc(func(capture.Packet) { packets <- struct{}{} }), &c)
	}()
	<-packets
	deadline := time.After(time.Second)
	for c.Status().Loops != 1 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("loop progress not published")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture pause ignored cancellation")
	}
}

func TestCountersUnitsEpochAndSameZone(t *testing.T) {
	_, set := installedSet(t)
	for _, zones := range [][]string{{"dmz", "lan", "wan"}, {"only"}} {
		var c Counters
		topo := NewTopology(zones)
		if err := c.start(set, topo); err != nil {
			t.Fatal(err)
		}
		from, to := topo.ResolveZones("modbus")
		c.charge(from, to, 100, 86)
		c.charge(from, to, 100, 86)
		before := c.Samples("run1")
		for _, s := range before {
			if s.Origin != telemetry.OriginDemo || s.Epoch != "run1" {
				t.Fatalf("bad origin/epoch: %+v", s)
			}
			switch s.Metric {
			case telemetry.IfaceTxBytes:
				if s.Dims["zone"] == from && s.Value != 200 {
					t.Fatal(s)
				}
				if s.Dims["role"] != "leaf" || s.Dims["interface"] != "demo:"+s.Dims["zone"] {
					t.Fatal(s)
				}
			case telemetry.IfaceRxBytes:
				if s.Dims["zone"] == to && s.Value != 200 {
					t.Fatal(s)
				}
			case telemetry.ConduitBytes, telemetry.ConduitPackets:
				if from == to {
					t.Fatal("same-zone conduit")
				}
				if s.Dims["from"] == from && s.Dims["to"] == to {
					want := uint64(172)
					if s.Metric == telemetry.ConduitPackets {
						want = 2
					}
					if s.Value != want {
						t.Fatalf("IP units: %+v", s)
					}
				}
			}
		}
		before[0].Dims["zone"] = "corrupted"
		if reflect.DeepEqual(before, c.Samples("run1")) {
			t.Fatal("mutable counter sample escaped")
		}
		c.stop()
		if len(c.Samples("run1")) != 0 {
			t.Fatal("stopped samples")
		}
		if err := c.start(set, topo); err != nil {
			t.Fatal(err)
		}
		for _, s := range c.Samples("run2") {
			if s.Value != 0 || s.Epoch != "run2" {
				t.Fatal(s)
			}
		}
		c.stop()
	}
}
