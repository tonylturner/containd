// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func detachedTestConfig(s *events.Store) DetachedConfig {
	return DetachedConfig{Events: s.Writer(telemetry.OriginDemo),
		ZoneAddresses: func(string) ([]net.Addr, error) { return nil, nil }}
}

func mustDetached(t *testing.T, s *events.Store) *Detached {
	t.Helper()
	d, err := NewDetached(detachedTestConfig(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func TestDetachedConstructorSafety(t *testing.T) {
	s := events.NewStore(4096)
	cfg := detachedTestConfig(s)
	for _, bad := range []DetachedConfig{
		{}, {Events: s.Writer(telemetry.OriginReal), ZoneAddresses: cfg.ZoneAddresses},
		{Events: cfg.Events}, {Events: (*events.Store)(nil).Writer(telemetry.OriginDemo), ZoneAddresses: cfg.ZoneAddresses},
	} {
		if d, err := NewDetached(bad); err == nil || d != nil {
			t.Fatal("accepted missing demo provenance or topology resolver")
		}
	}
	d := mustDetached(t, s)
	e := d.engine
	if e.capture != nil || e.captureFactory != nil || e.compiler != nil || e.applier != nil ||
		e.updater != nil || e.transport != nil || e.observation != nil || e.gate != nil ||
		e.learnWatch.Load() != nil || e.learnLoss != nil || e.sessions.injector != nil ||
		e.sessions.jobs != nil || e.sessions.settler != nil || e.hooks != nil || e.localIPv4 != nil ||
		e.nflogGroup != 0 || e.nfqueueGroup != 0 || !e.inspectAll {
		t.Fatal("detached constructor acquired live capabilities")
	}
	if _, err := e.clearMarks(context.Background(), 0, 0, 0); !errors.Is(err, errDetachedAuthority) {
		t.Fatal("conntrack clear-mark not refused")
	}
	if err := e.sessions.ctDelete(context.Background(), conntrack.DeleteRequest{}); !errors.Is(err, errDetachedAuthority) {
		t.Fatal("conntrack delete not refused")
	}
	// Install sentinels only after proving no worker/conntrack transport exists.
	e.sessions.jobs = newWorker(1)
	e.sessions.jobs.submitted = func() { t.Error("detached inspection submitted reset/abort work") }
	e.sessions.ctDelete = func(context.Context, conntrack.DeleteRequest) error {
		t.Error("detached inspection called conntrack")
		return nil
	}
	snap := rules.Snapshot{DPIMode: "enforce", Firewall: []rules.Entry{
		{ID: "iec-enforce", Action: rules.ActionDeny, Log: true, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "modbus-enforce", Action: rules.ActionDeny, Log: true, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}},
	}}
	d.LoadRules(snap)
	if snap.Firewall[0].ICS.Mode != "enforce" || e.CurrentRules().Firewall[0].ICS.Mode != "monitor" {
		t.Fatal("did not downgrade a private copy of the supplied snapshot")
	}
	// An inline-looking midstream control request must lose all transport
	// authority before reaching exactly the same packet chain as live capture.
	d.HandlePacket(capture.Packet{Timestamp: time.Now(), Proto: 6, Transport: "tcp",
		SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20"), SrcPort: 41000, DstPort: 2404,
		Token: capture.NewToken(1, 1), HasMark: true, Mark: ^uint32(0),
		TCP: capture.TCPMeta{Valid: true, Seq: 100, Ack: 200, Flags: capture.TCPFlagACK}, Payload: iframe(45, 1)})
	// Policy replacement must not abort the monitor session either.
	d.LoadRules(snap)
	for _, ev := range s.ListTelemetry(0) {
		if ev.Origin != telemetry.OriginDemo || ev.Attributes["outcome"] == "aborted" || ev.Attributes["outcome"] == "reset_failed" {
			t.Fatalf("effectful detached event: %+v", ev)
		}
	}
	if len(e.sessions.jobs.jobs) != 0 || !e.sessions.health.status().Healthy {
		t.Fatal("detached inspection queued I/O or declared enforce health faults")
	}
}

func TestDetachedTopologyResolution(t *testing.T) {
	s := events.NewStore(8)
	cfg := detachedTestConfig(s)
	calls := 0
	cfg.ZoneAddresses = func(iface string) ([]net.Addr, error) {
		calls++
		prefix := map[string]string{"demo:dmz": "198.18.0.0/24", "demo:lan": "198.18.1.0/24"}[iface]
		if prefix == "" {
			t.Fatalf("unexpected topology interface %q", iface)
		}
		_, network, err := net.ParseCIDR(prefix)
		return []net.Addr{network}, err
	}
	d, err := NewDetached(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.LoadRules(rules.Snapshot{ZoneIfaces: map[string][]string{"dmz": {"demo:dmz"}, "lan": {"demo:lan"}}})
	src, dst := d.engine.zones.resolve(d.engine.CurrentRules(), net.ParseIP("198.18.0.10"), net.ParseIP("198.18.1.20"))
	if calls == 0 || src != "dmz" || dst != "lan" || d.engine.zones.watched.Load() {
		t.Fatalf("topology resolver: calls=%d, zones=%s/%s, host watch=%v", calls, src, dst, d.engine.zones.watched.Load())
	}
}

func TestDetachedInvalidPacketAccounting(t *testing.T) {
	before := containdMetrics(t)
	d := mustDetached(t, events.NewStore(8))
	d.HandlePacket(capture.Packet{Transport: "tcp", Invalid: capture.InvalidTruncated, CaptureIncomplete: true})
	got := d.Stats().Stats()
	if len(got) != 1 || got[0].Protocol != "tcp" || got[0].PacketCount != 1 || len(d.engine.flows) != 0 {
		t.Fatalf("detached invalid packet diverged from live accounting: %+v", got)
	}
	if !reflect.DeepEqual(before, containdMetrics(t)) {
		t.Fatal("invalid demo packet charged live metrics")
	}
}

func containdMetrics(t *testing.T) map[string]string {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, family := range families {
		if strings.HasPrefix(family.GetName(), "containd_") {
			out[family.GetName()] = family.String()
		}
	}
	return out
}

func TestDetachedCorpusProvenanceAndMetrics(t *testing.T) {
	before := containdMetrics(t)
	var files, packets, emitted int
	for _, family := range []string{"modbus", "dnp3", "iec104", "cip", "it"} {
		paths, err := filepath.Glob("../../../test/" + family + "/testdata/*.pcap")
		if err != nil || len(paths) == 0 {
			t.Fatalf("missing %s fixtures: %v", family, err)
		}
		for _, path := range paths {
			t.Run(family+"/"+filepath.Base(path), func(t *testing.T) {
				f, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				records, _, err := corpus.ReadPCAP(f, path, corpus.ReadOptions{IgnoreEtherTypes: []uint16{0x0806}})
				if err != nil {
					t.Fatal(err)
				}
				s := events.NewStore(8192)
				d := mustDetached(t, s)
				live, err := New(Config{})
				if err != nil {
					t.Fatal(err)
				}
				defer live.Close()
				if d.Stats() == live.stats || d.engine.inventory == live.inventory || d.engine.sigEngine == live.sigEngine {
					t.Fatal("demo shares live inspection state")
				}
				liveBefore := live.ProtoStats()
				d.LoadRules(iecSnapshot("enforce"))
				for i, record := range records {
					pkt := record.Decoded
					pkt.Timestamp = time.Now().Add(time.Duration(i) * time.Millisecond)
					d.HandlePacket(pkt)
				}
				rows := s.ListTelemetry(0)
				// A link-only DNP3 exchange has no application object; the
				// truncated Modbus tail has neither FIN nor a complete ADU.
				// Neither produces a live decoder event on packet arrival.
				empty := family == "dnp3" && filepath.Base(path) == "link-only.pcap" || family == "modbus" && filepath.Base(path) == "truncation.pcap"
				if (len(rows) == 0) != empty || len(d.Stats().Stats()) == 0 {
					t.Fatalf("capture event count=%d, expected empty=%v; stats=%+v", len(rows), empty, d.Stats().Stats())
				}
				for _, ev := range rows {
					if ev.Origin != telemetry.OriginDemo {
						t.Fatalf("unstamped event: %+v", ev)
					}
				}
				counts := s.TelemetryCounts()
				if counts[0].Total != 0 || counts[1].Total != uint64(len(rows)) || !reflect.DeepEqual(liveBefore, live.ProtoStats()) {
					t.Fatalf("real accounting changed: %+v", counts)
				}
				files++
				packets += len(records)
				emitted += len(rows)
			})
		}
	}
	if after := containdMetrics(t); !reflect.DeepEqual(before, after) {
		for name, value := range after {
			if value != before[name] {
				t.Errorf("demo changed global metric %s", name)
			}
		}
	}
	t.Logf("%d captures, %d packets, %d demo events", files, packets, emitted)
}

func TestDetachedRunExpiryAndClose(t *testing.T) {
	s := events.NewStore(4096)
	d := mustDetached(t, s)
	d.LoadRules(iecSnapshot("monitor"))
	// Session expiry uses the normal table clock without capture, watch or I/O.
	d.HandlePacket(capture.Packet{Timestamp: time.Now(), Proto: 6, Transport: "tcp",
		SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20"), SrcPort: 41000, DstPort: 2404,
		TCP: capture.TCPMeta{Valid: true, Seq: 100, Flags: capture.TCPFlagSYN}})
	d.engine.sessions.mu.Lock()
	if len(d.engine.sessions.sessions) == 0 {
		t.Fatal("SYN did not create monitor session")
	}
	d.engine.sessions.now = func() time.Time { return time.Now().Add(2 * sessionIdleTTL) }
	d.engine.sessions.mu.Unlock()
	runDone := make(chan struct{})
	go func() { d.Run(context.Background()); close(runDone) }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		d.engine.sessions.mu.Lock()
		n := len(d.engine.sessions.sessions)
		d.engine.sessions.mu.Unlock()
		if n == 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("Run did not expire the IEC session")
		case <-tick.C:
		}
	}
	updatesDone := make(chan struct{})
	go func() {
		defer close(updatesDone)
		for i := 0; i < 20; i++ {
			d.LoadRules(iecSnapshot("enforce"))
			d.SetICSParsing(map[string]string{"iec104": "strict"})
			d.SetSignatures([]signatures.Signature{{ID: "demo", Protocol: "modbus"}})
		}
	}()
	d.Close()
	<-updatesDone
	select {
	case <-runDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not join Run")
	}
	before := s.TelemetryCounts()
	d.HandlePacket(capture.Packet{})
	if !reflect.DeepEqual(before, s.TelemetryCounts()) {
		t.Fatal("publication after Close")
	}
}
