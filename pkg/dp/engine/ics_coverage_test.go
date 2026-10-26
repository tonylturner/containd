// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func modbusEnforceSnapshot(id string) rules.Snapshot {
	return rules.Snapshot{Firewall: []rules.Entry{{ID: id, Action: rules.ActionAllow,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}}}}
}

func coverageCodes(rs []coverage.Rule) (coverage.State, []coverage.Code) {
	if len(rs) != 1 {
		return "", nil
	}
	var out []coverage.Code
	for _, r := range rs[0].Reasons {
		out = append(out, r.Code)
	}
	return rs[0].State, out
}

func wantCoverage(t *testing.T, e *Engine, when string, state coverage.State, codes ...coverage.Code) {
	t.Helper()
	got := e.ICSCoverage()
	gotState, gotCodes := coverageCodes(got)
	if gotState != state || !reflect.DeepEqual(gotCodes, codes) {
		t.Fatalf("%s: coverage = %+v, want %s %v", when, got, state, codes)
	}
	if st := e.RulesetStatus(); !reflect.DeepEqual(st.ICSCoverage, got) {
		t.Fatalf("%s: ruleset status coverage = %+v, want %+v", when, st.ICSCoverage, got)
	}
	for _, r := range got {
		for _, x := range r.Reasons {
			if x.Runtime != (x.Code == coverage.QueueUnavailable) {
				t.Fatalf("%s: reason %+v has the wrong runtime flag", when, x)
			}
		}
	}
}

// The configured queue protects only while this engine holds it.
func TestICSCoverageQueueOverlay(t *testing.T) {
	e := gateEngine(t, &nftModel{}, 101, &bindCapture{})
	if err := e.ApplyRules(context.Background(), modbusEnforceSnapshot("read")); err != nil {
		t.Fatal(err)
	}
	wantCoverage(t, e, "before the first bind", coverage.NotEnforcing, coverage.QueueUnavailable)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.StartWithRetry(ctx); err != nil {
		t.Fatal(err)
	}
	wantCoverage(t, e, "queue bound", coverage.Enforcing)
	e.hooks.onSource(capture.SourceEvent{Generation: 1, Err: errors.New("socket closed")})
	wantCoverage(t, e, "queue down", coverage.NotEnforcing, coverage.QueueUnavailable)
	e.hooks.onSource(capture.SourceEvent{Generation: 2, Ready: true})
	wantCoverage(t, e, "queue rebound", coverage.Enforcing)

	learn := modbusEnforceSnapshot("read")
	learn.Firewall[0].ICS.Mode = "learn"
	if err := e.ApplyRules(context.Background(), learn); err != nil {
		t.Fatal(err)
	}
	e.hooks.onSource(capture.SourceEvent{Generation: 2})
	wantCoverage(t, e, "learn rule while the queue is down", coverage.Monitoring)
}

// The engine accepts a snapshot that enforces without an inline path, and
// reports it instead of claiming protection.
func TestICSCoverageContradictorySnapshot(t *testing.T) {
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, Applier: &recordingApplier{}, Updater: &recordingUpdater{}},
		DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), modbusEnforceSnapshot("old")); err != nil {
		t.Fatalf("contradictory snapshot refused: %v", err)
	}
	wantCoverage(t, e, "no queue configured", coverage.NotEnforcing, coverage.NoInlinePath)
}

// Applied coverage describes the rules in force. A failed apply leaves the
// kernel ruleset and the engine snapshot unchanged, so the status adds the
// failure (error and the failed snapshot's version) while the coverage
// still describes the previous rules; with no earlier success it is empty.
func TestICSCoverageAfterFailedApply(t *testing.T) {
	applier := &recordingApplier{err: errors.New("nft apply failed")}
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, Applier: applier, Updater: &recordingUpdater{}},
		DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	first := modbusEnforceSnapshot("first")
	first.Version = "v1"
	if err := e.ApplyRules(context.Background(), first); err == nil {
		t.Fatal("apply error swallowed")
	}
	if st := e.RulesetStatus(); st.Error == "" || st.FailedSnapshotVersion != "v1" || st.ICSCoverage != nil {
		t.Fatalf("first failed apply: status %+v, want the error and no coverage", st)
	}

	applier.err = nil
	running := modbusEnforceSnapshot("running")
	running.Version = "v2"
	running.Firewall[0].ICS.Mode = "learn"
	if err := e.ApplyRules(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	applier.err = errors.New("nft apply failed")
	failed := modbusEnforceSnapshot("failed")
	failed.Version = "v3"
	if err := e.ApplyRules(context.Background(), failed); err == nil {
		t.Fatal("apply error swallowed")
	}
	st := e.RulesetStatus()
	if st.Error == "" || st.FailedSnapshotVersion != "v3" || st.SnapshotVersion != "v2" {
		t.Fatalf("status after failed apply = %+v, want the failure", st)
	}
	if len(st.ICSCoverage) != 1 || st.ICSCoverage[0].RuleID != "running" || st.ICSCoverage[0].State != coverage.Monitoring {
		t.Fatalf("coverage after failed apply = %+v, want the running learn rule", st.ICSCoverage)
	}
}

func exclusionMatches(e *Engine, value string) uint64 {
	for _, r := range e.ICSCoverage() {
		for _, x := range r.Reasons {
			if x.Value == value && !x.Runtime {
				return x.Matches
			}
		}
	}
	return 0
}

func tcpPacket(src, dst string, sport, dport uint16, flags capture.TCPFlags) capture.Packet {
	return capture.Packet{SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), SrcPort: sport, DstPort: dport,
		Proto: 6, Transport: "tcp", TCP: capture.TCPMeta{Flags: flags}}
}

// An address exclusion's matches count the connections it exempted since
// the rules were applied: once per connection, never IEC 104 sessions,
// and nothing while DPI is off.
func TestICSCoverageAddressExclusionMatches(t *testing.T) {
	newEngine := func(dpi bool) *Engine {
		e, err := New(Config{DPIEnabled: dpi, DPIMode: "enforce", NFQueueGroup: 0, DPIExclusions: []DPIExclusion{
			{Type: "ip", Value: "10.0.0.2"}, {Type: "cidr", Value: "10.9.0.0/16"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.ApplyRules(context.Background(), modbusEnforceSnapshot("read")); err != nil {
			t.Fatal(err)
		}
		return e
	}
	traffic := func(e *Engine) {
		for _, sport := range []uint16{40000, 40001} {
			e.HandlePacket(tcpPacket("10.0.0.1", "10.0.0.2", sport, 502, capture.TCPFlagSYN))
			e.HandlePacket(tcpPacket("10.0.0.2", "10.0.0.1", 502, sport, capture.TCPFlagSYN|capture.TCPFlagACK))
			e.HandlePacket(tcpPacket("10.0.0.1", "10.0.0.2", sport, 502, capture.TCPFlagACK))
		}
		e.HandlePacket(tcpPacket("10.0.0.1", "10.0.0.2", 40002, 2404, capture.TCPFlagSYN))
	}

	e := newEngine(true)
	if got := exclusionMatches(e, "10.0.0.2"); got != 0 {
		t.Fatalf("matches before traffic = %d", got)
	}
	traffic(e)
	if got := exclusionMatches(e, "10.0.0.2"); got != 2 {
		t.Fatalf("ip exclusion matches = %d, want 2 connections", got)
	}
	if got := exclusionMatches(e, "10.9.0.0/16"); got != 0 {
		t.Fatalf("unmatched cidr exclusion counted %d", got)
	}
	if err := e.ApplyRules(context.Background(), modbusEnforceSnapshot("read")); err != nil {
		t.Fatal(err)
	}
	if got := exclusionMatches(e, "10.0.0.2"); got != 0 {
		t.Fatalf("matches after a new apply = %d, want 0", got)
	}

	off := newEngine(false)
	traffic(off)
	if got := exclusionMatches(off, "10.0.0.2"); got != 0 {
		t.Fatalf("matches with DPI off = %d, want 0", got)
	}
}

func TestICSCoverageDomainExclusionMatches(t *testing.T) {
	e, _ := domainTestEngine(t)
	if err := e.ApplyRules(context.Background(), modbusEnforceSnapshot("read")); err != nil {
		t.Fatal(err)
	}
	observeTestDNS(e, 300)
	pkt := domainClientPacket(41000, nil)
	e.HandlePacket(pkt)
	pkt.Payload = []byte("GET / HTTP/1.0\r\n\r\n")
	e.HandlePacket(pkt)
	e.HandlePacket(pkt)
	if got := exclusionMatches(e, "*.example.com"); got != 1 {
		t.Fatalf("domain exclusion matches = %d, want 1 connection", got)
	}
}

func TestPreviewRuleCarriesCoverage(t *testing.T) {
	e := gateEngine(t, &nftModel{}, 101, &bindCapture{})
	entry := modbusEnforceSnapshot("candidate").Firewall[0]
	got := e.PreviewRule(entry).ICSCoverage
	if got == nil || got.RuleID != "candidate" || got.State != coverage.NotEnforcing ||
		len(got.Reasons) != 1 || got.Reasons[0].Code != coverage.QueueUnavailable {
		t.Fatalf("unbound queue preview coverage = %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.StartWithRetry(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.PreviewRule(entry).ICSCoverage; got == nil || got.State != coverage.Enforcing || got.Mode != "enforce" {
		t.Fatalf("bound queue preview coverage = %+v", got)
	}
	l4 := rules.Entry{ID: "l4", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Mode: "enforce"}}
	if got := e.PreviewRule(l4).ICSCoverage; got != nil {
		t.Fatalf("rule without ICS protocol has coverage %+v", got)
	}
}
