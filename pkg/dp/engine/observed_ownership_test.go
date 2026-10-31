// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestObservedScopeDisagreementKeepsHeldAndDroppedTokens(t *testing.T) {
	h := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecTypedPolicy("enforce"))
	// Reproduce the old publish window: the snapshot changed, while the IEC
	// table still owns a split APDU under the previous enforcing policy.
	monitor := iecTypedPolicy("monitor")
	h.e.ruleSnap.Install(&monitor, time.Now())
	payload := apdu(46, 6, 1, 3000, 2)
	held, d := h.send(true, payload[:4])
	if d.Action != capture.Hold {
		t.Fatalf("split APDU lost hold ownership: %+v", d)
	}
	_, d = h.send(true, payload[4:])
	if d.Action != capture.Drop {
		t.Fatalf("forbidden APDU lost drop ownership: %+v", d)
	}
	found := false
	for _, r := range d.Resolved {
		if r.Token == held.Token && r.Verdict == capture.VerdictDrop {
			found = true
		}
	}
	if !found {
		t.Fatalf("held token %v lost from drop resolutions: %+v", held, d)
	}
}

func TestObservedScopeDisagreementKeepsFailClosedDrop(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	d := e.HandlePacket(capture.Packet{Token: capture.NewToken(1, 1), Transport: "tcp", Proto: 6,
		SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"), SrcPort: 40000, DstPort: 2404,
		HasMark: true, Mark: enforce.EnvelopeMark, TCP: capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK}})
	if d.Action != capture.Drop || d.Reason != reasonIECFailClose {
		t.Fatalf("envelope disagreement admitted: %+v", d)
	}
}

func TestObservedDecisionRetainsResolutionAndNotify(t *testing.T) {
	token := capture.NewToken(1, 1)
	for _, action := range []capture.Disposition{capture.Accept, capture.Hold, capture.Drop} {
		original := capture.Decision{Action: action, Reason: "owned", Notify: true, Resolved: []capture.Resolution{{Token: token, Verdict: capture.VerdictDrop}}}
		got := observedDecision(capture.Packet{Mark: 0x020000ab}, original)
		want := action
		if action == capture.Accept {
			want = capture.Repeat
		}
		if got.Action != want || !got.Notify || got.Reason != original.Reason || len(got.Resolved) != 1 || got.Resolved[0] != original.Resolved[0] {
			t.Fatalf("action %v lost ownership metadata: %+v", action, got)
		}
		if got.Action == capture.Repeat && got.Mark != enforce.ObservedMark|0xab {
			t.Fatalf("replacement mark %#x", got.Mark)
		}
	}
}

func TestPolicyPublishExcludesPacketReaders(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(rules.Snapshot{Version: "before"})
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	build := e.iec.newPolicy
	e.iec.newPolicy = func(snap *rules.Snapshot) iecPolicy {
		close(entered)
		<-release
		return build(snap)
	}
	go func() { done <- e.ApplyRules(context.Background(), rules.Snapshot{Version: "after"}) }()
	<-entered
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	// Installation has reached the IEC table switch. Packet scope readers
	// must remain excluded until both authorities describe this generation.
	if e.policyMu.TryRLock() {
		e.policyMu.RUnlock()
		t.Fatal("packet readers can enter a partially published generation")
	}
}
