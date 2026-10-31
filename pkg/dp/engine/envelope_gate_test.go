// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// nftModel replays applied scripts like the kernel would for the envelope
// chain of table containd_policy: replacing or deleting the table sets or
// removes it, a switch replaces its rule.
type nftModel struct {
	mu       sync.Mutex
	live     enforce.TableLayout // what ReadTable reports
	readErr  error               // what ReadTable fails with
	scripts  []string
	envelope string // "", "drop" or "queue N"
	failNext bool
}

func (m *nftModel) Apply(_ context.Context, script string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return errors.New("nft: netlink busy")
	}
	m.scripts = append(m.scripts, script)
	if strings.Contains(script, enforce.DeleteTable("containd_policy")) {
		m.envelope = ""
		if i := strings.Index(script, "chain iec104_envelope {\n    "); i >= 0 {
			m.envelope = envelopeState(script[i+len("chain iec104_envelope {\n    "):])
		}
		return nil
	}
	const add = "add rule inet containd_policy iec104_envelope "
	if i := strings.Index(script, add); i >= 0 {
		m.envelope = envelopeState(script[i+len(add):])
	}
	return nil
}

func (m *nftModel) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live, m.readErr
}

func envelopeState(rule string) string {
	rule = rule[:strings.IndexAny(rule, ";\n")]
	if rule == "drop" {
		return "drop"
	}
	if i := strings.Index(rule, "queue num "); i >= 0 {
		return "queue " + rule[i+len("queue num "):]
	}
	return "?" + rule
}

func (m *nftModel) state() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.envelope, len(m.scripts)
}

func gateEngine(t *testing.T, nft *nftModel, group uint16, c captureRunner) *Engine {
	t.Helper()
	e, err := New(Config{
		Enforce:       EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: nft, Updater: &recordingUpdater{}},
		DPIEnabled:    true,
		DPIMode:       "enforce",
		NFQueueGroup:  group,
		ResetInjector: &session.Fake{},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.capture = c
	return e
}

func applyIEC(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.ApplyRules(context.Background(), iecSnapshot("enforce")); err != nil {
		t.Fatal(err)
	}
}

func wantEnvelope(t *testing.T, nft *nftModel, want, when string) {
	t.Helper()
	if got, _ := nft.state(); got != want {
		t.Fatalf("%s: envelope = %q, want %q", when, got, want)
	}
}

func TestEnvelopeClosedUntilBindThenOpen(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	applyIEC(t, e)
	wantEnvelope(t, nft, "drop", "rules applied before the first bind")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.StartWithRetry(ctx); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "queue 101", "after Start bound the queue")
	_, n := nft.state()
	e.hooks.onSource(capture.SourceEvent{Generation: 1, Ready: true})
	if _, m := nft.state(); m != n {
		t.Fatal("a repeated ready must not rewrite nft")
	}
	applyIEC(t, e)
	wantEnvelope(t, nft, "queue 101", "rules reapplied while bound")
}

func TestEnvelopeStaysClosedWhileBindFailsAndRetries(t *testing.T) {
	fastRetry(t, 8)
	nft := &nftModel{}
	c := &bindCapture{fails: 3}
	e := gateEngine(t, nft, 101, c)
	applyIEC(t, e)
	// Every failed attempt leaves the envelope dropped; a rule reapply in
	// between never opens it.
	starts := 0
	e.onError = func(error) {
		if got, _ := nft.state(); got != "drop" {
			t.Errorf("attempt %d failed with envelope %q", starts, got)
		}
		starts++
		applyIEC(t, e)
	}
	if err := e.StartWithRetry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starts != 3 {
		t.Fatalf("failed attempts seen = %d, want 3", starts)
	}
	wantEnvelope(t, nft, "queue 101", "after the bind finally succeeded")
}

func TestEnvelopeFollowsSourceDownAndUp(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	applyIEC(t, e)
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "queue 101", "bound")
	e.hooks.onSource(capture.SourceEvent{Generation: 1, Err: errors.New("netlink closed")})
	wantEnvelope(t, nft, "drop", "source down")
	applyIEC(t, e)
	wantEnvelope(t, nft, "drop", "rules reapplied while the source is down")
	e.hooks.onSource(capture.SourceEvent{Generation: 2, Ready: true})
	wantEnvelope(t, nft, "queue 101", "source rebound")
}

func TestEnvelopeClosesOnReconfigureAndRequiresTheOwnedQueue(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	applyIEC(t, e)
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "queue 101", "bound")
	// The new configuration uses queue 102; the installed ruleset still
	// steers to 101, which nobody in this engine owns.
	fresh := gateEngine(t, nft, 102, &bindCapture{})
	e.Reconfigure(fresh)
	wantEnvelope(t, nft, "drop", "after Reconfigure, before the new bind")
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "drop", "queue 102 bound but the ruleset steers to 101")
	applyIEC(t, e)
	wantEnvelope(t, nft, "queue 102", "ruleset for queue 102 applied")
	// Same group again: closes on Reconfigure, reopens on bind.
	e.Reconfigure(gateEngine(t, nft, 102, &bindCapture{}))
	wantEnvelope(t, nft, "drop", "second Reconfigure")
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "queue 102", "rebound after Reconfigure")
}

func TestEnvelopeSwitchFailureFailsClosedAndIsUnhealthy(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	applyIEC(t, e)
	nft.mu.Lock()
	nft.failNext = true
	nft.mu.Unlock()
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEnvelope(t, nft, "drop", "open switch failed")
	if st := e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "envelope steering switch") {
		t.Fatalf("health = %+v", st)
	}
	// The next reapply writes the owned state, which clears the fault.
	applyIEC(t, e)
	wantEnvelope(t, nft, "queue 101", "reapplied while bound")
	if st := e.IEC104Enforcement(); !st.Healthy {
		t.Fatalf("health after the reapply = %+v", st)
	}
}

func TestUSRulesetUnchangedByEnvelopeState(t *testing.T) {
	nft := &nftModel{}
	e := gateEngine(t, nft, 101, &bindCapture{})
	us := rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
		ID: "mb", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS: rules.ICSPredicate{Protocol: "modbus"}, Action: rules.ActionAllow,
	}}}
	if err := e.ApplyRules(context.Background(), us); err != nil {
		t.Fatal(err)
	}
	before := nft.scripts[len(nft.scripts)-1]
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), us); err != nil {
		t.Fatal(err)
	}
	if got := nft.scripts[len(nft.scripts)-1]; got != before || len(nft.scripts) != 2 {
		t.Fatalf("a US-only ruleset changed with the queue state (%d scripts):\n%s", len(nft.scripts), got)
	}
	if !regexp.MustCompile(`tcp dport 502 counter name "rule_[0-9a-f]{16}" jump ics_enforce_queue;`).MatchString(before) ||
		!strings.Contains(before, "meta mark set meta mark and 0xe0ffffff or 0x08000000 queue num 101;") {
		t.Fatalf("US Modbus steering missing:\n%s", before)
	}
}

func TestEnvelopeSampleUsesCandidateQueue(t *testing.T) {
	g := &envelopeGate{}
	for _, owned := range []uint16{0, 101, 102} {
		g.own(owned)
		for _, queue := range []int{0, 101, 102} {
			want := owned != 0 && int(owned) == queue
			if got := g.sampleOpen(queue); got != want {
				t.Fatalf("owned=%d candidate=%d open=%v want=%v", owned, queue, got, want)
			}
			if g.comp != nil || g.installed || g.open {
				t.Fatal("sample changed gate state")
			}
		}
	}
}
