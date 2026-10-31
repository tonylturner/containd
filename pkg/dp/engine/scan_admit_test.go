// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// admitModel records applied scripts and tracks the admission chain of
// table containd_policy like the kernel would: a table replacement sets it
// from the compiled chain, a switch rewrites it.
type admitModel struct {
	mu       sync.Mutex
	scripts  int
	admit    string
	failNext bool
}

func (m *admitModel) Apply(_ context.Context, script string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext {
		m.failNext = false
		return errors.New("nft: netlink busy")
	}
	m.scripts++
	const chain = "  chain " + enforce.GateAdmitChain + " {\n"
	if i := strings.Index(script, chain); i >= 0 {
		body := script[i+len(chain):]
		m.admit = admitState(strings.TrimSpace(body[:strings.Index(body, "  }\n")]))
		return nil
	}
	const add = "add rule inet containd_policy " + enforce.GateAdmitChain + " "
	if i := strings.Index(script, add); i >= 0 {
		m.admit = admitState(script[i+len(add):])
	}
	return nil
}

func (m *admitModel) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}

// admitState names the state the chain's first rule means.
func admitState(rules string) string {
	first := rules[:strings.IndexAny(rules, ";\n")]
	switch first {
	case "jump " + enforce.GateDeliverChain:
		return "open"
	case "jump gate_ics":
		return "refuse"
	}
	if strings.HasSuffix(first, " return") {
		return "pass"
	}
	return "?" + first
}

func (m *admitModel) state() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.admit, m.scripts
}

func admitEngine(t *testing.T, nft *admitModel, enforcing bool) *Engine {
	t.Helper()
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: enforcing, Applier: nft, Updater: &recordingUpdater{},
		GatePlainPort: enforce.DefaultGatePlainPort, GateMasqPort: enforce.DefaultGateMasqPort}})
	if err != nil {
		t.Fatal(err)
	}
	e.capture = &bindCapture{}
	return e
}

func applyGated(t *testing.T, e *Engine) {
	t.Helper()
	snap := rules.Snapshot{Default: rules.ActionDeny, ZoneIfaces: map[string][]string{"lan": {"eth1"}, "wan": {"eth0"}},
		Gate: rules.GateSelection{Enabled: true, Zones: []rules.GateZone{{Name: "wan", Index: 1, Devices: []string{"eth0"}}},
			Include: []rules.GateEntry{{DestZones: []string{"wan"}, Ports: []rules.GatePortRange{{Lo: 80, Hi: 80}}}}}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
}

func wantAdmit(t *testing.T, nft *admitModel, want, when string) {
	t.Helper()
	if got, _ := nft.state(); got != want {
		t.Fatalf("%s: gate_admit = %q, want %q", when, got, want)
	}
}

// TestGateAdmitRefusesUntilSetAndSurvivesApplies: the first ruleset
// refuses; a switch rewrites the installed chain alone and every later
// apply writes the switched state.
func TestGateAdmitRefusesUntilSetAndSurvivesApplies(t *testing.T) {
	nft := &admitModel{}
	e := admitEngine(t, nft, true)
	if e.GateAdmit() != enforce.GateAdmitRefuse {
		t.Fatal("initial state is not refuse")
	}
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitOpen); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.state(); n != 0 {
		t.Fatal("a switch before the first apply wrote to nft")
	}
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitRefuse); err != nil {
		t.Fatal(err)
	}
	applyGated(t, e)
	wantAdmit(t, nft, "refuse", "first apply")
	_, n := nft.state()
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitOpen); err != nil {
		t.Fatal(err)
	}
	wantAdmit(t, nft, "open", "switched open")
	if _, m := nft.state(); m != n+1 {
		t.Fatalf("switch wrote %d scripts, want 1", m-n)
	}
	applyGated(t, e)
	wantAdmit(t, nft, "open", "reapplied while open")
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitPass); err != nil {
		t.Fatal(err)
	}
	wantAdmit(t, nft, "pass", "switched to pass")
	applyGated(t, e)
	wantAdmit(t, nft, "pass", "reapplied while passing")
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitState(7)); err == nil {
		t.Fatal("unknown state accepted")
	}
}

// TestGateAdmitOutlivesReconfigure: Reconfigure replaces the compiler; the
// next apply still writes the state set before it.
func TestGateAdmitOutlivesReconfigure(t *testing.T) {
	nft := &admitModel{}
	e := admitEngine(t, nft, true)
	applyGated(t, e)
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitOpen); err != nil {
		t.Fatal(err)
	}
	wantAdmit(t, nft, "open", "switched open")
	if err := e.Reconfigure(admitEngine(t, nft, true)); err != nil {
		t.Fatal(err)
	}
	if e.GateAdmit() != enforce.GateAdmitOpen {
		t.Fatal("Reconfigure reset the admission state")
	}
	applyGated(t, e)
	wantAdmit(t, nft, "open", "reapplied after Reconfigure")
}

// TestGateAdmitFailedSwitchKeepsKernelStateAndIsRetriedByApply: a failed
// switch reports the error and leaves the chain as it was; the next apply
// writes the wanted state.
func TestGateAdmitFailedSwitchKeepsKernelStateAndIsRetriedByApply(t *testing.T) {
	nft := &admitModel{}
	e := admitEngine(t, nft, true)
	applyGated(t, e)
	nft.mu.Lock()
	nft.failNext = true
	nft.mu.Unlock()
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitOpen); err == nil {
		t.Fatal("failed switch reported success")
	}
	wantAdmit(t, nft, "refuse", "after the failed switch")
	if e.GateAdmit() != enforce.GateAdmitOpen {
		t.Fatal("the wanted state was not kept")
	}
	applyGated(t, e)
	wantAdmit(t, nft, "open", "reapplied after the failed switch")
}

// TestGateAdmitWithoutEnforcementWritesNothing: the state is kept for a
// later enforcing configuration, but nothing reaches nft.
func TestGateAdmitWithoutEnforcementWritesNothing(t *testing.T) {
	nft := &admitModel{}
	e := admitEngine(t, nft, false)
	if err := e.SetGateAdmit(context.Background(), enforce.GateAdmitOpen); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.state(); n != 0 {
		t.Fatal("a switch without enforcement wrote to nft")
	}
	if e.GateAdmit() != enforce.GateAdmitOpen {
		t.Fatal("state not kept without enforcement")
	}
	if err := e.Reconfigure(admitEngine(t, nft, true)); err != nil {
		t.Fatal(err)
	}
	applyGated(t, e)
	wantAdmit(t, nft, "open", "enforcement enabled after the switch")
}
