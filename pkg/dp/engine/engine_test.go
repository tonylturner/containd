// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func TestEngineStartAndRules(t *testing.T) {
	// Use a platform loopback name, but skip if unavailable.
	loopbacks := []string{"lo", "lo0"}
	var e *Engine
	var err error
	for _, name := range loopbacks {
		e, err = New(Config{Capture: capture.Config{Interfaces: []string{name}}})
		if err == nil {
			if startErr := e.Start(context.Background()); startErr == nil {
				break
			}
		}
	}
	if e == nil || err != nil {
		t.Skipf("no loopback interface available: %v", err)
	}
	snap := rules.Snapshot{Version: "1"}
	e.LoadRules(snap)
	if got := e.CurrentRules(); got == nil || got.Version != "1" {
		t.Fatalf("expected snapshot version 1, got %+v", got)
	}

	act := e.Evaluate(rules.EvalContext{})
	if act == "" {
		t.Fatalf("expected action")
	}
}

func TestEvaluateVerdictMapsActions(t *testing.T) {
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"lo"}}})
	if err != nil {
		e, err = New(Config{Capture: capture.Config{Interfaces: []string{"lo0"}}})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	v := e.EvaluateVerdict(rules.EvalContext{})
	if v.Action != verdict.AllowContinue {
		t.Fatalf("expected allow verdict, got %s", v.Action)
	}
}

type recordingApplier struct {
	ruleset string
	err     error
}

func (r *recordingApplier) Apply(ctx context.Context, ruleset string) error {
	r.ruleset = ruleset
	return r.err
}

func TestApplyRulesEnforcesBeforeSwap(t *testing.T) {
	applier := &recordingApplier{}
	e, err := New(Config{
		Capture: capture.Config{Interfaces: []string{"lo"}},
		Enforce: EnforceConfig{
			Enabled: true,
			Applier: applier,
		},
	})
	if err != nil {
		e, err = New(Config{
			Capture: capture.Config{Interfaces: []string{"lo0"}},
			Enforce: EnforceConfig{
				Enabled: true,
				Applier: applier,
			},
		})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}

	snap := rules.Snapshot{Version: "2", Default: rules.ActionAllow}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	if applier.ruleset == "" || applier.ruleset == "flush ruleset\n" {
		t.Fatalf("expected compiled ruleset to be applied")
	}
	if got := e.CurrentRules(); got == nil || got.Version != "2" {
		t.Fatalf("expected snapshot version 2 after apply, got %+v", got)
	}
}

func TestApplyRulesDoesNotSwapOnFailure(t *testing.T) {
	applier := &recordingApplier{err: context.DeadlineExceeded}
	e, err := New(Config{
		Capture: capture.Config{Interfaces: []string{"lo"}},
		Enforce: EnforceConfig{
			Enabled: true,
			Applier: applier,
		},
	})
	if err != nil {
		e, err = New(Config{
			Capture: capture.Config{Interfaces: []string{"lo0"}},
			Enforce: EnforceConfig{
				Enabled: true,
				Applier: applier,
			},
		})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	e.LoadRules(rules.Snapshot{Version: "1"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "bad"}); err == nil {
		t.Fatalf("expected apply error")
	}
	if got := e.CurrentRules(); got == nil || got.Version != "1" {
		t.Fatalf("expected snapshot to remain version 1, got %+v", got)
	}
}

type recordingUpdater struct {
	hostIP  string
	flowKey string
	ttl     time.Duration
}

func (r *recordingUpdater) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	r.hostIP = ip.To4().String()
	r.ttl = ttl
	return nil
}

func (r *recordingUpdater) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	r.flowKey = srcIP.To4().String() + "->" + dstIP.To4().String() + "/" + proto + ":" + dport
	r.ttl = ttl
	return nil
}

func TestApplyVerdictUsesUpdater(t *testing.T) {
	up := &recordingUpdater{}
	e, err := New(Config{
		Capture: capture.Config{Interfaces: []string{"lo"}},
		Enforce: EnforceConfig{
			Enabled: true,
			Updater: up,
		},
	})
	if err != nil {
		e, err = New(Config{
			Capture: capture.Config{Interfaces: []string{"lo0"}},
			Enforce: EnforceConfig{
				Enabled: true,
				Updater: up,
			},
		})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	flow := rules.EvalContext{
		SrcIP: net.ParseIP("10.0.0.1"),
		DstIP: net.ParseIP("10.0.0.2"),
		Proto: "tcp",
		Port:  "502",
	}
	v := verdict.Verdict{Action: verdict.BlockFlowTemp, TTL: 10 * time.Second}
	if err := e.ApplyVerdict(context.Background(), v, flow); err != nil {
		t.Fatalf("apply verdict: %v", err)
	}
	if up.flowKey == "" || up.ttl != 10*time.Second {
		t.Fatalf("expected updater to be called, got key=%q ttl=%s", up.flowKey, up.ttl)
	}
}

func TestRecordDPIEventsEmitsIDSAlert(t *testing.T) {
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"lo"}}})
	if err != nil {
		e, err = New(Config{Capture: capture.Config{Interfaces: []string{"lo0"}}})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	snap := rules.Snapshot{
		Version: "v1",
		IDS: rules.IDSConfig{
			Enabled: true,
			Rules: []rules.IDSRule{
				{
					ID:    "mb-write",
					Proto: "modbus",
					When: rules.IDSCondition{
						Field: "attr.is_write",
						Op:    "equals",
						Value: true,
					},
					Severity: "high",
				},
			},
		},
	}
	e.LoadRules(snap)
	state := flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 502,
		Proto:   6,
		Dir:     flow.DirForward,
	}, time.Now())
	evs := []dpi.Event{{
		FlowID: "f1",
		Proto:  "modbus",
		Kind:   "request",
		Attributes: map[string]any{
			"is_write": true,
		},
	}}
	e.RecordDPIEvents(state, &dpi.ParsedPacket{Proto: "tcp"}, evs)
	list := e.Events().List(10)
	foundAlert := false
	for _, ev := range list {
		if ev.Proto == "ids" && ev.Kind == "alert" {
			foundAlert = true
		}
	}
	if !foundAlert {
		t.Fatalf("expected ids alert in events, got %+v", list)
	}
}

func TestShouldInspectICSHeuristics(t *testing.T) {
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"lo"}}, DPIEnabled: true})
	if err != nil {
		e, err = New(Config{Capture: capture.Config{Interfaces: []string{"lo0"}}, DPIEnabled: true})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	snap := rules.Snapshot{
		Version: "v1",
		Firewall: []rules.Entry{
			{
				ID: "ics1",
				Protocols: []rules.Protocol{
					{Name: "tcp", Port: "502"},
				},
				ICS: rules.ICSPredicate{Protocol: "modbus"},
			},
		},
	}
	e.LoadRules(snap)
	state := flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 502,
		Proto:   6,
		Dir:     flow.DirForward,
	}, time.Now())
	if !e.ShouldInspect(state, &dpi.ParsedPacket{Proto: "tcp", SrcPort: 12345, DstPort: 502}) {
		t.Fatal("expected inspect for modbus port")
	}
	if e.ShouldInspect(state, &dpi.ParsedPacket{Proto: "tcp", SrcPort: 12345, DstPort: 80}) {
		t.Fatal("expected no inspect for non-ICS port")
	}
}
