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
	protoStats := e.ProtoStats()
	if len(protoStats) == 0 || protoStats[0].Protocol != "modbus" || protoStats[0].EventCount == 0 {
		t.Fatalf("expected modbus protocol stats, got %+v", protoStats)
	}
	assets := e.Inventory().List()
	if len(assets) != 2 {
		t.Fatalf("expected two inventory assets, got %+v", assets)
	}
}

func TestEnforceDPIEventsBlocksDeniedICSFlow(t *testing.T) {
	up := &recordingUpdater{}
	e, err := New(Config{
		Capture: capture.Config{Interfaces: []string{"lo"}},
		Enforce: EnforceConfig{
			Enabled: true,
			Updater: up,
		},
		DPIMode: "enforce",
	})
	if err != nil {
		e, err = New(Config{
			Capture: capture.Config{Interfaces: []string{"lo0"}},
			Enforce: EnforceConfig{
				Enabled: true,
				Updater: up,
			},
			DPIMode: "enforce",
		})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	snap := rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{
			{
				ID:           "deny-write",
				Sources:      []string{"10.0.0.1/32"},
				Destinations: []string{"10.0.0.2/32"},
				Protocols:    []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS: rules.ICSPredicate{
					Protocol:     "modbus",
					FunctionCode: []uint8{6},
					WriteOnly:    true,
				},
				Action: rules.ActionDeny,
				Log:    true,
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
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 12345, DstPort: 502}
	evs := []dpi.Event{{
		FlowID: "f-write",
		Proto:  "modbus",
		Kind:   "request",
		Attributes: map[string]any{
			"function_code": uint8(6),
			"unit_id":       uint8(1),
			"is_write":      true,
			"address":       uint16(1),
		},
		Timestamp: time.Now().UTC(),
	}}

	v, enforced := e.enforceDPIEvents(state, pkt, evs)
	if !enforced {
		t.Fatal("expected enforcement verdict")
	}
	if v.Action != verdict.BlockFlowTemp {
		t.Fatalf("expected block-flow verdict, got %s", v.Action)
	}
	if up.flowKey != "10.0.0.1->10.0.0.2/tcp:502" {
		t.Fatalf("unexpected blocked flow key %q", up.flowKey)
	}
	if up.ttl != dpiEnforceBlockTTL {
		t.Fatalf("ttl=%s want %s", up.ttl, dpiEnforceBlockTTL)
	}

	list := e.Events().List(10)
	foundRuleHit := false
	for _, ev := range list {
		if ev.Kind == "firewall.rule.hit" && ev.Attributes["ruleId"] == "deny-write" {
			foundRuleHit = true
			break
		}
	}
	if !foundRuleHit {
		t.Fatalf("expected firewall rule hit event, got %+v", list)
	}
}

func TestHandlePacketDoesNotLetEmptyTCPPacketSuppressLaterDPI(t *testing.T) {
	e, err := New(Config{
		Capture:    capture.Config{Interfaces: []string{"lo"}},
		DPIEnabled: true,
	})
	if err != nil {
		e, err = New(Config{
			Capture:    capture.Config{Interfaces: []string{"lo0"}},
			DPIEnabled: true,
		})
	}
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	e.LoadRules(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{
			{
				ID:        "inspect-modbus",
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS: rules.ICSPredicate{
					Protocol: "modbus",
				},
				Action: rules.ActionAllow,
			},
		},
	})

	base := capture.Packet{
		Timestamp: time.Now().UTC(),
		Interface: "lo",
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   42000,
		DstPort:   502,
		Proto:     6,
		Transport: "tcp",
	}
	e.handlePacket(base)
	e.handlePacket(capture.Packet{
		Timestamp: time.Now().UTC(),
		Interface: base.Interface,
		SrcIP:     base.SrcIP,
		DstIP:     base.DstIP,
		SrcPort:   base.SrcPort,
		DstPort:   base.DstPort,
		Proto:     base.Proto,
		Transport: base.Transport,
		Payload: []byte{
			0x00, 0x01,
			0x00, 0x00,
			0x00, 0x06,
			0x01,
			0x03,
			0x00, 0x00,
			0x00, 0x02,
		},
	})

	list := e.Events().List(10)
	found := false
	for _, ev := range list {
		if ev.Proto == "modbus" && ev.Kind == "request" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected modbus event after payload packet, got %+v", list)
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
