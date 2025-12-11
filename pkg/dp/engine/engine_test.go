package engine

import (
	"context"
	"testing"

	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/rules"
)

func TestEngineStartAndRules(t *testing.T) {
	// Use loopback for validation (may exist in most environments).
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"lo0"}}})
	if err != nil {
		t.Skipf("loopback interface not found or unavailable: %v", err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
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
