package engine

import (
	"context"
	"sync/atomic"

	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/rules"
)

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	capture  *capture.Manager
	ruleSnap atomic.Pointer[rules.Snapshot]
	started  atomic.Bool
}

type Config struct {
	Capture capture.Config
}

func New(cfg Config) (*Engine, error) {
	capManager, err := capture.NewManager(cfg.Capture)
	if err != nil {
		return nil, err
	}
	e := &Engine{capture: capManager}
	return e, nil
}

func (e *Engine) Start(ctx context.Context) error {
	if e.started.Swap(true) {
		return nil
	}
	if err := e.capture.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (e *Engine) LoadRules(snap rules.Snapshot) {
	e.ruleSnap.Store(&snap)
}

func (e *Engine) CurrentRules() *rules.Snapshot {
	return e.ruleSnap.Load()
}

func (e *Engine) Interfaces() []string {
	return e.capture.Interfaces()
}

// Evaluate applies the current rule snapshot to a simple context.
func (e *Engine) Evaluate(ctx rules.EvalContext) rules.Action {
	snap := e.ruleSnap.Load()
	ev := rules.NewEvaluator(snap)
	return ev.Evaluate(ctx)
}
