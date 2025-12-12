package engine

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/enforce"
	"github.com/containd/containd/pkg/dp/ics/modbus"
	"github.com/containd/containd/pkg/dp/rules"
	"github.com/containd/containd/pkg/dp/verdict"
)

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	capture  *capture.Manager
	ruleSnap atomic.Pointer[rules.Snapshot]
	started  atomic.Bool
	compiler *enforce.Compiler
	applier  enforce.Applier
	updater  enforce.Updater
	dpiMgr   *dpi.Manager
}

type EnforceConfig struct {
	Enabled   bool
	TableName string
	Applier   enforce.Applier
	Updater   enforce.Updater
}

type Config struct {
	Capture capture.Config
	Enforce EnforceConfig
}

func New(cfg Config) (*Engine, error) {
	capManager, err := capture.NewManager(cfg.Capture)
	if err != nil {
		return nil, err
	}
	e := &Engine{capture: capManager}
	e.dpiMgr = dpi.NewManager(modbus.NewDecoder())
	if cfg.Enforce.Enabled {
		comp := enforce.NewCompiler()
		if cfg.Enforce.TableName != "" {
			comp.TableName = cfg.Enforce.TableName
		}
		e.compiler = comp
		if cfg.Enforce.Applier != nil {
			e.applier = cfg.Enforce.Applier
		} else {
			e.applier = enforce.NewNftApplier()
		}
		if cfg.Enforce.Updater != nil {
			e.updater = cfg.Enforce.Updater
		} else {
			e.updater = enforce.NewNftUpdater(comp.TableName)
		}
	}
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

// ApplyRules compiles and applies a snapshot to nftables (when enabled) and atomically swaps it.
// If enforcement is disabled, it simply swaps the snapshot.
func (e *Engine) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	if e.compiler == nil {
		e.ruleSnap.Store(&snap)
		return nil
	}
	ruleset, err := e.compiler.CompileFirewall(&snap)
	if err != nil {
		return err
	}
	if e.applier == nil {
		return errors.New("no applier configured")
	}
	if err := e.applier.Apply(ctx, ruleset); err != nil {
		return err
	}
	e.ruleSnap.Store(&snap)
	return nil
}

func (e *Engine) CurrentRules() *rules.Snapshot {
	return e.ruleSnap.Load()
}

func (e *Engine) Interfaces() []string {
	return e.capture.Interfaces()
}

// DPI returns the selective DPI manager.
func (e *Engine) DPI() *dpi.Manager {
	return e.dpiMgr
}

// Evaluate applies the current rule snapshot to a simple context.
func (e *Engine) Evaluate(ctx rules.EvalContext) rules.Action {
	snap := e.ruleSnap.Load()
	ev := rules.NewEvaluator(snap)
	return ev.Evaluate(ctx)
}

// EvaluateVerdict returns a baseline verdict for the current snapshot.
// DPI/IDS paths will later override this for selective inspection policies.
func (e *Engine) EvaluateVerdict(ctx rules.EvalContext) verdict.Verdict {
	return verdict.FromRulesAction(e.Evaluate(ctx))
}

// ApplyVerdict applies a verdict to dynamic enforcement primitives when enabled.
// It is safe to call even when enforcement is disabled.
func (e *Engine) ApplyVerdict(ctx context.Context, v verdict.Verdict, flow rules.EvalContext) error {
	if e.updater == nil {
		return nil
	}
	switch v.Action {
	case verdict.BlockHostTemp:
		ip := flow.SrcIP
		if ip == nil {
			ip = flow.DstIP
		}
		return e.updater.BlockHostTemp(ctx, ip, v.TTL)
	case verdict.BlockFlowTemp:
		return e.updater.BlockFlowTemp(ctx, flow.SrcIP, flow.DstIP, flow.Proto, flow.Port, v.TTL)
	default:
		return nil
	}
}
