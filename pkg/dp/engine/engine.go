package engine

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/enforce"
	"github.com/containd/containd/pkg/dp/events"
	"github.com/containd/containd/pkg/dp/flow"
	"github.com/containd/containd/pkg/dp/ics/modbus"
	"github.com/containd/containd/pkg/dp/ids"
	"github.com/containd/containd/pkg/dp/itdpi"
	"github.com/containd/containd/pkg/dp/rules"
	"github.com/containd/containd/pkg/dp/verdict"
)

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	capture       *capture.Manager
	ruleSnap      atomic.Pointer[rules.Snapshot]
	started       atomic.Bool
	compiler      *enforce.Compiler
	applier       enforce.Applier
	updater       enforce.Updater
	dpiMgr        *dpi.Manager
	eventStore    *events.Store
	rulesetStatus atomic.Pointer[RulesetStatus]
	avSink        AVSink
}

// RulesetStatus captures the last compiled/applied ruleset and any error.
type RulesetStatus struct {
	Ruleset   string    `json:"ruleset"`
	AppliedAt time.Time `json:"appliedAt"`
	Error     string    `json:"error,omitempty"`
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
	e.eventStore = events.NewStore(4096)
	e.dpiMgr = dpi.NewManager(
		modbus.NewDecoder(),
		itdpi.NewDNSDecoder(),
		itdpi.NewTLSDecoder(),
		itdpi.NewHTTPDecoder(),
		itdpi.NewICSMarker(),
		itdpi.NewPortDetector(),
	)
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
	var compiled string
	var applyErr error

	if e.compiler != nil {
		compiled, applyErr = e.compiler.CompileFirewall(&snap)
		if applyErr != nil {
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
		if e.applier == nil {
			applyErr = errors.New("no applier configured")
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
		if applyErr = e.applier.Apply(ctx, compiled); applyErr != nil {
			e.setRulesetStatus(compiled, applyErr)
			return applyErr
		}
	}

	e.ruleSnap.Store(&snap)
	e.setRulesetStatus(compiled, nil)
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

// ShouldInspect returns true if this packet/flow should be sent through selective DPI.
// Phase-2 policy: any flow matching an ICS predicate or when native IDS is enabled.
// Steering is a no-op for now (capture always userspace in mock), but this keeps the hook stable.
func (e *Engine) ShouldInspect(state *flow.State, pkt *dpi.ParsedPacket) bool {
	if e == nil || pkt == nil {
		return false
	}
	snap := e.ruleSnap.Load()
	if snap == nil {
		return false
	}
	// If IDS is enabled, inspect everything for now (future: selective per IDS rule proto).
	if snap.IDS.Enabled {
		return true
	}
	if len(snap.Firewall) == 0 {
		return false
	}
	for _, entry := range snap.Firewall {
		if entry.ICS.Protocol == "" {
			continue
		}
		// If explicit protocols exist, require port match.
		if len(entry.Protocols) > 0 {
			for _, p := range entry.Protocols {
				if protocolPortMatches(entry, p, state, pkt) {
					return true
				}
			}
			continue
		}
		// Default port heuristics by ICS protocol.
		switch strings.ToLower(entry.ICS.Protocol) {
		case "modbus":
			if servicePort(state, pkt) == 502 {
				return true
			}
		}
	}
	return false
}

func protocolPortMatches(entry rules.Entry, p rules.Protocol, state *flow.State, pkt *dpi.ParsedPacket) bool {
	if p.Name != "" && !strings.EqualFold(p.Name, pkt.Proto) {
		return false
	}
	port := servicePort(state, pkt)
	if p.Port == "" {
		// Any port for that transport.
		return true
	}
	min, max, ok := parsePortRange(p.Port)
	if !ok {
		return false
	}
	return port >= min && port <= max
}

func servicePort(state *flow.State, pkt *dpi.ParsedPacket) uint16 {
	if state != nil && state.Key.Dir == flow.DirReverse {
		return pkt.SrcPort
	}
	return pkt.DstPort
}

func parsePortRange(s string) (uint16, uint16, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	if !strings.Contains(s, "-") {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 65535 {
			return 0, 0, false
		}
		u := uint16(v)
		return u, u, true
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 0 || hi < 0 || lo > 65535 || hi > 65535 {
		return 0, 0, false
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return uint16(lo), uint16(hi), true
}

// RecordDPIEvents appends events to the telemetry store.
func (e *Engine) RecordDPIEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if e == nil || e.eventStore == nil {
		return
	}
	for i := range evs {
		evs[i] = itdpi.MarkICS(evs[i])
	}
	// Push HTTP previews to AV sink (if configured).
	if e.avSink != nil {
		src, dst := srcDestStrings(state)
		for _, ev := range evs {
			if ev.Proto != "http" {
				continue
			}
			if ev.Kind != "request" && ev.Kind != "response" {
				continue
			}
			preview, _ := ev.Attributes["preview"].([]byte)
			hash, _ := ev.Attributes["hash"].(string)
			if len(preview) == 0 {
				continue
			}
			ics := isICSEvent(ev.Proto, ev.Kind)
			task := AVScanTask{
				Hash:      hash,
				Direction: ev.Kind,
				Proto:     "http",
				Source:    src,
				Dest:      dst,
				FlowID:    ev.FlowID,
				Preview:   preview,
				ICS:       ics,
			}
			e.avSink.EnqueueAVScan(context.Background(), task)
			// Drop preview from telemetry to avoid large payloads.
			delete(ev.Attributes, "preview")
		}
	}
	e.eventStore.Record(state, pkt, evs)
	// Evaluate IDS rules over DPI events and record alerts.
	snap := e.ruleSnap.Load()
	if snap != nil && snap.IDS.Enabled && len(snap.IDS.Rules) > 0 {
		eval := ids.New(snap.IDS)
		var alerts []dpi.Event
		for _, ev := range evs {
			alerts = append(alerts, eval.Evaluate(ev)...)
		}
		if len(alerts) > 0 {
			e.eventStore.Record(state, pkt, alerts)
		}
	}
}

// Events returns the telemetry event store.
func (e *Engine) Events() *events.Store {
	return e.eventStore
}

// AVSink returns the currently configured AV sink, if any.
func (e *Engine) AVSink() AVSink {
	if e == nil {
		return nil
	}
	return e.avSink
}

// Updater returns the dynamic nftables updater when enforcement is enabled.
func (e *Engine) Updater() enforce.Updater {
	if e == nil {
		return nil
	}
	return e.updater
}

func isICSEvent(proto, kind string) bool {
	switch strings.ToLower(proto) {
	case "modbus", "dnp3", "iec104", "s7", "ics":
		return true
	}
	_ = kind
	return false
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

// RulesetStatus returns the last compiled/applied nftables ruleset snapshot.
func (e *Engine) RulesetStatus() RulesetStatus {
	if e == nil {
		return RulesetStatus{}
	}
	ptr := e.rulesetStatus.Load()
	if ptr == nil {
		return RulesetStatus{}
	}
	return *ptr
}

func (e *Engine) setRulesetStatus(ruleset string, err error) {
	st := &RulesetStatus{
		Ruleset:   ruleset,
		AppliedAt: time.Now().UTC(),
	}
	if err != nil {
		st.Error = err.Error()
	}
	e.rulesetStatus.Store(st)
}
