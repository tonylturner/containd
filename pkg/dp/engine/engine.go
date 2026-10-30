// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"container/list"
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

var startNFLog = capture.StartNFLog

type captureRunner interface {
	Start(context.Context, capture.Handler) error
	Stop()
	Interfaces() []string
	Settler() capture.Settler
}

// Engine coordinates capture and rule enforcement components.
type Engine struct {
	managementReservation *mgmtpath.Reservation
	engineAPI             *enforce.EngineAPIPath
	capture               captureRunner
	runCapture            captureRunner
	runCancel             context.CancelFunc
	runDone               chan struct{}
	ruleSnap              ruleSnapshots
	zones                 zoneCache // outlives Reconfigure, as the namespace does
	started               atomic.Bool
	epoch                 atomic.Uint64 // counts Reconfigure calls; ends stale start retries
	compiler              *enforce.Compiler
	applier               enforce.Applier
	updater               enforce.Updater
	dpiMgr                *dpi.Manager
	eventStore            *events.Store
	rulesetStatus         atomic.Pointer[RulesetStatus]
	inspectAll            bool
	dpiEnabled            bool // master DPI on/off
	icsParsing            atomic.Pointer[map[string]string]
	conformance           conformanceAlerts
	dpiMode               string            // "learn" or "enforce"
	dpiExclusions         []DPIExclusion    // IPs/domains excluded from DPI
	exclusionHits         *exclusionHits    // flows each exclusion exempted since the last apply
	coverage              coverage.Settings // static coverage inputs of this configuration
	nflogGroup            uint16            // 0 disables nflog consumer + log clauses
	nflogStop             func()            // stops the running nflog consumer; nil before Start or after disable
	onError               func(error)
	nfqueueGroup          uint16     // 0 disables NFQUEUE consumer + queue verdicts on dpiEligible rules
	lifecycleMu           sync.Mutex // serializes Start, Reconfigure and ApplyRules
	flowMu                sync.Mutex
	flows                 map[string]*flow.State
	deniedTCP             map[string]*deniedTCP
	deniedTCPOrder        list.List // oldest first; protected by flowMu
	deniedTCPNow          func() time.Time
	tcpISNs               map[string]uint32
	tcpDecisions          [256]sync.Mutex
	lastSweep             time.Time
	verdictCache          *VerdictCache
	inventory             *inventory.Inventory
	anomalyDetector       *anomaly.Detector
	learner               *learn.Learner
	sigEngine             *signatures.Engine
	stats                 *stats.Tracker
	hooks                 *inlineHooks
	iec                   *iecTable
	gate                  *envelopeGate // outlives Reconfigure, as the kernel ruleset does
	// gateAdmit is the admission state of the scanning gate (scan_admit.go):
	// written by SetGateAdmit and into every applied ruleset, under
	// lifecycleMu. It outlives Reconfigure, as the kernel ruleset does.
	gateAdmit          enforce.GateAdmitState
	domains            *domainExclusions
	observation        *liveObserver
	observationPending []observationRecord // finalized under flowMu; recorded after unlocking
	transport          *transportResolver
	wireSerial         uint64                             // under flowMu; never reset during Reconfigure
	transportISNs      map[string]uint32                  // raw capture incarnation hints, not deny tombstones
	transportCoverage  map[*flow.State]*transportCoverage // under flowMu; fields under admissionMu
}

// RulesetStatus describes the installed ruleset: its compiled text,
// snapshot version, apply time and warnings (enforce.RuleWarnings), which a
// failed apply leaves in place, as it leaves the ruleset installed. Error,
// FailedSnapshotVersion and FailedAt describe the last apply when it
// failed; the next successful apply clears them. ICSCoverage is the live
// coverage of the ICS rules in force (none before the first success, never
// a failed snapshot's); omitted when there are none. SchedulePlanner is the
// schedule planner's state for the installed ruleset; omitted when it has
// no scheduled rule.
type RulesetStatus struct {
	Ruleset               string                `json:"ruleset"`
	SnapshotVersion       string                `json:"snapshotVersion,omitempty"`
	AppliedAt             time.Time             `json:"appliedAt"`
	Error                 string                `json:"error,omitempty"`
	FailedSnapshotVersion string                `json:"failedSnapshotVersion,omitempty"`
	FailedAt              *time.Time            `json:"failedAt,omitempty"`
	Warnings              []enforce.RuleWarning `json:"warnings,omitempty"`
	ICSCoverage           []coverage.Rule       `json:"icsCoverage,omitempty"`
	SchedulePlanner       *SchedulePlan         `json:"schedulePlanner,omitempty"`
	TransportIdentity     *TransportStatus      `json:"transportIdentity,omitempty"`
}

type EnforceConfig struct {
	ManagementReservation *mgmtpath.Reservation
	// EngineAPI is the process's non-loopback engine API path, if any.
	EngineAPI *enforce.EngineAPIPath
	Enabled   bool
	TableName string
	// GatePlainPort and GateMasqPort are the scanning gate's loopback
	// listener ports (enforce.CompilerSettings); both zero compiles no
	// gate. The application passes the same values to preview.
	GatePlainPort uint16
	GateMasqPort  uint16
	Applier       enforce.Applier
	Updater       enforce.Updater
}

type Config struct {
	Capture capture.Config
	// Events is shared by every configuration of a live engine. Nil allocates
	// a private 4096-event store for a standalone engine.
	Events *events.Store
	// OnError is the fallback for capture errors and also receives non-fatal NFLOG registration errors.
	OnError         func(error)
	Enforce         EnforceConfig
	InspectAll      bool
	DPIEnabled      bool              // master DPI toggle
	DPIMode         string            // "learn" or "enforce"
	DPIProtocols    map[string]bool   // per-IT-protocol enable/disable
	DPIICSProtocols map[string]bool   // per-ICS-protocol enable/disable
	DPIICSParsing   map[string]string // per-ICS-protocol tolerant/strict policy
	DPIExclusions   []DPIExclusion    // IPs/domains excluded from DPI
	// NFLogGroup, when non-zero, enables kernel-side logging for rules
	// with Log:true via nftables `log group <N>` and starts a userspace
	// nflog consumer that translates each logged packet into a
	// firewall.rule.hit event in the engine's event store. Zero disables
	// (no log clause emitted, no consumer started).
	NFLogGroup uint16

	// NFQueueGroup, when non-zero, enables NFQUEUE-based DPI enforcement
	// for dpiEligible rules. The compiler queues the traffic of rules with
	// an ICS predicate to queue <N> instead of accepting or dropping it
	// (through enforce.ICSQueueChain, or enforce.IEC104EnvelopeChain for
	// IEC104 rules), and the capture manager runs an NFQUEUE consumer at
	// that group. Zero disables
	// (ICS rules fall back to plain accept/drop with no function-code
	// inspection, so management validation refuses ICS rules in enforce
	// mode). See config.DataPlaneConfig.NFQueueGroup
	// for full rationale.
	NFQueueGroup uint16

	// ResetInjector sends the IEC104 abort resets. Nil opens the platform
	// injector when NFQueueGroup is set.
	ResetInjector session.Injector
}

// DPIExclusion represents an IP, CIDR, or domain excluded from DPI.
type DPIExclusion struct {
	Value string
	Type  string // "ip", "cidr", "domain"
}

func New(cfg Config) (*Engine, error) {
	if cfg.Enforce.ManagementReservation != nil && !cfg.Enforce.Enabled {
		return nil, fmt.Errorf("dataplane.enforcement=false conflicts with reserved management path")
	}
	if cfg.Capture.OnError == nil {
		cfg.Capture.OnError = cfg.OnError
	}
	// If NFQueueGroup is set, drive the capture manager via NFQUEUE
	// rather than AFPACKET. This pairs with the compiler queueing the
	// traffic of dpiEligible rules to NFQueueGroup (below), so ICS-flagged
	// packets land in handlePacket where the
	// DPI decoders + enforceDPIEvents can apply function-code-level
	// verdicts. Explicit NFQUEUE config overrides any inherited Mode.
	if cfg.NFQueueGroup != 0 {
		cfg.Capture.Mode = "nfqueue"
		cfg.Capture.QueueID = int(cfg.NFQueueGroup)
	}
	hooks := newInlineHooks(cfg.OnError)
	cfg.Capture.OnVerdict = hooks.onVerdict
	cfg.Capture.OnSource = hooks.onSource
	capManager, err := capture.NewManager(cfg.Capture)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		managementReservation: cfg.Enforce.ManagementReservation,
		engineAPI:             cfg.Enforce.EngineAPI,
		capture:               capManager,
		onError:               cfg.OnError,
		inspectAll:            cfg.InspectAll,
		dpiEnabled:            cfg.DPIEnabled,
		dpiMode:               cfg.DPIMode,
		dpiExclusions:         cfg.DPIExclusions,
		exclusionHits:         newExclusionHits(cfg.DPIExclusions),
		coverage:              coverageSettings(cfg),
		domains:               newDomainExclusions(cfg.DPIExclusions),
		nflogGroup:            cfg.NFLogGroup,
		nfqueueGroup:          cfg.NFQueueGroup,
		flows:                 make(map[string]*flow.State),
		deniedTCPNow:          time.Now,
		verdictCache:          NewVerdictCache(30*time.Second, 65536),
		hooks:                 hooks,
	}
	e.SetICSParsing(cfg.DPIICSParsing)
	e.inventory = inventory.New()
	e.anomalyDetector = anomaly.New()
	e.learner = learn.New()
	e.sigEngine = signatures.New()
	e.sigEngine.LoadBuiltins()
	e.stats = stats.New()
	e.eventStore = cfg.Events
	if e.eventStore == nil {
		e.eventStore = events.NewStore(4096)
	}
	e.dpiMgr = dpi.NewManager(FilterDecoders(cfg.DPIProtocols, cfg.DPIICSProtocols)...)
	e.initIEC(cfg, capManager)
	e.gate = &envelopeGate{}
	e.bindGate()
	if cfg.Enforce.Enabled {
		comp := enforce.NewCompilerWithSettings(enforce.CompilerSettings{
			TableName: cfg.Enforce.TableName, NFLogGroup: cfg.NFLogGroup, NFQueueGroup: cfg.NFQueueGroup,
			GatePlainPort: cfg.Enforce.GatePlainPort, GateMasqPort: cfg.Enforce.GateMasqPort,
		}, e.managementReservation)
		comp.EngineAPI = e.engineAPI
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
	if err := e.initTransport(cfg); err != nil {
		return nil, err
	}
	if e.transport != nil {
		e.observation, err = newLiveObserver(cfg)
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Reconfigure replaces the engine's internal state from a freshly created
// engine without copying atomic or mutex fields (which are not safe to copy).
// fresh must be constructed with Config.Events set to e.Events(): IEC104
// callbacks bind to that store at construction, and the store is never swapped.
//
// Reconfigure returns only after the previous data-plane run has stopped,
// including its capture consumers and nflog socket, so the following Start
// cannot overlap the old run.
// The lifecycle lock serializes the full swap/stop with Start: if Reconfigure
// finishes before a queued Start runs, that Start binds the latest state and
// later Start calls see the engine as already started.
//
// When fresh does not enforce, Reconfigure first deletes the nft tables this
// engine installed, so the kernel stops enforcing too, and the ruleset status
// stops describing them. If that fails it returns the error and changes
// nothing.
func (e *Engine) Reconfigure(fresh *Engine) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if fresh.compiler == nil {
		if err := e.gate.release(); err != nil {
			return fmt.Errorf("remove enforcement tables: %w", err)
		}
		e.releaseRulesetStatus()
	}

	prevCancel := e.runCancel
	prevCapture := e.runCapture
	e.flowMu.Lock()
	prevNflogStop := e.nflogStop
	e.nflogStop = nil
	e.flowMu.Unlock()
	prevRunDone := e.runDone
	prevIEC := e.iec
	if prevCapture != nil {
		prevCapture.Stop()
	}
	// Closing an inline queue invokes OnSourceDown, which schedules IEC
	// session resets on the old worker. Keep it alive until those callbacks
	// and their reset jobs have completed; otherwise cancellation can discard
	// the resets while Reconfigure replaces the session table.
	if prevIEC != nil && prevIEC.jobs != nil && prevRunDone != nil {
		prevIEC.jobs.flush(prevRunDone)
	}
	if prevCancel != nil {
		prevCancel()
	}
	if prevNflogStop != nil {
		prevNflogStop()
	}
	if prevRunDone != nil {
		<-prevRunDone
	}
	if prevIEC != nil {
		prevIEC.stopInventory()
	}
	e.runCancel = nil
	e.runCapture = nil
	e.runDone = nil

	e.flowMu.Lock()
	observationRecords := e.observationPending
	e.observationPending = nil
	if e.observation != nil {
		observationRecords = append(observationRecords, e.observation.records(e.observation.observer.Drain())...)
		e.observation.syncMetrics()
	}
	e.observation = fresh.observation
	e.capture = fresh.capture
	e.compiler = fresh.compiler
	if e.compiler != nil {
		e.compiler.ManagementReservation = e.managementReservation
		e.compiler.EngineAPI = e.engineAPI
	}
	e.applier = fresh.applier
	e.transport = fresh.transport
	e.updater = fresh.updater
	e.dpiMgr = fresh.dpiMgr
	e.inventory = fresh.inventory
	e.anomalyDetector = fresh.anomalyDetector
	e.sigEngine = fresh.sigEngine
	e.stats = fresh.stats
	e.inspectAll = fresh.inspectAll
	e.dpiEnabled = fresh.dpiEnabled
	e.dpiMode = fresh.dpiMode
	e.icsParsing.Store(fresh.icsParsing.Load())
	e.conformance.clear()
	e.dpiExclusions = fresh.dpiExclusions
	e.exclusionHits = fresh.exclusionHits
	e.coverage = fresh.coverage
	e.domains = fresh.domains
	e.nflogGroup = fresh.nflogGroup
	e.nfqueueGroup = fresh.nfqueueGroup
	e.onError = fresh.onError
	e.flows = fresh.flows
	e.tcpISNs = fresh.tcpISNs
	e.transportISNs = fresh.transportISNs
	e.transportCoverage = fresh.transportCoverage
	e.lastSweep = fresh.lastSweep
	e.verdictCache = fresh.verdictCache
	e.hooks = fresh.hooks
	fresh.iec.zones = &e.zones
	e.iec = fresh.iec
	e.flowMu.Unlock()
	e.recordObservations(observationRecords)
	e.epoch.Add(1)
	e.started.Store(false)
	// The old queue is closed and the new one is not bound yet: the
	// envelope drops until the new run binds.
	e.bindGate()
	e.gate.own(0)
	// The fresh table enforces the loaded rules at once; sessions of the
	// old run are unknown to it and are reset once.
	if snap := e.ruleSnap.Load(); snap != nil {
		e.iec.setPolicy(snap)
	}
	if prevIEC != nil && prevIEC.injector != nil && prevIEC.injector != e.iec.injector {
		_ = prevIEC.injector.Close()
	}
	return nil
}

func (e *Engine) Start(ctx context.Context) error {
	_, err := e.start(ctx)
	return err
}

// start is Start; it also returns the NFQUEUE group of the configuration
// it started, read under the lifecycle lock.
func (e *Engine) start(ctx context.Context) (uint16, error) {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	group := e.nfqueueGroup

	if e.started.Swap(true) {
		return group, nil
	}
	runCtx, runCancel := context.WithCancel(ctx)
	runCapture := e.capture
	e.runCancel = runCancel
	e.runCapture = runCapture
	handler := e.HandlePacket
	var transportDone chan struct{}
	if e.transport != nil {
		r := e.transport
		r.admissionMu.Lock()
		r.closed = false
		r.admissionMu.Unlock()
		transportDone = make(chan struct{})
		go func() { defer close(transportDone); r.run(runCtx, e) }()
		handler = func(pkt capture.Packet) capture.Decision { return r.admit(e, pkt) }
	}
	if err := runCapture.Start(runCtx, handler); err != nil {
		if e.nfqueueGroup != 0 {
			e.iec.health.fault(faultQueue, "queue bind: "+err.Error())
			e.gate.own(0)
		}
		runCancel()
		if transportDone != nil {
			<-transportDone
		}
		e.runCancel = nil
		e.runCapture = nil
		e.started.Store(false)
		return group, err
	}
	if group != 0 {
		// Start returned nil: the queue is bound and registered.
		e.gate.own(group)
	}
	// Start the nflog consumer if configured. This produces
	// firewall.rule.hit events for L4 (non-DPI) rules with Log:true. A
	// failure here is non-fatal — log it via the rules-event log so the
	// admin can see "nflog unavailable" without taking down the rest of
	// the engine. Common cause: container lacks NET_ADMIN cap; in that
	// case the kernel log clause still fires but the userspace consumer
	// just won't translate the packets into events.
	if e.nflogGroup != 0 && e.eventStore != nil {
		stop, err := startNFLog(runCtx, e.nflogGroup, nflogRuleHits{e}, func(perr error) {
			// Per-packet hook errors — drop. Surface only at debug.
			_ = perr
		})
		if err != nil {
			e.flowMu.Lock()
			e.nflogStop = nil
			e.flowMu.Unlock()
			// Surface as a system event so it's visible in /api/v1/events.
			e.eventStore.Append(events.Event{
				Kind:      "service.nflog.unavailable",
				Timestamp: time.Now().UTC(),
				Attributes: map[string]any{
					"group": int(e.nflogGroup),
					"error": err.Error(),
				},
			})
			if e.onError != nil {
				e.onError(fmt.Errorf("nflog group %d unavailable: %w", e.nflogGroup, err))
			}
		} else {
			e.flowMu.Lock()
			e.nflogStop = stop
			e.flowMu.Unlock()
		}
	}
	runDone := make(chan struct{})
	e.runDone = runDone
	var run sync.WaitGroup
	run.Add(5)
	go func() {
		defer run.Done()
		e.hooks.blocks.run(runCtx)
	}()
	onError := e.onError
	go func() {
		defer run.Done()
		e.runSchedulePlanner(runCtx, onError)
	}()
	go func() {
		defer run.Done()
		e.iec.run(runCtx.Done())
	}()
	go func() {
		defer run.Done()
		e.zones.watch(runCtx, onError)
	}()
	// Periodically update the active goroutine gauge.
	go func() {
		defer run.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				metrics.GoroutinesActive.Set(float64(runtime.NumGoroutine()))
			}
		}
	}()
	go func() {
		run.Wait()
		if transportDone != nil {
			<-transportDone
		}
		close(runDone)
	}()
	return group, nil
}

func (e *Engine) LoadRules(snap rules.Snapshot) {
	e.ruleSnap.Store(&snap)
	e.iec.setPolicy(&snap)
}

// ApplyRules compiles and applies a snapshot to nftables (when enabled) and atomically swaps it.
// If enforcement is disabled, it simply swaps the snapshot.
func (e *Engine) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	if err := snap.ValidateIndustrialProtocols(); err != nil {
		return err
	}
	if err := snap.Gate.Validate(); err != nil {
		return err
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	if err := enforce.ValidateManagementSnapshot(&snap, e.managementReservation); err != nil {
		return err
	}
	var compiled string
	var warnings []enforce.RuleWarning

	if e.compiler != nil {
		start := time.Now()
		var err error
		e.compiler.GateAdmit = e.gateAdmit
		if compiled, err = e.gate.apply(ctx, e.compiler, e.applier, &snap); err != nil {
			e.recordApplyFailure(snap.Version, err)
			return err
		}
		metrics.NFTablesApplyDuration.Observe(time.Since(start).Seconds())
		warnings = e.compiler.RuleWarnings(&snap)
	}

	e.ruleSnap.Store(&snap)
	e.iec.setPolicy(&snap)
	metrics.RulesCount.Set(float64(len(snap.Firewall)))
	e.rulesetStatus.Store(&RulesetStatus{Ruleset: compiled, SnapshotVersion: snap.Version, AppliedAt: time.Now().UTC(), Warnings: warnings})
	e.resetExclusionHits()
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
	if !e.dpiInspectionEnabled(state) {
		return false
	}
	if e.inspectAll {
		return true
	}
	snap := e.ruleSnap.Load()
	if !shouldInspectWithSnapshot(snap) {
		return false
	}
	if snap.IDS.Enabled {
		return true
	}
	for _, entry := range snap.Firewall {
		if shouldInspectFirewallEntry(entry, state, pkt) {
			return true
		}
	}
	return false
}

func (e *Engine) dpiInspectionEnabled(state *flow.State) bool {
	// Master DPI toggle — when explicitly disabled, skip DPI entirely.
	// Note: inspectAll (DPIMock/lab mode) overrides this for testing.
	if !e.dpiEnabled && !e.inspectAll {
		return false
	}
	if len(e.dpiExclusions) > 0 && state != nil && e.isExcluded(state) {
		return false
	}
	return true
}

func shouldInspectWithSnapshot(snap *rules.Snapshot) bool {
	return snap != nil && len(snap.Firewall) > 0 || (snap != nil && snap.IDS.Enabled)
}

func shouldInspectFirewallEntry(entry rules.Entry, state *flow.State, pkt *dpi.ParsedPacket) bool {
	if entry.ICS.Protocol == "" {
		return false
	}
	if len(entry.Protocols) > 0 {
		return entryMatchesProtocolPorts(entry, state, pkt)
	}
	return ics.IsProtocolPortOn(entry.ICS.Protocol, state.Key.Proto, servicePort(state, pkt))
}

func entryMatchesProtocolPorts(entry rules.Entry, state *flow.State, pkt *dpi.ParsedPacket) bool {
	for _, p := range entry.Protocols {
		if protocolPortMatches(entry, p, state, pkt) {
			return true
		}
	}
	return false
}

// handlePacket runs flow tracking, DPI and enforcement for one captured
// packet and decides it.
func (e *Engine) handlePacket(pkt capture.Packet) capture.Decision {
	return e.handlePacketConnection(pkt, nil, nil)
}

func (e *Engine) handlePacketConnection(pkt capture.Packet, connection *flow.Connection, history *transportAdmission) capture.Decision {
	if e == nil {
		return acceptDecision
	}
	metrics.PacketsTotal.Inc()
	metrics.BytesTotal.Add(float64(len(pkt.Payload)))
	if pkt.Invalid != "" {
		return invalidPacketDecision(pkt)
	}
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	defer e.lockGenericTCP(pkt)()
	e.reopenDeniedTCP(pkt)
	e.retireTransportIncarnation(pkt, connection)
	state := e.trackFlow(pkt, now)
	if state == nil {
		return acceptDecision
	}
	e.bindTransport(state, connection)
	if connection != nil && e.transport != nil {
		e.transport.trackConnection(state, now, history)
		e.flowMu.Lock()
		e.transport.admissionMu.Lock()
		e.bindDecodeCoverageLocked(state, history)
		e.transport.admissionMu.Unlock()
		e.flowMu.Unlock()
	}
	stopped := e.applyDecodeCoverage(state, pkt)
	if e.observation != nil && !stopped {
		e.observePacket(pkt, state)
	}
	if d, ok := e.handleIECPacket(pkt, state); ok {
		return d
	}
	return e.handleFlowPacket(pkt, state, connection != nil || e.transport == nil)
}

// trackFlow returns the state of the packet's connection direction. Each
// direction of a connection has its own state, keyed by its wire tuple,
// whose Key.Dir records whether its sender opened the connection
// (DirForward) or accepted it (DirReverse).
func (e *Engine) trackFlow(pkt capture.Packet, now time.Time) *flow.State {
	e.flowMu.Lock()
	state, forgotten := e.connectionStateLocked(pkt, now)
	state.Touch(uint64(len(pkt.Payload)), now)
	if state.Packets == 1 && state.Key.Dir == flow.DirForward {
		e.countAddressExclusionLocked(state)
	}
	// Only check if sweep is due under the existing lock; do the actual
	// sweep outside the critical path if needed.
	needsSweep := now.Sub(e.lastSweep) >= 30*time.Second
	if needsSweep {
		e.lastSweep = now
	}
	e.flowMu.Unlock()

	// End the forgotten connection's streams before this packet starts the
	// new one.
	for _, st := range forgotten {
		e.endFlowStream(st, nil)
	}
	if needsSweep {
		e.sweepFlows(now)
	}
	return state
}

// connectionStateLocked finds or creates the direction state for pkt. A
// SYN marks its sender as the opener and a SYN-ACK as the server; without
// a handshake, the opposite direction or a known ICS service port orients
// it. Ambiguous or unknown ports retain first-seen orientation. When the
// handshake contradicts the recorded orientation, the states of the old
// connection are forgotten and returned, for the caller to end their
// streams once it releases e.flowMu. Must be called with e.flowMu held.
func (e *Engine) connectionStateLocked(pkt capture.Packet, now time.Time) (*flow.State, []*flow.State) {
	key := flow.Key{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
	}
	hint, hinted := handshakeDirection(pkt)
	var forgotten []*flow.State
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		key.Dir = dir
		state, ok := e.flows[key.Hash()]
		if !ok {
			continue
		}
		if !hinted || hint == dir {
			return state, nil
		}
		// The handshake contradicts the recorded orientation: the tuple
		// carries a new connection. Forget both of the old directions.
		for _, old := range []flow.Key{key, key.Reversed()} {
			if st := e.dropFlowLocked(old); st != nil {
				forgotten = append(forgotten, st)
			}
		}
		break
	}

	key.Dir = flow.DirForward
	if hinted {
		key.Dir = hint
	} else {
		opposite := key.Reversed()
		opposite.Dir = flow.DirForward
		if _, ok := e.flows[opposite.Hash()]; ok {
			key.Dir = flow.DirReverse
		} else {
			opposite.Dir = flow.DirReverse
			if _, ok := e.flows[opposite.Hash()]; !ok {
				if dir, known := icsServiceDirection(pkt); known {
					key.Dir = dir
				}
			}
		}
	}
	state := flow.NewState(key, now)
	state.IdleTimeout = 5 * time.Minute
	state.Tags = e.flowTags(key)
	e.flows[key.Hash()] = state
	e.noteTransportSYNLocked(pkt, key)
	if pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0 && handshakeMarked(pkt) {
		if e.tcpISNs == nil {
			e.tcpISNs = make(map[string]uint32)
		}
		e.tcpISNs[key.Hash()] = pkt.TCP.Seq
	}
	metrics.FlowsActive.Inc()
	return state, forgotten
}

// handshakeDirection reports the direction a TCP handshake segment
// proves: a SYN comes from the opener, a SYN-ACK from the server.
func handshakeDirection(pkt capture.Packet) (flow.Direction, bool) {
	if pkt.Proto != 6 || pkt.TCP.Flags&capture.TCPFlagSYN == 0 {
		return flow.DirForward, false
	}
	if pkt.TCP.Flags&capture.TCPFlagACK != 0 {
		return flow.DirReverse, true
	}
	return flow.DirForward, true
}

// dropFlowLocked forgets the state of key and returns it, nil when there
// is none. The caller ends its stream: normally outside flowMu, but denial
// retirement tears down streams atomically under that lock before exposing an
// unguarded tuple. sweepFlows ends idle streams too. Requires e.flowMu held.
func (e *Engine) dropFlowLocked(key flow.Key) *flow.State {
	hash := key.Hash()
	st, ok := e.flows[hash]
	if !ok {
		return nil
	}
	e.releaseObservationLocked(st)
	delete(e.flows, hash)
	delete(e.tcpISNs, hash)
	delete(e.transportISNs, hash)
	delete(e.transportCoverage, st)
	metrics.FlowsActive.Dec()
	return st
}

func (e *Engine) sweepFlows(now time.Time) {
	e.expireDeniedTCP(now)
	var expired []*flow.State
	e.flowMu.Lock()
	for k, st := range e.flows {
		if st == nil || st.Expired(now) {
			if st != nil {
				e.releaseObservationLocked(st)
			}
			delete(e.flows, k)
			delete(e.tcpISNs, k)
			delete(e.transportISNs, k)
			delete(e.transportCoverage, st)
			metrics.FlowsActive.Dec()
			if st != nil {
				expired = append(expired, st)
			}
		}
	}
	var observationRecords []observationRecord
	if e.observation != nil {
		output := e.observation.observer.Sweep(e.observation.now())
		e.settleObservationsLocked(output)
		observationRecords = e.observation.records(output)
		e.observation.syncMetrics()
	}
	observationRecords = append(observationRecords, e.observationPending...)
	e.observationPending = nil
	e.flowMu.Unlock()
	e.recordObservations(observationRecords)
	for _, st := range expired {
		e.endFlowStream(st, nil)
	}
	if e.transport != nil {
		e.transport.sweepAdmission(now)
	}
}

// ManagementReservation is trusted startup authority, never accepted in payloads.
func (e *Engine) ManagementReservation() *mgmtpath.Reservation { return e.managementReservation }
