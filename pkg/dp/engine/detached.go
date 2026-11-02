// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

// DetachedConfig contains inspection inputs, never live dataplane authority.
// Nil protocol maps enable all decoders, just as in Config. InspectAll is always
// enabled. ZoneAddresses is required; it must resolve the supplied topology
// without consulting host interfaces.
type DetachedConfig struct {
	Events          *events.Writer
	DPIProtocols    map[string]bool
	DPIICSProtocols map[string]bool
	DPIICSParsing   map[string]string
	DPIExclusions   []DPIExclusion
	ZoneAddresses   func(iface string) ([]net.Addr, error)
}

// Detached exposes only packet inspection and private detection state.
// Close cancels and joins Run and waits for in-flight publications. Callers
// serialize packet arrivals; policy, parsing and signature updates may overlap.
type Detached struct {
	engine *Engine
	mu     sync.RWMutex
	closed bool
	cancel context.CancelFunc
	done   chan struct{}
}

var errDetachedAuthority = errors.New("detached inspection has no host authority")

func NewDetached(cfg DetachedConfig) (*Detached, error) {
	if cfg.Events == nil || cfg.Events.Store() == nil || cfg.Events.Origin() != telemetry.OriginDemo {
		return nil, errors.New("detached inspection requires a demo-origin event writer")
	}
	if cfg.ZoneAddresses == nil {
		return nil, errors.New("detached inspection requires topology zone addresses")
	}
	exclusions := slices.Clone(cfg.DPIExclusions)
	// Deliberately do not call New: it constructs capture, transport and live
	// enforcement callbacks even in a non-enforcing configuration.
	e := &Engine{
		detached:        true,
		eventStore:      cfg.Events,
		inspectAll:      true,
		dpiEnabled:      true,
		dpiMode:         "monitor",
		dpiExclusions:   exclusions,
		exclusionHits:   newExclusionHits(exclusions),
		domains:         newDomainExclusions(exclusions),
		flows:           make(map[flow.MapKey]*flow.State),
		deniedTCPNow:    time.Now,
		verdictCache:    NewVerdictCache(30*time.Second, 65536),
		inventory:       inventory.New(),
		anomalyDetector: anomaly.New(),
		sigEngine:       signatures.New(),
		stats:           stats.New(),
		clearMarks: func(context.Context, uint32, uint32, uint32) (int, error) {
			return 0, errDetachedAuthority
		},
	}
	e.zones.addrsFor = cfg.ZoneAddresses
	e.verdictCache.detached = true
	e.SetICSParsing(cfg.DPIICSParsing)
	e.sigEngine.LoadBuiltins()
	e.counters.tracker.Store(e.stats)
	e.dpiMgr = dpi.NewManager(FilterDecoders(cfg.DPIProtocols, cfg.DPIICSProtocols)...)
	e.initIEC(Config{DPIMode: "monitor"})
	e.iec.ctDelete = func(context.Context, conntrack.DeleteRequest) error { return errDetachedAuthority }
	runID := newRunID()
	var seq atomic.Uint64
	e.iec.newID = func() string { return eventfields.SessionID(runID, seq.Add(1)) }
	return &Detached{engine: e}, nil
}

func (d *Detached) HandlePacket(pkt capture.Packet) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	// Copy only observational fields. A caller cannot smuggle inline tokens,
	// marks, conntrack metadata or a live publication-lock pin into this path.
	d.engine.HandlePacket(capture.Packet{
		Timestamp: pkt.Timestamp, Interface: pkt.Interface,
		SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort,
		IPVersion: pkt.IPVersion, PortsValid: pkt.PortsValid, Proto: pkt.Proto,
		Transport: pkt.Transport, Payload: pkt.Payload, TCP: pkt.TCP,
		Invalid: pkt.Invalid, CaptureIncomplete: pkt.CaptureIncomplete,
	})
}

// LoadRules refuses enforcement in depth: even an incorrectly derived caller
// snapshot is evaluated only in monitor mode. The caller's snapshot is immutable.
func (d *Detached) LoadRules(snap rules.Snapshot) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	snap.DPIMode = "monitor"
	snap.Firewall = slices.Clone(snap.Firewall)
	for i := range snap.Firewall {
		snap.Firewall[i].ICS.Mode = "monitor"
	}
	d.engine.LoadRules(snap)
}

func (d *Detached) SetICSParsing(modes map[string]string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.closed {
		d.engine.SetICSParsing(modes)
	}
}

// SetSignatures replaces the definitions, including builtins, as one packet
// policy generation. Definitions must remain immutable after publication.
func (d *Detached) SetSignatures(defs []signatures.Signature) {
	next := signatures.New()
	for _, def := range defs {
		next.Add(def)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.closed {
		d.engine.policyMu.Lock()
		d.engine.sigEngine = next
		d.engine.policyMu.Unlock()
	}
}

// Run drives only IEC session expiry; it returns after cancellation. At most
// one Run may be active. No capture, I/O worker or host watcher is started.
func (d *Detached) Run(ctx context.Context) {
	d.mu.Lock()
	if d.closed || d.done != nil {
		d.mu.Unlock()
		return
	}
	ctx, d.cancel = context.WithCancel(ctx)
	d.done = make(chan struct{})
	done := d.done
	d.mu.Unlock()
	d.engine.iec.run(ctx.Done())
	close(done)
}

func (d *Detached) Stats() *stats.Tracker { return d.engine.stats }

func (d *Detached) Close() {
	d.mu.Lock()
	d.closed = true
	done := d.done
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	if done != nil {
		<-done
	}
	d.engine.Close()
}
