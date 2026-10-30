// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/observe"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// liveObserver is engine-owned. All access is under flowMu, including the pure
// callbacks invoked under Observer's mutex. No callback acquires another lock.
type liveObserver struct {
	observer *observe.Observer
	entries  map[identify.Key]*observationContext
	now      func() time.Time
	last     observe.Snapshot
}

type observationContext struct {
	states   [2]*flow.State
	legacy   *dpi.Manager
	selected bool
	iecOwned bool
	framer   string // actual/prospective port-selected TCP owner, not every supporting decoder
	snapshot *rules.Snapshot
	refused  bool // Open is attempted only once, including at capacity.
	// The table can retain legacy connection evidence across tuple reuse.
	// Passive incarnation retirement must remember the latest generation
	// independently, without rewriting that legacy evidence.
	generation *conntrack.Evidence
}

type observationRecord struct {
	state  *flow.State
	events []dpi.Event
}

func newLiveObserver(cfg Config) (*liveObserver, error) {
	var decoders []dpi.StreamDecoder
	protocols := make([]identify.Protocol, 0, 4)
	for _, d := range FilterDecoders(nil, cfg.DPIICSProtocols) {
		if sd, ok := d.(dpi.StreamDecoder); ok && ics.Supported(sd.Protocol()) {
			decoders = append(decoders, sd)
			protocols = append(protocols, identify.Protocol(sd.Protocol()))
		}
	}
	manager, err := dpi.NewObservationManager(decoders...)
	if err != nil {
		return nil, err
	}
	live := &liveObserver{entries: make(map[identify.Key]*observationContext), now: time.Now}
	budgets := identify.DefaultBudgets()
	budgets.Protocols = protocols
	live.observer, err = observe.New(observe.Options{Budgets: budgets, Markers: budgets.Entries,
		Manager: manager, Now: func() time.Time { return live.now() },
		LegacyDecodes: func(key identify.Key, p identify.Protocol) bool { return legacyDecodes(live.entries[key], p) },
		Scope:         func(key identify.Key, p identify.Protocol) any { return observationScope(live.entries[key], p) },
	})
	return live, err
}

// legacyDecodes is the only ownership policy. A mismatch deliberately binds the
// confirmed protocol even when a different port-selected decoder owns the flow.
func legacyDecodes(c *observationContext, protocol identify.Protocol) bool {
	if c == nil {
		return false
	}
	if protocol == identify.IEC104 && c.iecOwned && c.framer == string(protocol) {
		return true
	}
	if !c.selected {
		return false
	}
	for _, st := range c.states {
		if st == nil {
			continue
		}
		key := st.ServiceKey()
		// UDP/2222 selects legacy implicit I/O, never the confirmed ENIP layer.
		if protocol == identify.ENIP && cip.UsesImplicitIO(st) {
			return false
		}
		if key.Proto == 6 && (key.SrcPort == iec104Port || key.DstPort == iec104Port) {
			return false
		}
		if st.Key.Proto == 6 {
			return c.framer == string(protocol)
		}
		if c.legacy != nil {
			name := string(protocol)
			if protocol == identify.ENIP {
				name = "cip"
			}
			if matches, committed := c.legacy.CommittedProtocol(st, name); committed {
				return matches
			}
		}
		if ics.IsProtocolPortOn(string(protocol), key.Proto, key.SrcPort) || ics.IsProtocolPortOn(string(protocol), key.Proto, key.DstPort) {
			// The generic legacy path never decodes IEC104 without a table owner.
			return protocol != identify.IEC104
		}
	}
	return false
}

func observationScope(c *observationContext, p identify.Protocol) any {
	if c == nil || c.snapshot == nil {
		return "unknown"
	}
	var state *flow.State
	for _, st := range c.states {
		if st != nil {
			state = st
			break
		}
	}
	if state == nil {
		return "unknown"
	}
	named := false
	for _, entry := range c.snapshot.Firewall {
		if entry.ICS.Protocol == "" || !strings.EqualFold(entry.ICS.Protocol, string(p)) {
			continue
		}
		named = true
		if shouldInspectFirewallEntry(entry, state, observationPacket(state)) {
			return false
		}
	}
	return named
}

func observationPacket(st *flow.State) *dpi.ParsedPacket {
	proto := "tcp"
	if st.Key.Proto == 17 {
		proto = "udp"
	}
	return &dpi.ParsedPacket{Proto: proto, SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort}
}

// observePacket has no verdict return value and runs before either legacy
// handler, including cached ALLOW/DENY and IEC104's envelope owner.
func (e *Engine) observePacket(pkt capture.Packet, st *flow.State) {
	// Domain decisions are made outside flowMu (their lock order is domain ->
	// flow). Discovery does not inherit the legacy IEC104 domain exemption.
	enabled := e.dpiInspectionEnabled(st) && !e.discoveryDomainExcluded(st, pkt)
	parsed := observationPacket(st)
	selected := e.ShouldInspect(st, parsed)
	snapshot := e.ruleSnap.Load()
	iecOwned := e.iecOwnsState(pkt, st)
	framer := e.dpiMgr.FramingProtocol(st, parsed)
	e.flowMu.Lock()
	live := e.observation
	if live == nil {
		e.flowMu.Unlock()
		return
	}
	if pkt.Timestamp.IsZero() {
		pkt.Timestamp = live.now()
	}
	connection := st.Connection.Load()
	if connection == nil || connection.Key == "" {
		e.flowMu.Unlock()
		panic("observation requires a bound incarnation")
	}
	key := identify.Key(connection.Key)
	ctx := live.entries[key]
	if ctx == nil {
		if !enabled {
			e.flowMu.Unlock()
			return
		}
		ctx = &observationContext{generation: connection.Evidence, legacy: e.dpiMgr}
		live.entries[key] = ctx
		ports := [2]uint16{pkt.SrcPort, pkt.DstPort}
		if connection.Direction(st.Key) == flow.DirReverse {
			ports[0], ports[1] = ports[1], ports[0]
		}
		ctx.refused = !live.observer.Open(key, identify.Meta{Transport: pkt.Proto, Ports: ports})
	}
	dir := uint8(connection.Direction(st.Key))
	ctx.states[dir], ctx.selected, ctx.iecOwned, ctx.snapshot = st, selected, iecOwned, snapshot
	ctx.framer = framer
	var output observe.Output
	if !enabled {
		output = live.observer.Finish(key)
	} else if !ctx.refused {
		output = live.observer.Observe(key, observe.Packet{Arrival: identify.Arrival{
			Direction: dir, Sequence: pkt.TCP.Seq, SYN: pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0,
			Payload: pkt.Payload,
		}, State: st, At: pkt.Timestamp, SYNACK: pkt.TCP.Flags&capture.TCPFlagACK != 0,
			FIN: pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagFIN != 0, RST: pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagRST != 0})
	}
	e.settleObservationsLocked(output)
	if ctx.refused && e.transport != nil && !ics.IsDecoderPortOn(pkt.Proto, pkt.SrcPort) && !ics.IsDecoderPortOn(pkt.Proto, pkt.DstPort) {
		e.transport.settleObservation(st)
	}

	records := append(e.observationPending, live.records(output)...)
	e.observationPending = nil
	live.syncMetrics()
	e.flowMu.Unlock()
	e.recordObservations(records)
}

// records must run before removing context: terminal events still need their
// own directional state, even when a sweep or adoption produced them.
func (live *liveObserver) records(output observe.Output) []observationRecord {
	var records []observationRecord
	for _, id := range output.Identifications {
		if ctx := live.entries[id.Key]; ctx != nil {
			for _, state := range ctx.states {
				if state != nil {
					records = append(records, observationRecord{state, []dpi.Event{id.Event}})
					break
				}
			}
		}
	}
	for _, batch := range output.Batches {
		if batch.State != nil && len(batch.Events) > 0 {
			records = append(records, observationRecord{batch.State, batch.Events})
		}
	}
	return records
}

func (e *Engine) recordObservations(records []observationRecord) {
	for _, record := range records {
		parsed := observationPacket(record.state)
		e.RecordDPIEvents(record.state, parsed, record.events)
		for _, ev := range record.events {
			e.recordConformanceAlert(record.state, parsed, ev, "passed")
		}
	}
}

func (e *Engine) settleObservationsLocked(output observe.Output) {
	if e.transport == nil || e.observation == nil {
		return
	}
	for _, id := range output.Identifications {
		if ctx := e.observation.entries[id.Key]; ctx != nil {
			for _, state := range ctx.states {
				if state != nil {
					key := state.ServiceKey()
					if !ics.IsDecoderPortOn(key.Proto, key.SrcPort) && !ics.IsDecoderPortOn(key.Proto, key.DstPort) {
						e.transport.settleObservation(state)
					}
				}
			}
		}
	}
}
