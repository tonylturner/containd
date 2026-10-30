// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/observe"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// AnalysisOptions supplies an immutable rule snapshot and a deadline clock.
// By default, deadlines use a nondecreasing capture watermark. Packet.At
// always retains the original capture timestamp, even if it moves backwards.
type AnalysisOptions struct {
	Rules *rules.Snapshot
	Now   func() time.Time
}

// Identification retains the observer's exact event-field spellings, with an
// offline incarnation key so tuple reuse cannot merge distinct results.
type Identification struct {
	Key        string         `json:"key"`
	FlowID     string         `json:"flowId"`
	SrcIP      string         `json:"srcIp"`
	DstIP      string         `json:"dstIp"`
	SrcPort    uint16         `json:"srcPort"`
	DstPort    uint16         `json:"dstPort"`
	Attributes map[string]any `json:"attributes"`
}

type offlineConnection struct {
	key       identify.Key
	endpoints [2]string
	meta      identify.Meta
	states    [2]*flow.State
	syn       [2]bool
	isn       [2]uint32
	service   uint16
}

type offlineObserver struct {
	observer *observe.Observer
	runID    string
	serial   uint64
	byTuple  map[string]*offlineConnection
	byKey    map[identify.Key]*offlineConnection
	decoders []dpi.Decoder
	manager  *dpi.Manager
	sessions *offlineSessions
}

func newOfflineObserver(manager *dpi.Manager, sessions *offlineSessions, opts AnalysisOptions, decoders []dpi.Decoder) (*offlineObserver, error) {
	// Only enabled ICS decoders get fresh observation instances. Never share a
	// stateful decoder with the port-selected manager or a live engine.
	factories := []dpi.StreamDecoder{modbus.NewDecoder(), dnp3.NewDecoderWithClock(opts.Now), iec104.NewDecoder(), cip.NewDecoder()}
	enabled := map[string]bool{}
	for _, d := range decoders {
		if sd, ok := d.(dpi.StreamDecoder); ok {
			enabled[sd.Protocol()] = true
		}
	}
	var fresh []dpi.StreamDecoder
	budgets := identify.DefaultBudgets()
	budgets.Protocols = []identify.Protocol{}
	for _, d := range factories {
		if enabled[d.Protocol()] {
			fresh = append(fresh, d)
			budgets.Protocols = append(budgets.Protocols, identify.Protocol(d.Protocol()))
		}
	}
	mgr, err := dpi.NewObservationManager(fresh...)
	if err != nil {
		return nil, err
	}
	o := &offlineObserver{manager: manager, runID: sessions.runID, sessions: sessions, byTuple: map[string]*offlineConnection{}, byKey: map[identify.Key]*offlineConnection{}, decoders: decoders}
	o.observer, err = observe.New(observe.Options{Budgets: budgets, Markers: budgets.Entries, Manager: mgr, Now: opts.Now,
		LegacyDecodes: o.legacyDecodes,
		Scope: func(key identify.Key, p identify.Protocol) any {
			if opts.Rules == nil {
				return "unknown"
			}
			c := o.byKey[key]
			return outsideRulePorts(opts.Rules, p, c.meta.Transport, c.service)
		}})
	return o, err
}

// legacyDecodes is the single offline binding policy. A mismatched protocol
// gets passive decoding; an already selected matching decoder is not duplicated.
func (o *offlineObserver) legacyDecodes(key identify.Key, p identify.Protocol) bool {
	c := o.byKey[key]
	st := c.states[0]
	if p == identify.ENIP && cip.UsesImplicitIO(st) {
		return false
	}
	parsed := &dpi.ParsedPacket{Proto: "tcp"}
	if st.Key.Proto == ics.TCP && (st.Key.SrcPort == ics.IEC104Port || st.Key.DstPort == ics.IEC104Port) {
		// annotate bypasses every legacy decoder on this tuple until a
		// session has both handshake directions, not just the IEC decoder.
		s, _, dir := o.sessions.lookup(c.endpoints[0], c.endpoints[1])
		if s == nil || s.dirs[1] == nil {
			return false
		}
		parsed.HasOffset, parsed.Session, parsed.Dir = true, s.id, dpi.ClientToServer
		if dir == 1 {
			parsed.Dir = dpi.ServerToClient
		}
	}
	if st.Key.Proto == ics.TCP {
		return o.manager.FramingProtocol(st, parsed) == string(p)
	}
	for _, d := range o.decoders {
		sd, ok := d.(dpi.StreamDecoder)
		if !ok || !d.Supports(st) {
			continue
		}
		if sd.Protocol() == string(p) {
			return true
		}
	}
	return false
}

func (o *offlineObserver) packet(pkt capture.Packet, state *flow.State, ts time.Time, truncated bool) observe.Output {
	if pkt.Proto != 6 && pkt.Proto != 17 {
		return observe.Output{}
	}
	src, dst := endpoint(pkt.SrcIP, pkt.SrcPort), endpoint(pkt.DstIP, pkt.DstPort)
	a, b := src, dst
	if a > b {
		a, b = b, a
	}
	tuple := fmt.Sprintf("%d/%s/%s", pkt.Proto, a, b)
	c := o.byTuple[tuple]
	dir := uint8(0)
	if c != nil && c.endpoints[1] == src {
		dir = 1
	}
	syn := pkt.TCP.Flags&capture.TCPFlagSYN != 0
	var out observe.Output
	// Retransmitted SYNs retain their key. A different ISN, or a SYN after
	// midstream capture, retires both directions of the old incarnation.
	if c != nil && syn && (c.syn[dir] && c.isn[dir] != pkt.TCP.Seq || !c.syn[0] && !c.syn[1]) {
		out = o.observer.Release(c.key)
		delete(o.byKey, c.key)
		c = nil
	}
	if c == nil {
		o.serial++
		c = &offlineConnection{key: identify.Key(fmt.Sprintf("%s/%d", o.runID, o.serial)), endpoints: [2]string{src, dst}, meta: identify.Meta{Transport: pkt.Proto, Ports: [2]uint16{pkt.SrcPort, pkt.DstPort}}, service: pkt.DstPort}
		dir = 0
		if state.Key.Dir == flow.DirReverse {
			c.service = pkt.SrcPort
		}
		o.byTuple[tuple], o.byKey[c.key] = c, c
		c.states[0] = state
		o.observer.Open(c.key, c.meta) // one admission attempt per incarnation
	}
	c.states[dir] = state
	state.Connection.Store(&flow.Connection{Key: string(c.key), Status: "wire"})
	if syn {
		c.syn[dir], c.isn[dir] = true, pkt.TCP.Seq
		if pkt.TCP.Flags&capture.TCPFlagACK == 0 {
			c.service = pkt.DstPort
		} else {
			c.service = pkt.SrcPort
		}
	}
	next := o.observer.Observe(c.key, observe.Packet{Arrival: identify.Arrival{Direction: dir, Sequence: pkt.TCP.Seq, SYN: syn, Payload: pkt.Payload, Truncated: truncated || pkt.Invalid == capture.InvalidTruncated}, State: state, At: ts,
		SYNACK: syn && pkt.TCP.Flags&capture.TCPFlagACK != 0, FIN: pkt.TCP.Flags&capture.TCPFlagFIN != 0, RST: pkt.TCP.Flags&capture.TCPFlagRST != 0})
	out.Identifications = append(out.Identifications, next.Identifications...)
	out.Batches = append(out.Batches, next.Batches...)
	return out
}

func outsideRulePorts(snap *rules.Snapshot, p identify.Protocol, transport uint8, port uint16) bool {
	named := false
	for _, entry := range snap.Firewall {
		if !strings.EqualFold(entry.ICS.Protocol, string(p)) {
			continue
		}
		named = true
		if len(entry.Protocols) == 0 {
			if ics.IsProtocolPortOn(string(p), transport, port) {
				return false
			}
			continue
		}
		for _, proto := range entry.Protocols {
			if proto.Name != "" && !strings.EqualFold(proto.Name, flowTransport(transport)) {
				continue
			}
			if proto.Port == "" {
				return false
			}
			parts := strings.SplitN(strings.TrimSpace(proto.Port), "-", 2)
			lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || lo < 0 || lo > 65535 {
				continue
			}
			hi := lo
			if len(parts) == 2 {
				hi, err = strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil || hi < 0 || hi > 65535 {
					continue
				}
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			if int(port) >= lo && int(port) <= hi {
				return false
			}
		}
	}
	return named
}

func (o *offlineObserver) record(out observe.Output, result *AnalysisResult, flowEvents map[string]int, onEvent eventCallback) {
	for _, id := range out.Identifications {
		ev := id.Event
		ev.Connection = &flow.Connection{Key: string(id.Key), Status: "wire"}
		identification := Identification{Key: string(id.Key), FlowID: ev.FlowID, Attributes: ev.Attributes}
		if id.Binding == observe.Observation {
			result.observed[string(id.Key)] = true
		}
		hash := ev.FlowID
		if k, ok := flow.ParseKey(hash); ok {
			// The directional state carries SYN roles when captured. Present
			// the opener first, even when the capture started at the SYN-ACK.
			presented := k
			if presented.Dir == flow.DirReverse {
				presented = presented.Reversed()
			}
			identification.SrcIP, identification.DstIP = presented.SrcIP.String(), presented.DstIP.String()
			identification.SrcPort, identification.DstPort = presented.SrcPort, presented.DstPort
			k.Dir = flow.DirForward
			hash = k.Hash()
		}
		result.Identifications = append(result.Identifications, identification)
		recordAnalysisEvents(result, flowEvents, hash, "", "", []dpi.Event{ev}, onEvent)
	}
	for _, batch := range out.Batches {
		if batch.State == nil {
			continue
		}
		for i := range batch.Events {
			batch.Events[i].Connection = &flow.Connection{Key: string(batch.Key), Status: "wire"}
		}
		k := batch.State.Key
		k.Dir = flow.DirForward
		recordAnalysisEvents(result, flowEvents, k.Hash(), k.SrcIP.String(), k.DstIP.String(), batch.Events, onEvent)
	}
}
