// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TAG labels are a function of the applied snapshot, its identity bindings
// included, and a connection's opener-oriented tuple (opener, server,
// layer-4 protocol, server port).
// The engine stamps them on a flow's state when the state is created and
// adds them to the flow's events; the connection list derives them the
// same way from the running snapshot.

// flowTags returns the labels of the TAG rules that match the connection
// of key, or nil.
func (e *Engine) flowTags(state *flow.State) []string {
	p := e.ruleSnap.current.Load()
	if p == nil || !p.evaluator.HasTags() {
		return nil
	}
	key := state.ServiceKey()
	port := key.DstPort
	if key.Dir == flow.DirReverse {
		port = key.SrcPort
	}
	ctx := tagContext(p.snapshot, key.OpenerIP(), key.ServerIP(), protocolName(key.Proto), port)
	if p.evaluator.TagsUseZones() {
		ctx.SrcZone, ctx.DstZone = e.zones.resolve(p.snapshot, ctx.SrcIP, ctx.DstIP)
	}
	return p.evaluator.Tags(ctx)
}

// recordTaggedEvents snapshots tags under the same lock as evidence binding.
// Event storage still receives the untouched wire key and packet endpoints.
func (e *Engine) recordTaggedEvents(state *flow.State, pkt *dpi.ParsedPacket, evs []dpi.Event) {
	if state == nil {
		e.eventStore.Record(nil, pkt, evs)
		return
	}
	e.flowMu.Lock()
	snapshot := *state
	e.flowMu.Unlock()
	e.eventStore.Record(&snapshot, pkt, evs)
}

// nflogRuleHits appends the firewall.rule.hit events of kernel-logged
// packets (capture.StartNFLog) to the engine's event store, with the TAG
// labels of their connection under the applied snapshot.
type nflogRuleHits struct{ e *Engine }

func (h nflogRuleHits) RuleHit(ev events.Event, key *flow.Key) {
	if key != nil {
		ev.Attributes = events.WithTags(ev.Attributes, h.e.flowTags(&flow.State{Key: *key}))
	}
	h.e.eventStore.Append(ev)
}

// tagContext is the evaluation context of a connection tuple for TAG
// rules, with the identities snap binds to the opener. Only TCP and UDP
// carry a server port.
func tagContext(snap *rules.Snapshot, opener, server net.IP, proto string, serverPort uint16) rules.EvalContext {
	ctx := rules.EvalContext{SrcIP: opener, DstIP: server, Proto: proto, Identities: snap.IdentitiesOf(opener)}
	if proto == "tcp" || proto == "udp" {
		ctx.Port = strconv.Itoa(int(serverPort))
	}
	return ctx
}

// protocolName names an IP protocol number as rules and the connection
// list do.
func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return strconv.Itoa(int(proto))
	}
}

// tagPolicy is the TAG part of the rule evaluator. *rules.Evaluator
// implements it.
type tagPolicy interface {
	HasTags() bool
	TagsUseZones() bool
	Tags(rules.EvalContext) []string
}

// withSessionTags adds to IEC104 session events the TAG labels of their
// session tuple, which is oriented client to server, under the table's
// current policy. It runs outside the table lock.
func (t *iecTable) withSessionTags(evs []iecTelemetry) []events.Event {
	out := make([]events.Event, len(evs))
	for i := range evs {
		out[i] = evs[i].Event
	}
	t.mu.Lock()
	policy, snap := t.policy, t.snap
	t.mu.Unlock()
	tp, ok := policy.(tagPolicy)
	if !ok || !tp.HasTags() {
		return out
	}
	for i, ev := range evs {
		client, server := net.ParseIP(ev.SrcIP), net.ParseIP(ev.DstIP)
		if client == nil || server == nil {
			continue
		}
		port := ev.DstPort
		if key := ev.service; key != nil {
			client, server = key.OpenerIP(), key.ServerIP()
			port = key.DstPort
			if key.Dir == flow.DirReverse {
				port = key.SrcPort
			}
		}
		ctx := tagContext(snap, client, server, strings.ToLower(ev.Transport), port)
		if tp.TagsUseZones() {
			ctx.SrcZone, ctx.DstZone = t.zones.resolve(snap, client, server)
		}
		out[i].Attributes = events.WithTags(ev.Attributes, tp.Tags(ctx))
	}
	return out
}

// TaggedConnection is a kernel connection with the labels of the TAG
// rules that match it under the running snapshot.
type TaggedConnection struct {
	conntrack.Entry
	Tags []string `json:"tags,omitempty"`
}

// TagConnections labels connections, whose original tuples are oriented
// on their openers, with the running snapshot's TAG rules.
func (e *Engine) TagConnections(entries []conntrack.Entry) []TaggedConnection {
	out := make([]TaggedConnection, len(entries))
	for i, c := range entries {
		out[i].Entry = c
	}
	if e == nil {
		return out
	}
	p := e.ruleSnap.current.Load()
	if p == nil || !p.evaluator.HasTags() {
		return out
	}
	var zones zoneIndex
	if p.evaluator.TagsUseZones() {
		zones = e.zones.index(p.snapshot)
	}
	for i, c := range entries {
		opener, server := net.ParseIP(c.Src), net.ParseIP(c.Dst)
		if opener == nil || server == nil {
			continue
		}
		port, _ := strconv.ParseUint(c.Dport, 10, 16)
		state := &flow.State{Key: flow.Key{SrcIP: opener, DstIP: server, DstPort: uint16(port)}}
		// Kernel listings carry both tuples but no incarnation metadata. Parse
		// the complete TCP/UDP record before using it as service authority.
		if original, reply, ok := listingTuples(c); ok {
			state.Key = flow.TupleKey(original, flow.DirForward)
			state.Connection.Store(&flow.Connection{Status: "resolved", Evidence: &conntrack.Evidence{Original: original, Reply: reply}})
		}
		key := state.ServiceKey()
		opener, server = key.OpenerIP(), key.ServerIP()
		ctx := tagContext(p.snapshot, opener, server, strings.ToLower(c.Proto), key.DstPort)
		ctx.SrcZone, ctx.DstZone = zones.zoneFor(opener), zones.zoneFor(server)
		out[i].Tags = p.evaluator.Tags(ctx)
	}
	return out
}

func listingTuples(entry conntrack.Entry) (conntrack.Tuple, conntrack.Tuple, bool) {
	var proto uint8
	switch strings.ToLower(entry.Proto) {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	default:
		return conntrack.Tuple{}, conntrack.Tuple{}, false
	}
	parse := func(src, dst, sport, dport string) (conntrack.Tuple, bool) {
		s, errS := netip.ParseAddr(src)
		d, errD := netip.ParseAddr(dst)
		sp, errSP := strconv.ParseUint(sport, 10, 16)
		dp, errDP := strconv.ParseUint(dport, 10, 16)
		if errS != nil || errD != nil || errSP != nil || errDP != nil {
			return conntrack.Tuple{}, false
		}
		key := flow.Key{SrcIP: s.AsSlice(), DstIP: d.AsSlice(), SrcPort: uint16(sp), DstPort: uint16(dp), Proto: proto}
		tuple := key.Tuple()
		return tuple, tuple.Validate() == nil
	}
	original, okO := parse(entry.Src, entry.Dst, entry.Sport, entry.Dport)
	reply, okR := parse(entry.ReplySrc, entry.ReplyDst, entry.ReplySport, entry.ReplyDport)
	return original, reply, okO && okR
}
