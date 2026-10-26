// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TAG labels are a function of the applied snapshot and a connection's
// opener-oriented tuple (opener, server, layer-4 protocol, server port).
// The engine stamps them on a flow's state when the state is created and
// adds them to the flow's events; the connection list derives them the
// same way from the running snapshot.

// flowTags returns the labels of the TAG rules that match the connection
// of key, or nil.
func (e *Engine) flowTags(key flow.Key) []string {
	p := e.ruleSnap.current.Load()
	if p == nil || !p.evaluator.HasTags() {
		return nil
	}
	port := key.DstPort
	if key.Dir == flow.DirReverse {
		port = key.SrcPort
	}
	ctx := tagContext(key.OpenerIP(), key.ServerIP(), protocolName(key.Proto), port)
	if p.evaluator.TagsUseZones() {
		ctx.SrcZone, ctx.DstZone = resolveZonesForFlow(p.snapshot, ctx.SrcIP, ctx.DstIP)
	}
	return p.evaluator.Tags(ctx)
}

// tagContext is the evaluation context of a connection tuple for TAG
// rules. Only TCP and UDP carry a server port.
func tagContext(opener, server net.IP, proto string, serverPort uint16) rules.EvalContext {
	ctx := rules.EvalContext{SrcIP: opener, DstIP: server, Proto: proto}
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
func (t *iecTable) withSessionTags(evs []events.Event) []events.Event {
	t.mu.Lock()
	policy, snap := t.policy, t.snap
	t.mu.Unlock()
	tp, ok := policy.(tagPolicy)
	if !ok || !tp.HasTags() {
		return evs
	}
	for i, ev := range evs {
		client, server := net.ParseIP(ev.SrcIP), net.ParseIP(ev.DstIP)
		if client == nil || server == nil {
			continue
		}
		ctx := tagContext(client, server, strings.ToLower(ev.Transport), ev.DstPort)
		if tp.TagsUseZones() {
			ctx.SrcZone, ctx.DstZone = resolveZonesForFlow(snap, client, server)
		}
		evs[i].Attributes = events.WithTags(ev.Attributes, tp.Tags(ctx))
	}
	return evs
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
		zones = newZoneIndex(p.snapshot, interfaceAddrs)
	}
	for i, c := range entries {
		opener, server := net.ParseIP(c.Src), net.ParseIP(c.Dst)
		if opener == nil || server == nil {
			continue
		}
		port, _ := strconv.ParseUint(c.Dport, 10, 16)
		ctx := tagContext(opener, server, strings.ToLower(c.Proto), uint16(port))
		ctx.SrcZone, ctx.DstZone = zones.zoneFor(opener), zones.zoneFor(server)
		out[i].Tags = p.evaluator.Tags(ctx)
	}
	return out
}
