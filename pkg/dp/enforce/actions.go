// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Lowering of the firewall rule actions. Every line of a rule counts into
// the rule's named counter (counters.go) before its action:
//
//   - ALLOW accepts and DENY drops.
//   - RESET rejects back to the sender: a TCP reset for TCP, ICMP or
//     ICMPv6 destination unreachable (administratively prohibited)
//     otherwise.
//   - RATE_LIMIT polices each directional 5-tuple (source, destination,
//     layer-4 protocol, source and destination port; the protocol alone
//     without ports for anything but TCP and UDP) in a per-rule dynamic
//     set, and drops the packets over the limit, counted again in the
//     rule's excess counter. A packet under the limit continues. Its lines
//     precede IEC104 steering, NFQUEUE and the established accept, and
//     match a connection by its original tuple, so they meter every packet
//     of the flow in both directions, each direction in its own bucket
//     (meterLines).
//   - TAG has no kernel effect: its line only counts the connection
//     openers it matches, after the established accept, and continues.

// rejectTCP and rejectOther are RESET's reject statements.
const (
	rejectTCP   = "reject with tcp reset"
	rejectOther = "reject with icmpx admin-prohibited"
)

// Meter bounds: the tuples one meter set tracks, and the shortest idle
// timeout of a tuple.
const (
	meterSetSize        = 65536
	meterMinIdleSeconds = 10
)

// lineForm is one nft line of a rule protocol: match clauses that go before
// the rule's own predicates, and the statements that follow them.
type lineForm struct {
	match string
	stmts string
}

// actionForms lowers e's action for protocol p. counted is the rule's
// counter statement; logStmt, when set, logs the packets the action
// applies to. A queued rule's traffic goes to the engine's queue through
// ICSQueueChain whatever its action. RATE_LIMIT, which needs lines per
// direction, is meterLines'.
func actionForms(e rules.Entry, p rules.Protocol, queued bool, counted, logStmt string) ([]lineForm, error) {
	stmts := func(verdict string) string {
		out := counted
		if logStmt != "" {
			out += " " + logStmt
		}
		if verdict != "" {
			out += " " + verdict
		}
		return out
	}
	if queued {
		return []lineForm{{stmts: stmts("jump " + ICSQueueChain)}}, nil
	}
	switch e.Action {
	case rules.ActionAllow:
		return []lineForm{{stmts: stmts("accept")}}, nil
	case rules.ActionDeny:
		return []lineForm{{stmts: stmts("drop")}}, nil
	case rules.ActionReset:
		switch protocolName(p) {
		case "tcp":
			return []lineForm{{stmts: stmts(rejectTCP)}}, nil
		case "":
			return []lineForm{{match: "meta l4proto tcp", stmts: stmts(rejectTCP)}, {stmts: stmts(rejectOther)}}, nil
		default:
			return []lineForm{{stmts: stmts(rejectOther)}}, nil
		}
	case rules.ActionTag:
		return []lineForm{{stmts: stmts("")}}, nil
	default:
		return nil, fmt.Errorf("unknown action %q in entry %s", e.Action, e.ID)
	}
}

// Meter line selection of the packets with and without a usable conntrack
// entry: every packet takes exactly one of them.
const (
	untrackedState = "ct state { invalid, untracked }"
	trackedState   = "ct state != { invalid, untracked }"
)

// meterLines lowers a RATE_LIMIT rule for protocol p in each of its address
// scopes, per meter key. A tracked packet of either direction matches by
// its connection's original tuple, as the established recheck does
// (predicates.ctLines); a packet without a usable conntrack entry matches
// by its header, as a connection's first packet. Either way the meter keys
// on the packet's own header, so each direction of a flow has its own
// bucket. The excess is logged when logStmt is set.
func meterLines(e rules.Entry, p rules.Protocol, scopes []addrScope, zones zoneIndex, logStmt string) ([]ruleLine, error) {
	rl := e.RateLimit
	if rl == nil || rl.PacketsPerSecond == 0 {
		return nil, fmt.Errorf("entry %s: RATE_LIMIT needs a positive packetsPerSecond", e.ID)
	}
	burst := rl.Burst
	if burst == 0 {
		burst = rl.PacketsPerSecond
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", rl.PacketsPerSecond, burst)
	tail := fmt.Sprintf("counter name %q", excessCounterName(e.ID))
	if logStmt != "" {
		tail += " " + logStmt
	}
	header, err := protocolMatch(p)
	if err != nil {
		return nil, fmt.Errorf("entry %s: %w", e.ID, err)
	}
	tracked, err := ctProtocolMatch(p)
	if err != nil {
		return nil, fmt.Errorf("entry %s: %w", e.ID, err)
	}
	dirs, ok := zones.ctDirections(e)
	if !ok {
		return nil, nil
	}
	in, _ := zones.clause("iifname", e.SourceZones)
	out, _ := zones.clause("oifname", e.DestZones)
	var lines []ruleLine
	for _, s := range scopes {
		for _, k := range meterKeys(p, s.family) {
			match := "meta nfproto " + k.nfproto()
			if protocolName(p) == "" {
				if k.ports {
					match += " meta l4proto { tcp, udp }"
				} else {
					match += " meta l4proto != { tcp, udp }"
				}
			}
			stmts := fmt.Sprintf("%s update @%s { %s %s } %s drop", counterStmt(e.ID), k.set(e.ID), k.key(), limit, tail)
			first := append([]string{match, untrackedState, in, out, header}, s.header(false)...)
			lines = append(lines, ruleLine{family: k.family, text: joinClauses(append(first, stmts))})
			for _, d := range dirs {
				both := append([]string{match, trackedState, d.clause, d.in, d.out, tracked}, s.conntrack()...)
				lines = append(lines, ruleLine{family: k.family, ct: true, text: joinClauses(append(both, stmts))})
			}
		}
	}
	return lines, nil
}

// meterKey is one key form of a rule's meter: an address family, with or
// without the transport ports.
type meterKey struct {
	family int // 0: IPv4, 1: IPv6
	ports  bool
}

// meterKeys lists the keys a RATE_LIMIT rule meters protocol p with in
// address family family (familyAny: both). ICMP is IPv4's.
func meterKeys(p rules.Protocol, family int) []meterKey {
	families := []int{0, 1}
	if family != familyAny {
		families = []int{family}
	}
	name := protocolName(p)
	var out []meterKey
	for _, f := range families {
		if name == "icmp" && f != 0 {
			continue
		}
		switch name {
		case "tcp", "udp":
			out = append(out, meterKey{family: f, ports: true})
		case "":
			out = append(out, meterKey{family: f, ports: true}, meterKey{family: f})
		default:
			out = append(out, meterKey{family: f})
		}
	}
	return out
}

// nfproto is the key's family as meta nfproto names it.
func (k meterKey) nfproto() string {
	return [2]string{"ipv4", "ipv6"}[k.family]
}

// set names the rule's meter set of this key.
func (k meterKey) set(ruleID string) string {
	name := ruleCounterName(ruleID) + "_m4"
	if k.family == 1 {
		name = ruleCounterName(ruleID) + "_m6"
	}
	if k.ports {
		name += "p"
	}
	return name
}

func (k meterKey) key() string {
	addr := familyKeyword[k.family]
	key := addr + " saddr . " + addr + " daddr . meta l4proto"
	if k.ports {
		key += " . th sport . th dport"
	}
	return key
}

func (k meterKey) setType() string {
	typ := k.nfproto() + "_addr . " + k.nfproto() + "_addr . inet_proto"
	if k.ports {
		typ += " . inet_service . inet_service"
	}
	return typ
}

// writeMeterSets declares a RATE_LIMIT rule's meter sets in the policy
// table. A tuple expires once idle long enough to refill its bucket, so a
// new tuple's full bucket never admits more than the old one would have.
func writeMeterSets(buf *bytes.Buffer, e rules.Entry) error {
	if e.Action != rules.ActionRateLimit || e.RateLimit == nil || e.RateLimit.PacketsPerSecond == 0 {
		return nil
	}
	scopes, err := addrScopes(e)
	if err != nil {
		return err
	}
	pps, burst := uint64(e.RateLimit.PacketsPerSecond), uint64(e.RateLimit.Burst)
	idle := (burst + pps - 1) / pps
	if idle < meterMinIdleSeconds {
		idle = meterMinIdleSeconds
	}
	protos := e.Protocols
	if len(protos) == 0 {
		protos = []rules.Protocol{{}}
	}
	var keys []meterKey
	for _, p := range protos {
		for _, s := range scopes {
			for _, k := range meterKeys(p, s.family) {
				if !slices.Contains(keys, k) {
					keys = append(keys, k)
				}
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].set(e.ID) < keys[j].set(e.ID) })
	for _, k := range keys {
		fmt.Fprintf(buf, "  set %s {\n    type %s;\n    size %d;\n    flags dynamic,timeout;\n    timeout %ds;\n  }\n",
			k.set(e.ID), k.setType(), meterSetSize, idle)
	}
	return nil
}

// protocolName is a rule protocol's normalized name; "" matches every
// protocol.
func protocolName(p rules.Protocol) string {
	return strings.ToLower(strings.TrimSpace(p.Name))
}

// forwardSections splits the firewall entries into the forward chain's
// sections: the RATE_LIMIT meters by rule ID, the TAG lines by rule ID,
// and the deciding entries in rules.DecisionOrder.
func forwardSections(entries []rules.Entry) (meters, tags, decide []rules.Entry) {
	for _, e := range entries {
		switch e.Action {
		case rules.ActionRateLimit:
			meters = append(meters, e)
		case rules.ActionTag:
			tags = append(tags, e)
		}
	}
	byID := func(list []rules.Entry) {
		sort.SliceStable(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	}
	byID(meters)
	byID(tags)
	for _, i := range rules.DecisionOrder(entries) {
		decide = append(decide, entries[i])
	}
	return meters, tags, decide
}
