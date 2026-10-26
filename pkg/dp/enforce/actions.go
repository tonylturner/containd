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
//     precede IEC104 steering, NFQUEUE and the established accept, so they
//     meter every packet of the flow.
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
// applies to. A queued rule's traffic goes to queueID whatever its action.
func actionForms(e rules.Entry, p rules.Protocol, queued bool, queueID int, counted, logStmt string) ([]lineForm, error) {
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
		return []lineForm{{stmts: stmts(fmt.Sprintf("queue num %d", queueID))}}, nil
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
	case rules.ActionRateLimit:
		return meterForms(e, p, counted, logStmt)
	default:
		return nil, fmt.Errorf("unknown action %q in entry %s", e.Action, e.ID)
	}
}

// meterForms lowers a RATE_LIMIT rule for protocol p: one line per address
// family and key. The excess is logged when logStmt is set.
func meterForms(e rules.Entry, p rules.Protocol, counted, logStmt string) ([]lineForm, error) {
	rl := e.RateLimit
	if rl == nil || rl.PacketsPerSecond == 0 {
		return nil, fmt.Errorf("entry %s: RATE_LIMIT needs a positive packetsPerSecond", e.ID)
	}
	burst := rl.Burst
	if burst == 0 {
		burst = rl.PacketsPerSecond
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", rl.PacketsPerSecond, burst)
	excess := excessCounterName(e.ID)
	tail := fmt.Sprintf("counter name %q", excess)
	if logStmt != "" {
		tail += " " + logStmt
	}
	var out []lineForm
	for _, k := range meterKeys(e, p) {
		match := "meta nfproto " + k.family
		if protocolName(p) == "" {
			if k.ports {
				match += " meta l4proto { tcp, udp }"
			} else {
				match += " meta l4proto != { tcp, udp }"
			}
		}
		out = append(out, lineForm{
			match: match,
			stmts: fmt.Sprintf("%s update @%s { %s %s } %s drop", counted, k.set(e.ID), k.key(), limit, tail),
		})
	}
	return out, nil
}

// meterKey is one key form of a rule's meter: an address family, with or
// without the transport ports.
type meterKey struct {
	family string // ipv4 | ipv6
	ports  bool
}

// meterKeys lists the keys a RATE_LIMIT rule meters protocol p with. Rule
// addresses are matched as IPv4, and ICMP is IPv4's, so either limits the
// meter to IPv4.
func meterKeys(e rules.Entry, p rules.Protocol) []meterKey {
	families := []string{"ipv4", "ipv6"}
	name := protocolName(p)
	if len(e.Sources) > 0 || len(e.Destinations) > 0 || name == "icmp" {
		families = families[:1]
	}
	var out []meterKey
	for _, f := range families {
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

// set names the rule's meter set of this key.
func (k meterKey) set(ruleID string) string {
	name := ruleCounterName(ruleID) + "_m4"
	if k.family == "ipv6" {
		name = ruleCounterName(ruleID) + "_m6"
	}
	if k.ports {
		name += "p"
	}
	return name
}

func (k meterKey) key() string {
	addr := "ip"
	if k.family == "ipv6" {
		addr = "ip6"
	}
	key := addr + " saddr . " + addr + " daddr . meta l4proto"
	if k.ports {
		key += " . th sport . th dport"
	}
	return key
}

func (k meterKey) setType() string {
	typ := k.family + "_addr . " + k.family + "_addr . inet_proto"
	if k.ports {
		typ += " . inet_service . inet_service"
	}
	return typ
}

// writeMeterSets declares a RATE_LIMIT rule's meter sets in the policy
// table. A tuple expires once idle long enough to refill its bucket, so a
// new tuple's full bucket never admits more than the old one would have.
func writeMeterSets(buf *bytes.Buffer, e rules.Entry) {
	if e.Action != rules.ActionRateLimit || e.RateLimit == nil || e.RateLimit.PacketsPerSecond == 0 {
		return
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
		for _, k := range meterKeys(e, p) {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].set(e.ID) < keys[j].set(e.ID) })
	for _, k := range keys {
		fmt.Fprintf(buf, "  set %s {\n    type %s;\n    size %d;\n    flags dynamic,timeout;\n    timeout %ds;\n  }\n",
			k.set(e.ID), k.setType(), meterSetSize, idle)
	}
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
