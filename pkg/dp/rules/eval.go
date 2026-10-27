// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"net"
	"strconv"
	"time"
)

// EvalContext represents a simplified flow context for rule evaluation.
type EvalContext struct {
	SrcZone string
	DstZone string
	SrcIP   net.IP
	DstIP   net.IP
	Proto   string // tcp, udp, icmp
	Port    string // dest port as string (e.g., "80")
	// Identities represent user/group or identity tags associated with the flow.
	Identities []string
	// ICS provides decoded ICS metadata for predicate matching.
	ICS *ICSContext
	// Now overrides the current time for schedule evaluation (used in tests).
	// If zero, time.Now() is used.
	Now time.Time
}

// ICSContext represents decoded ICS metadata for rule evaluation.
type ICSContext struct {
	Protocol     string
	FunctionCode uint8
	UnitID       *uint8
	ObjectClass  uint16
	ReadOnly     bool
	WriteOnly    bool
	Direction    string // "request" or "response"
	// Spans are the address ranges the message reads or writes, for
	// address predicates; empty when it touches none. SpansUnknown marks a
	// message that may touch addresses its decoder cannot bound, such as a
	// Modbus request with an unknown function code or a malformed PDU.
	Spans        []AddressSpan
	SpansUnknown bool
	// IEC104 is set only for IEC 60870-5-104 events.
	IEC104 *IEC104Context
}

// compiledPort holds a pre-parsed protocol port or port range.
type compiledPort struct {
	low, high uint16
}

// compiledEntry pairs an Entry with pre-parsed address, network and port
// data so that string parsing is done once at load time rather than on
// every packet.
type compiledEntry struct {
	Entry
	src, dst  networks         // pre-parsed Sources and Destinations
	schedule  compiledSchedule // pre-parsed Schedule
	addresses addrSet          // pre-parsed ICS addresses
	ports     []compiledPort   // pre-parsed protocol port ranges (one per Protocol)
	iec       *compiledIEC104  // set for ics.protocol iec104 entries only
}

// networks is one side's parsed CIDRs. listed records that the entry names
// any CIDR on that side, parseable or not: a side whose CIDRs all fail to
// parse matches no address.
type networks struct {
	listed bool
	nets   []*net.IPNet
}

func compileNetworks(cidrs []string) networks {
	side := networks{listed: len(cidrs) > 0}
	for _, c := range cidrs {
		if _, network, err := net.ParseCIDR(c); err == nil {
			side.nets = append(side.nets, network)
		}
	}
	return side
}

// holds reports whether ip is in the side's networks; an unlisted side
// holds every address.
func (n *networks) holds(ip net.IP) bool {
	if !n.listed {
		return true
	}
	for _, network := range n.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Evaluator evaluates a snapshot for a given context and returns an action.
type Evaluator struct {
	snapshot *Snapshot
	compiled []compiledEntry
	decide   []int // deciding entries in DecisionOrder
	tags     []int // TAG entries
}

func NewEvaluator(snap *Snapshot) *Evaluator {
	ev := &Evaluator{snapshot: snap}
	ev.compile()
	return ev
}

// compile pre-parses address and port range strings from every firewall entry.
func (e *Evaluator) compile() {
	if e.snapshot == nil {
		return
	}
	e.compiled = make([]compiledEntry, len(e.snapshot.Firewall))
	for i, entry := range e.snapshot.Firewall {
		e.compiled[i] = compileEntry(entry)
	}
	e.decide = DecisionOrder(e.snapshot.Firewall)
	e.tags = tagIndexes(e.snapshot.Firewall)
}

// compileEntry pre-parses a single Entry.
func compileEntry(entry Entry) compiledEntry {
	ce := compiledEntry{Entry: entry, src: compileNetworks(entry.Sources), dst: compileNetworks(entry.Destinations),
		schedule: compileSchedule(entry)}
	if entry.ICS.Protocol == ProtocolIEC104 {
		ce.iec = compileIEC104(entry.ICS)
	}

	ce.addresses = compileAddrs(entry.ICS.Addresses)

	// Pre-parse protocol port ranges.
	ce.ports = make([]compiledPort, len(entry.Protocols))
	for j, p := range entry.Protocols {
		if p.Port == "" {
			continue
		}
		lo, hi, err := ParsePortRange(p.Port)
		if err == nil {
			ce.ports[j] = compiledPort{low: lo, high: hi}
		} else {
			ce.ports[j] = compiledPort{low: 1, high: 0}
		}

	}

	return ce
}

// PreviewMatch tests a single rule against an EvalContext to determine if it
// would match, as the Evaluator matches it. This is used for dry-run/impact
// preview without affecting enforcement. The entry is compiled on the fly;
// the packet path matches entries compiled once per snapshot.
func PreviewMatch(entry Entry, ctx EvalContext) bool {
	ce := compileEntry(entry)
	return ce.matches(ctx)
}

// AddressScopeMatch reports whether the zones and addresses of the
// snapshot's firewall entry i hold ctx. Its protocols, identities, ICS
// predicate and schedule are not consulted. It allocates nothing.
func (e *Evaluator) AddressScopeMatch(i int, ctx EvalContext) bool {
	ce := &e.compiled[i]
	return matchZones(&ce.Entry, ctx) && matchCIDRs(ce, ctx)
}

func (e *Evaluator) Evaluate(ctx EvalContext) Action {
	action, _ := e.EvaluateMatch(ctx)
	return action
}

// EvaluateMatch returns the decision for ctx and the deciding Entry, or nil
// when the default decides. Any matching ALLOW wins; otherwise the first
// matching DENY or RESET by rule ID decides (DecisionOrder). RATE_LIMIT and
// TAG entries never decide.
func (e *Evaluator) EvaluateMatch(ctx EvalContext) (Action, *Entry) {
	if e.snapshot == nil {
		return ActionDeny, nil
	}
	for _, i := range e.decide {
		if ce := &e.compiled[i]; ce.matches(ctx) {
			return ce.Action, &ce.Entry
		}
	}
	// Like the nftables chain policy, only an explicit ALLOW default admits.
	if e.snapshot.Default == ActionAllow {
		return ActionAllow, nil
	}
	return ActionDeny, nil
}

func matchZones(entry *Entry, ctx EvalContext) bool {
	if len(entry.SourceZones) > 0 && !contains(entry.SourceZones, ctx.SrcZone) {
		return false
	}
	if len(entry.DestZones) > 0 && !contains(entry.DestZones, ctx.DstZone) {
		return false
	}
	return true
}

func matchCIDRs(ce *compiledEntry, ctx EvalContext) bool {
	return ce.src.holds(ctx.SrcIP) && ce.dst.holds(ctx.DstIP)
}

// matchProtoCompiled uses pre-parsed port ranges for fast evaluation.
func matchProtoCompiled(ce *compiledEntry, ctx EvalContext) bool {
	if len(ce.Protocols) == 0 {
		return true
	}
	for j, p := range ce.Protocols {
		if p.Name != "" && p.Name != ctx.Proto {
			continue
		}
		if p.Port != "" {
			cp := ce.ports[j]
			pv, err := strconv.ParseUint(ctx.Port, 10, 16)
			if err != nil || uint16(pv) < cp.low || uint16(pv) > cp.high {
				continue
			}
		}
		return true
	}
	return false
}

// matchICSCompiled uses pre-parsed addresses for fast evaluation.
func matchICSCompiled(ce *compiledEntry, ctx EvalContext) bool {
	if icsPredicateEmpty(ce.ICS) {
		return true
	}
	if ctx.ICS == nil {
		return false
	}
	if ce.iec != nil {
		return matchIEC104(ce, ctx)
	}
	return matchICSProtocol(ce.ICS, ctx) &&
		matchICSFunctionCode(ce.ICS, ctx) &&
		matchICSUnitID(ce.ICS, ctx) &&
		matchICSAddresses(ce, ctx) &&
		matchICSObjectClass(ce.ICS, ctx) &&
		matchICSDirection(ce.ICS, ctx) &&
		matchICSAccessMode(ce.ICS, ctx)
}

func matchICSProtocol(pred ICSPredicate, ctx EvalContext) bool {
	return pred.Protocol == "" || pred.Protocol == ctx.ICS.Protocol
}

func matchICSFunctionCode(pred ICSPredicate, ctx EvalContext) bool {
	if len(pred.FunctionCode) == 0 {
		return true
	}
	for _, fc := range pred.FunctionCode {
		if fc == ctx.ICS.FunctionCode {
			return true
		}
	}
	return false
}

func matchICSUnitID(pred ICSPredicate, ctx EvalContext) bool {
	if pred.UnitID == nil {
		return true
	}
	return ctx.ICS.UnitID != nil && *pred.UnitID == *ctx.ICS.UnitID
}

// matchICSAddresses applies an address predicate to the spans the message
// touches. A DENY or RESET matches when any span meets the predicate's
// ranges, or when the spans are unknown, so a message whose addresses
// cannot be bounded never slips past a deny. Every other action matches
// only a message with at least one span, all of them inside the ranges:
// an ALLOW never admits addresses beyond what it names, nor a message
// whose addresses are unknown.
func matchICSAddresses(ce *compiledEntry, ctx EvalContext) bool {
	if !ce.addresses.listed {
		return true
	}
	if ce.Action == ActionDeny || ce.Action == ActionReset {
		return ctx.ICS.SpansUnknown || ce.addresses.meetsAny(ctx.ICS.Spans)
	}
	return !ctx.ICS.SpansUnknown && ce.addresses.holdsAll(ctx.ICS.Spans)
}

func matchICSObjectClass(pred ICSPredicate, ctx EvalContext) bool {
	if len(pred.ObjectClasses) == 0 {
		return true
	}
	for _, oc := range pred.ObjectClasses {
		if oc == ctx.ICS.ObjectClass {
			return true
		}
	}
	return false
}

func matchICSDirection(pred ICSPredicate, ctx EvalContext) bool {
	return pred.Direction == "" || pred.Direction == ctx.ICS.Direction
}

func matchICSAccessMode(pred ICSPredicate, ctx EvalContext) bool {
	if pred.ReadOnly && !ctx.ICS.ReadOnly {
		return false
	}
	if pred.WriteOnly && !ctx.ICS.WriteOnly {
		return false
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func icsPredicateEmpty(p ICSPredicate) bool {
	return p.Protocol == "" &&
		len(p.FunctionCode) == 0 &&
		p.UnitID == nil &&
		len(p.Addresses) == 0 &&
		len(p.ObjectClasses) == 0 &&
		p.Direction == "" &&
		!p.ReadOnly &&
		!p.WriteOnly &&
		len(p.TypeIDs) == 0 &&
		len(p.Classes) == 0 &&
		len(p.CA) == 0 &&
		len(p.IOA) == 0
}
