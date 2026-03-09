// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"net"
	"strconv"
	"strings"
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
	Address      string
	ObjectClass  uint16
	ReadOnly     bool
	WriteOnly    bool
	Direction    string // "request" or "response"
}

// compiledAddr holds a pre-parsed ICS address or address range.
type compiledAddr struct {
	low, high int64
}

// compiledPort holds a pre-parsed protocol port or port range.
type compiledPort struct {
	low, high uint16
}

// compiledEntry pairs an Entry with pre-parsed address and port data so that
// string parsing is done once at load time rather than on every packet.
type compiledEntry struct {
	Entry
	addresses []compiledAddr // pre-parsed ICS addresses
	ports     []compiledPort // pre-parsed protocol port ranges (one per Protocol)
}

// Evaluator evaluates a snapshot for a given context and returns an action.
type Evaluator struct {
	snapshot *Snapshot
	compiled []compiledEntry
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
		ce := compiledEntry{Entry: entry}

		// Pre-parse ICS addresses.
		if len(entry.ICS.Addresses) > 0 {
			ce.addresses = make([]compiledAddr, 0, len(entry.ICS.Addresses))
			for _, spec := range entry.ICS.Addresses {
				if parts := strings.SplitN(spec, "-", 2); len(parts) == 2 {
					low, okLow := parseAddr(parts[0])
					high, okHigh := parseAddr(parts[1])
					if okLow && okHigh {
						ce.addresses = append(ce.addresses, compiledAddr{low: low, high: high})
						continue
					}
				}
				// Single value.
				if val, ok := parseAddr(spec); ok {
					ce.addresses = append(ce.addresses, compiledAddr{low: val, high: val})
				}
			}
		}

		// Pre-parse protocol port ranges.
		ce.ports = make([]compiledPort, len(entry.Protocols))
		for j, p := range entry.Protocols {
			if p.Port == "" {
				continue
			}
			if parts := strings.SplitN(p.Port, "-", 2); len(parts) == 2 {
				lo, errLo := strconv.ParseUint(parts[0], 10, 16)
				hi, errHi := strconv.ParseUint(parts[1], 10, 16)
				if errLo == nil && errHi == nil {
					ce.ports[j] = compiledPort{low: uint16(lo), high: uint16(hi)}
					continue
				}
			}
			// Single port.
			v, err := strconv.ParseUint(p.Port, 10, 16)
			if err == nil {
				ce.ports[j] = compiledPort{low: uint16(v), high: uint16(v)}
			}
		}

		e.compiled[i] = ce
	}
}

// CompileEntry pre-parses a single Entry for preview matching.
// This avoids creating a full Evaluator/Snapshot for dry-run scenarios.
func CompileEntry(entry Entry) compiledEntry {
	ce := compiledEntry{Entry: entry}

	// Pre-parse ICS addresses.
	if len(entry.ICS.Addresses) > 0 {
		ce.addresses = make([]compiledAddr, 0, len(entry.ICS.Addresses))
		for _, spec := range entry.ICS.Addresses {
			if parts := strings.SplitN(spec, "-", 2); len(parts) == 2 {
				low, okLow := parseAddr(parts[0])
				high, okHigh := parseAddr(parts[1])
				if okLow && okHigh {
					ce.addresses = append(ce.addresses, compiledAddr{low: low, high: high})
					continue
				}
			}
			if val, ok := parseAddr(spec); ok {
				ce.addresses = append(ce.addresses, compiledAddr{low: val, high: val})
			}
		}
	}

	// Pre-parse protocol port ranges.
	ce.ports = make([]compiledPort, len(entry.Protocols))
	for j, p := range entry.Protocols {
		if p.Port == "" {
			continue
		}
		if parts := strings.SplitN(p.Port, "-", 2); len(parts) == 2 {
			lo, errLo := strconv.ParseUint(parts[0], 10, 16)
			hi, errHi := strconv.ParseUint(parts[1], 10, 16)
			if errLo == nil && errHi == nil {
				ce.ports[j] = compiledPort{low: uint16(lo), high: uint16(hi)}
				continue
			}
		}
		v, err := strconv.ParseUint(p.Port, 10, 16)
		if err == nil {
			ce.ports[j] = compiledPort{low: uint16(v), high: uint16(v)}
		}
	}

	return ce
}

// PreviewMatch tests a single rule against an EvalContext to determine if it
// would match. This is used for dry-run/impact preview without affecting
// enforcement. The entry is compiled on the fly for predicate evaluation.
func PreviewMatch(entry Entry, ctx EvalContext) bool {
	ce := CompileEntry(entry)
	return matchZones(ce.Entry, ctx) &&
		matchCIDRs(ce.Entry, ctx) &&
		matchProtoCompiled(&ce, ctx) &&
		matchIdentities(ce.Entry, ctx) &&
		matchICSCompiled(&ce, ctx) &&
		matchSchedule(ce.Entry, ctx)
}

func (e *Evaluator) Evaluate(ctx EvalContext) Action {
	if e.snapshot == nil {
		return ActionDeny
	}
	for i := range e.compiled {
		ce := &e.compiled[i]
		if matchZones(ce.Entry, ctx) && matchCIDRs(ce.Entry, ctx) && matchProtoCompiled(ce, ctx) && matchIdentities(ce.Entry, ctx) && matchICSCompiled(ce, ctx) && matchSchedule(ce.Entry, ctx) {
			return ce.Action
		}
	}
	if e.snapshot.Default != "" {
		return e.snapshot.Default
	}
	return ActionDeny
}

func matchZones(entry Entry, ctx EvalContext) bool {
	if len(entry.SourceZones) > 0 && !contains(entry.SourceZones, ctx.SrcZone) {
		return false
	}
	if len(entry.DestZones) > 0 && !contains(entry.DestZones, ctx.DstZone) {
		return false
	}
	return true
}

func matchCIDRs(entry Entry, ctx EvalContext) bool {
	if len(entry.Sources) > 0 && !ipInCIDRs(ctx.SrcIP, entry.Sources) {
		return false
	}
	if len(entry.Destinations) > 0 && !ipInCIDRs(ctx.DstIP, entry.Destinations) {
		return false
	}
	return true
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

func matchIdentities(entry Entry, ctx EvalContext) bool {
	if len(entry.Identities) == 0 {
		return true
	}
	if len(ctx.Identities) == 0 {
		return false
	}
	for _, id := range entry.Identities {
		if id == "" {
			continue
		}
		for _, got := range ctx.Identities {
			if id == got {
				return true
			}
		}
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
	if ce.ICS.Protocol != "" && ce.ICS.Protocol != ctx.ICS.Protocol {
		return false
	}
	if len(ce.ICS.FunctionCode) > 0 {
		match := false
		for _, fc := range ce.ICS.FunctionCode {
			if fc == ctx.ICS.FunctionCode {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if ce.ICS.UnitID != nil {
		if ctx.ICS.UnitID == nil || *ce.ICS.UnitID != *ctx.ICS.UnitID {
			return false
		}
	}
	if len(ce.addresses) > 0 {
		ctxVal, ok := parseAddr(ctx.ICS.Address)
		if !ok {
			return false
		}
		matched := false
		for _, a := range ce.addresses {
			if ctxVal >= a.low && ctxVal <= a.high {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(ce.ICS.ObjectClasses) > 0 {
		match := false
		for _, oc := range ce.ICS.ObjectClasses {
			if oc == ctx.ICS.ObjectClass {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if ce.ICS.Direction != "" && ce.ICS.Direction != ctx.ICS.Direction {
		return false
	}
	if ce.ICS.ReadOnly && !ctx.ICS.ReadOnly {
		return false
	}
	if ce.ICS.WriteOnly && !ctx.ICS.WriteOnly {
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
		!p.WriteOnly
}

// parseAddr parses a numeric address string supporting both decimal and hex (0x prefix).
func parseAddr(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return v, err == nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// matchAddress checks whether contextAddr falls within any of the entry address
// specifications. Each entry may be a single value ("0x0100", "256") or a
// dash-separated range ("0x0100-0x01FF", "100-511"). Both hex (0x prefix) and
// decimal formats are supported, and they may be mixed.
func matchAddress(entryAddrs []string, contextAddr string) bool {
	ctxVal, ok := parseAddr(contextAddr)
	if !ok {
		return false
	}
	for _, spec := range entryAddrs {
		if parts := strings.SplitN(spec, "-", 2); len(parts) == 2 {
			// Disambiguate: if the first part starts with "0x"/"0X" and the
			// second part also starts with "0x"/"0X", treat as range. Also
			// handle the case where neither part has a prefix (pure decimal
			// range). For a hex prefix on part1 but not part2, it could be
			// ambiguous (e.g. "0x10-20"); we handle it by checking if
			// part2 parses as a standalone value.
			low, okLow := parseAddr(parts[0])
			high, okHigh := parseAddr(parts[1])
			if okLow && okHigh {
				if ctxVal >= low && ctxVal <= high {
					return true
				}
				continue
			}
		}
		// Single value.
		val, ok := parseAddr(spec)
		if ok && val == ctxVal {
			return true
		}
	}
	return false
}

func ipInCIDRs(ip net.IP, cidrs []string) bool {
	for _, c := range cidrs {
		if _, network, err := net.ParseCIDR(c); err == nil {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func schedulePredicateEmpty(s SchedulePredicate) bool {
	return len(s.DaysOfWeek) == 0 && s.StartTime == "" && s.EndTime == ""
}

func matchSchedule(entry Entry, ctx EvalContext) bool {
	if schedulePredicateEmpty(entry.Schedule) {
		return true
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}
	// Convert to the rule's timezone if specified.
	if entry.Schedule.Timezone != "" {
		loc, err := time.LoadLocation(entry.Schedule.Timezone)
		if err != nil {
			return false
		}
		now = now.In(loc)
	}
	// Check day of week.
	if len(entry.Schedule.DaysOfWeek) > 0 {
		day := now.Weekday().String()
		found := false
		for _, d := range entry.Schedule.DaysOfWeek {
			if d == day {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Check time window.
	hasStart := entry.Schedule.StartTime != ""
	hasEnd := entry.Schedule.EndTime != ""
	if hasStart || hasEnd {
		hhmm := formatHHMM(now.Hour(), now.Minute())
		if hasStart && hasEnd {
			if entry.Schedule.StartTime <= entry.Schedule.EndTime {
				// Normal range, e.g. 09:00–17:00.
				if hhmm < entry.Schedule.StartTime || hhmm > entry.Schedule.EndTime {
					return false
				}
			} else {
				// Overnight range, e.g. 22:00–06:00.
				if hhmm < entry.Schedule.StartTime && hhmm > entry.Schedule.EndTime {
					return false
				}
			}
		} else if hasStart {
			if hhmm < entry.Schedule.StartTime {
				return false
			}
		} else {
			if hhmm > entry.Schedule.EndTime {
				return false
			}
		}
	}
	return true
}

// formatHHMM returns "HH:MM" without fmt.Sprintf allocation.
func formatHHMM(h, m int) string {
	return string([]byte{
		byte('0' + h/10), byte('0' + h%10),
		':',
		byte('0' + m/10), byte('0' + m%10),
	})
}
