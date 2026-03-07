// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"fmt"
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
	ReadOnly     bool
	WriteOnly    bool
}

// Evaluator evaluates a snapshot for a given context and returns an action.
type Evaluator struct {
	snapshot *Snapshot
}

func NewEvaluator(snap *Snapshot) *Evaluator {
	return &Evaluator{snapshot: snap}
}

func (e *Evaluator) Evaluate(ctx EvalContext) Action {
	if e.snapshot == nil {
		return ActionDeny
	}
	for _, entry := range e.snapshot.Firewall {
		if matchZones(entry, ctx) && matchCIDRs(entry, ctx) && matchProto(entry, ctx) && matchIdentities(entry, ctx) && matchICS(entry, ctx) && matchSchedule(entry, ctx) {
			return entry.Action
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

func matchProto(entry Entry, ctx EvalContext) bool {
	if len(entry.Protocols) == 0 {
		return true
	}
	for _, p := range entry.Protocols {
		if p.Name != "" && p.Name != ctx.Proto {
			continue
		}
		if p.Port != "" {
			if !portMatches(p.Port, ctx.Port) {
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

func matchICS(entry Entry, ctx EvalContext) bool {
	if icsPredicateEmpty(entry.ICS) {
		return true
	}
	if ctx.ICS == nil {
		return false
	}
	if entry.ICS.Protocol != "" && entry.ICS.Protocol != ctx.ICS.Protocol {
		return false
	}
	if len(entry.ICS.FunctionCode) > 0 {
		match := false
		for _, fc := range entry.ICS.FunctionCode {
			if fc == ctx.ICS.FunctionCode {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if entry.ICS.UnitID != nil {
		if ctx.ICS.UnitID == nil || *entry.ICS.UnitID != *ctx.ICS.UnitID {
			return false
		}
	}
	if len(entry.ICS.Addresses) > 0 {
		if !matchAddress(entry.ICS.Addresses, ctx.ICS.Address) {
			return false
		}
	}
	if entry.ICS.ReadOnly && !ctx.ICS.ReadOnly {
		return false
	}
	if entry.ICS.WriteOnly && !ctx.ICS.WriteOnly {
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

// portMatches supports single ports and ranges like "1000-2000".
func portMatches(pattern, port string) bool {
	if pattern == "" {
		return true
	}
	if pattern == port {
		return true
	}
	var low, high int
	if n, err := fmt.Sscanf(pattern, "%d-%d", &low, &high); err == nil && n == 2 {
		if p, err := strconv.Atoi(port); err == nil {
			return p >= low && p <= high
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
	if entry.Schedule.StartTime != "" && entry.Schedule.EndTime != "" {
		hhmm := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
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
	} else if entry.Schedule.StartTime != "" {
		hhmm := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
		if hhmm < entry.Schedule.StartTime {
			return false
		}
	} else if entry.Schedule.EndTime != "" {
		hhmm := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
		if hhmm > entry.Schedule.EndTime {
			return false
		}
	}
	return true
}
