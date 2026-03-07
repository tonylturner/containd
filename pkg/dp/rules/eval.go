// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"fmt"
	"net"
	"strconv"
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
		if matchZones(entry, ctx) && matchCIDRs(entry, ctx) && matchProto(entry, ctx) && matchIdentities(entry, ctx) && matchICS(entry, ctx) {
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
		addrMatch := false
		for _, addr := range entry.ICS.Addresses {
			if addr == ctx.ICS.Address {
				addrMatch = true
				break
			}
		}
		if !addrMatch {
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
