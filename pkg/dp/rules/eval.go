package rules

import (
	"net"
	"fmt"
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
		if matchZones(entry, ctx) && matchCIDRs(entry, ctx) && matchProto(entry, ctx) {
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

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
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
