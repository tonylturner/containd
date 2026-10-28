// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package learn

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// LearnedProfile accumulates observed ICS traffic for a single communication pair and protocol.
type LearnedProfile struct {
	Protocol      string          `json:"protocol"`
	SourceIP      string          `json:"sourceIP"`
	DestIP        string          `json:"destIP"`
	UnitIDs       map[uint8]bool  `json:"unitIDs,omitempty"`
	FunctionCodes map[uint8]bool  `json:"functionCodes,omitempty"`
	Addresses     map[string]bool `json:"addresses,omitempty"`
	ServiceCodes  map[uint16]bool `json:"serviceCodes,omitempty"`  // CIP service codes
	ObjectClasses map[uint16]bool `json:"objectClasses,omitempty"` // CIP object classes
	ReadSeen      bool            `json:"readSeen"`
	WriteSeen     bool            `json:"writeSeen"`
	FirstSeen     time.Time       `json:"firstSeen"`
	LastSeen      time.Time       `json:"lastSeen"`
	PacketCount   int             `json:"packetCount"`
}

// Learner passively records ICS traffic and generates allowlist rules.
type Learner struct {
	mu       sync.RWMutex
	profiles map[string]*LearnedProfile // keyed by "srcIP:dstIP:protocol"
}

// New creates a new Learner.
func New() *Learner {
	return &Learner{
		profiles: make(map[string]*LearnedProfile),
	}
}

// RecordEvent updates the learned profile for a communication pair based on a DPI event.
func (l *Learner) RecordEvent(srcIP, dstIP string, ev dpi.Event) {
	proto := strings.ToLower(ev.Proto)
	if !ics.Learnable(proto) {
		return
	}

	key := srcIP + ":" + dstIP + ":" + proto
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	p, ok := l.profiles[key]
	if !ok {
		p = newLearnedProfile(proto, srcIP, dstIP, now)
		l.profiles[key] = p
	}

	updateProfileMetadata(p, now)
	recordProtocolAttributes(proto, p, ev)
	recordReadWriteState(p, ev)
}

func newLearnedProfile(proto, srcIP, dstIP string, now time.Time) *LearnedProfile {
	return &LearnedProfile{
		Protocol:      proto,
		SourceIP:      srcIP,
		DestIP:        dstIP,
		UnitIDs:       make(map[uint8]bool),
		FunctionCodes: make(map[uint8]bool),
		Addresses:     make(map[string]bool),
		ServiceCodes:  make(map[uint16]bool),
		ObjectClasses: make(map[uint16]bool),
		FirstSeen:     now,
	}
}

func updateProfileMetadata(p *LearnedProfile, now time.Time) {
	p.LastSeen = now
	p.PacketCount++
}

func recordProtocolAttributes(proto string, p *LearnedProfile, ev dpi.Event) {
	switch proto {
	case "cip":
		recordCIPAttributes(p, ev)
	case "dnp3":
		recordDNP3Attributes(p, ev)
	case eventfields.ProtoModbus:
		recordModbusAttributes(p, ev)
	default:
		recordDefaultAttributes(p, ev)
	}
}

func recordCIPAttributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, "service_code"); ok {
		p.FunctionCodes[v] = true
	}
	if v, ok := eventfields.Uint16(ev.Attributes, "object_class"); ok {
		p.ObjectClasses[v] = true
	}
	recordStringAddress(p, ev.Attributes["cip_path"])
}

func recordDNP3Attributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, "function_code"); ok {
		p.FunctionCodes[v] = true
	}
	recordStringAddress(p, ev.Attributes["object_groups"])
}

// recordModbusAttributes records each address span the message touches as
// an address entry, so a rule generated from the profile covers the whole
// spans observed: an ALLOW's address predicate holds a message only when
// every span it touches lies inside the predicate.
func recordModbusAttributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode); ok {
		p.FunctionCodes[v] = true
	}
	if v, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyUnitID); ok {
		p.UnitIDs[v] = true
	}
	spans, _ := modbus.AddressSpans(ev.Attributes)
	for _, sp := range spans {
		if sp.First == sp.Last {
			p.Addresses[fmt.Sprintf("%d", sp.First)] = true
		} else {
			p.Addresses[fmt.Sprintf("%d-%d", sp.First, sp.Last)] = true
		}
	}
}

func recordDefaultAttributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, "function_code"); ok {
		p.FunctionCodes[v] = true
	}
	if v, ok := eventfields.Uint8(ev.Attributes, "unit_id"); ok {
		p.UnitIDs[v] = true
	}
	if addr, ok := ev.Attributes["address"]; ok {
		recordAddressValue(p, addr)
	}
}

func recordStringAddress(p *LearnedProfile, v any) {
	s, ok := v.(string)
	if ok && s != "" {
		p.Addresses[s] = true
	}
}

func recordAddressValue(p *LearnedProfile, v any) {
	switch a := v.(type) {
	case string:
		if a != "" {
			p.Addresses[a] = true
		}
	default:
		s := fmt.Sprintf("%v", a)
		if s != "" {
			p.Addresses[s] = true
		}
	}
}

func recordReadWriteState(p *LearnedProfile, ev dpi.Event) {
	w, ok := ev.Attributes["is_write"]
	if !ok {
		return
	}
	b, ok := w.(bool)
	if !ok {
		return
	}
	if b {
		p.WriteSeen = true
		return
	}
	p.ReadSeen = true
}

// Profiles returns a copy of all learned profiles.
func (l *Learner) Profiles() []LearnedProfile {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]LearnedProfile, 0, len(l.profiles))
	for _, p := range l.profiles {
		cp := *p
		cp.UnitIDs = copyBoolMap8(p.UnitIDs)
		cp.FunctionCodes = copyBoolMap8(p.FunctionCodes)
		cp.Addresses = copyBoolMapStr(p.Addresses)
		cp.ServiceCodes = copyBoolMap16(p.ServiceCodes)
		cp.ObjectClasses = copyBoolMap16(p.ObjectClasses)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceIP != out[j].SourceIP {
			return out[i].SourceIP < out[j].SourceIP
		}
		if out[i].DestIP != out[j].DestIP {
			return out[i].DestIP < out[j].DestIP
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// GenerateRules converts learned profiles into firewall rules.
func (l *Learner) GenerateRules() []config.Rule {
	profiles := l.Profiles()
	rules := make([]config.Rule, 0, len(profiles))

	for _, p := range profiles {
		ruleID := fmt.Sprintf("learned-%s-%s-%s", p.Protocol, sanitizeIP(p.SourceIP), sanitizeIP(p.DestIP))

		// Merge service codes that fit in uint8 into FunctionCodes for rule generation.
		mergedFCs := copyBoolMap8(p.FunctionCodes)
		for sc := range p.ServiceCodes {
			if sc <= 255 {
				mergedFCs[uint8(sc)] = true
			}
		}

		fcs := sortedUint8Keys(mergedFCs)
		addrs := sortedStringKeys(p.Addresses)

		// Mode stays empty: a learned rule inherits the global DPI mode, so
		// it enforces only where enforce is configured and has an inline path.
		ics := config.ICSPredicate{
			Protocol:     p.Protocol,
			FunctionCode: fcs,
			Addresses:    addrs,
		}

		// Set read/write classification.
		if p.ReadSeen && !p.WriteSeen {
			ics.ReadOnly = true
		} else if p.WriteSeen && !p.ReadSeen {
			ics.WriteOnly = true
		}

		// If exactly one unit ID was observed, set it (Modbus-specific).
		if len(p.UnitIDs) == 1 {
			for uid := range p.UnitIDs {
				v := uid
				ics.UnitID = &v
			}
		}

		r := config.Rule{
			ID:           ruleID,
			Description:  fmt.Sprintf("Auto-learned %s rule (%s -> %s)", p.Protocol, p.SourceIP, p.DestIP),
			Sources:      []string{p.SourceIP + "/32"},
			Destinations: []string{p.DestIP + "/32"},
			ICS:          ics,
			Action:       config.ActionAllow,
		}
		rules = append(rules, r)
	}
	return rules
}

// Clear resets all learned data.
func (l *Learner) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.profiles = make(map[string]*LearnedProfile)
}

func sanitizeIP(ip string) string {
	return strings.ReplaceAll(ip, ":", "-")
}

func sortedUint8Keys(m map[uint8]bool) []uint8 {
	if len(m) == 0 {
		return nil
	}
	out := make([]uint8, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedStringKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func copyBoolMap8(m map[uint8]bool) map[uint8]bool {
	cp := make(map[uint8]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func copyBoolMap16(m map[uint16]bool) map[uint16]bool {
	cp := make(map[uint16]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func copyBoolMapStr(m map[string]bool) map[string]bool {
	cp := make(map[string]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
