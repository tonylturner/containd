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
)

// LearnedProfile accumulates observed ICS traffic for a single communication pair and protocol.
type LearnedProfile struct {
	Protocol      string          `json:"protocol"`
	SourceIP      string          `json:"sourceIP"`
	DestIP        string          `json:"destIP"`
	UnitIDs       map[uint8]bool  `json:"unitIDs"`
	FunctionCodes map[uint8]bool  `json:"functionCodes"`
	Addresses     map[string]bool `json:"addresses"`
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
	if proto == "" {
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
		p = &LearnedProfile{
			Protocol:      proto,
			SourceIP:      srcIP,
			DestIP:        dstIP,
			UnitIDs:       make(map[uint8]bool),
			FunctionCodes: make(map[uint8]bool),
			Addresses:     make(map[string]bool),
			FirstSeen:     now,
		}
		l.profiles[key] = p
	}

	p.LastSeen = now
	p.PacketCount++

	// Extract function_code.
	if fc, ok := ev.Attributes["function_code"]; ok {
		if v, ok := toUint8(fc); ok {
			p.FunctionCodes[v] = true
		}
	}

	// Extract unit_id.
	if uid, ok := ev.Attributes["unit_id"]; ok {
		if v, ok := toUint8(uid); ok {
			p.UnitIDs[v] = true
		}
	}

	// Extract address.
	if addr, ok := ev.Attributes["address"]; ok {
		if s, ok := addr.(string); ok && s != "" {
			p.Addresses[s] = true
		}
	}

	// Extract is_write.
	if w, ok := ev.Attributes["is_write"]; ok {
		if b, ok := w.(bool); ok {
			if b {
				p.WriteSeen = true
			} else {
				p.ReadSeen = true
			}
		}
	}
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

		fcs := sortedUint8Keys(p.FunctionCodes)
		addrs := sortedStringKeys(p.Addresses)

		ics := config.ICSPredicate{
			Protocol:     p.Protocol,
			FunctionCode: fcs,
			Addresses:    addrs,
			Mode:         "enforce",
		}

		// Set read/write classification.
		if p.ReadSeen && !p.WriteSeen {
			ics.ReadOnly = true
		} else if p.WriteSeen && !p.ReadSeen {
			ics.WriteOnly = true
		}

		// If exactly one unit ID was observed, set it.
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

// toUint8 converts common numeric types to uint8.
func toUint8(v any) (uint8, bool) {
	switch n := v.(type) {
	case uint8:
		return n, true
	case int:
		if n >= 0 && n <= 255 {
			return uint8(n), true
		}
	case int64:
		if n >= 0 && n <= 255 {
			return uint8(n), true
		}
	case float64:
		if n >= 0 && n <= 255 {
			return uint8(n), true
		}
	}
	return 0, false
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

func copyBoolMapStr(m map[string]bool) map[string]bool {
	cp := make(map[string]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
