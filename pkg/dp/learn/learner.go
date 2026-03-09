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
	Protocol      string           `json:"protocol"`
	SourceIP      string           `json:"sourceIP"`
	DestIP        string           `json:"destIP"`
	UnitIDs       map[uint8]bool   `json:"unitIDs,omitempty"`
	FunctionCodes map[uint8]bool   `json:"functionCodes,omitempty"`
	Addresses     map[string]bool  `json:"addresses,omitempty"`
	ServiceCodes  map[uint16]bool  `json:"serviceCodes,omitempty"`  // CIP/OPC UA service codes > 255
	ObjectClasses map[uint16]bool  `json:"objectClasses,omitempty"` // CIP object classes
	ReadSeen      bool             `json:"readSeen"`
	WriteSeen     bool             `json:"writeSeen"`
	FirstSeen     time.Time        `json:"firstSeen"`
	LastSeen      time.Time        `json:"lastSeen"`
	PacketCount   int              `json:"packetCount"`
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
			ServiceCodes:  make(map[uint16]bool),
			ObjectClasses: make(map[uint16]bool),
			FirstSeen:     now,
		}
		l.profiles[key] = p
	}

	p.LastSeen = now
	p.PacketCount++

	// Extract protocol-specific attributes and normalize them.
	switch proto {
	case "cip":
		// CIP: service_code (uint8) → FunctionCodes, object_class (uint16) → ObjectClasses,
		// cip_path → Addresses.
		if sc, ok := ev.Attributes["service_code"]; ok {
			if v, ok := toUint8(sc); ok {
				p.FunctionCodes[v] = true
			}
		}
		if oc, ok := ev.Attributes["object_class"]; ok {
			if v, ok := toUint16(oc); ok {
				p.ObjectClasses[v] = true
			}
		}
		if cp, ok := ev.Attributes["cip_path"]; ok {
			if s, ok := cp.(string); ok && s != "" {
				p.Addresses[s] = true
			}
		}

	case "dnp3":
		// DNP3: function_code (uint8), object_groups (string) → Addresses.
		if fc, ok := ev.Attributes["function_code"]; ok {
			if v, ok := toUint8(fc); ok {
				p.FunctionCodes[v] = true
			}
		}
		if og, ok := ev.Attributes["object_groups"]; ok {
			if s, ok := og.(string); ok && s != "" {
				p.Addresses[s] = true
			}
		}

	case "s7comm":
		// S7comm: function_code (uint8), address (string like "DB1.DBW0").
		if fc, ok := ev.Attributes["function_code"]; ok {
			if v, ok := toUint8(fc); ok {
				p.FunctionCodes[v] = true
			}
		}
		if addr, ok := ev.Attributes["address"]; ok {
			if s, ok := addr.(string); ok && s != "" {
				p.Addresses[s] = true
			}
		}

	case "bacnet":
		// BACnet: service_code (uint8) → FunctionCodes,
		// object_type + object_instance → Addresses.
		if sc, ok := ev.Attributes["service_code"]; ok {
			if v, ok := toUint8(sc); ok {
				p.FunctionCodes[v] = true
			}
		}
		// Build address from object type and instance if available.
		objType, hasType := ev.Attributes["object_type"]
		objInst, hasInst := ev.Attributes["object_instance"]
		if hasType && hasInst {
			s := fmt.Sprintf("%v/%v", objType, objInst)
			p.Addresses[s] = true
		}

	case "opcua":
		// OPC UA: service (string) for display, service node ID may be uint16 > 255.
		if svc, ok := ev.Attributes["service"]; ok {
			if s, ok := svc.(string); ok && s != "" {
				p.Addresses[s] = true
			}
		}
		// OPC UA service node IDs are not directly emitted as an attribute in
		// the decoder, but if present they would be uint16. The service name
		// is what we capture as an address for rule visibility.

	case "mms":
		// MMS: service_tag (string like "0xA5") → parse to uint8 → FunctionCodes,
		// variable_name (string) → Addresses.
		if st, ok := ev.Attributes["service_tag"]; ok {
			if s, ok := st.(string); ok {
				if v, ok := parseHexUint8(s); ok {
					p.FunctionCodes[v] = true
				}
			}
		}
		if vn, ok := ev.Attributes["variable_name"]; ok {
			if s, ok := vn.(string); ok && s != "" {
				p.Addresses[s] = true
			}
		}

	default:
		// Modbus and any other protocol: use generic attribute names.
		if fc, ok := ev.Attributes["function_code"]; ok {
			if v, ok := toUint8(fc); ok {
				p.FunctionCodes[v] = true
			}
		}
		if uid, ok := ev.Attributes["unit_id"]; ok {
			if v, ok := toUint8(uid); ok {
				p.UnitIDs[v] = true
			}
		}
		if addr, ok := ev.Attributes["address"]; ok {
			switch a := addr.(type) {
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
	}

	// Extract is_write (common across all protocols).
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

// toUint16 converts common numeric types to uint16.
func toUint16(v any) (uint16, bool) {
	switch n := v.(type) {
	case uint16:
		return n, true
	case uint8:
		return uint16(n), true
	case int:
		if n >= 0 && n <= 65535 {
			return uint16(n), true
		}
	case int64:
		if n >= 0 && n <= 65535 {
			return uint16(n), true
		}
	case float64:
		if n >= 0 && n <= 65535 {
			return uint16(n), true
		}
	}
	return 0, false
}

// parseHexUint8 parses a hex string like "0xA5" into a uint8.
func parseHexUint8(s string) (uint8, bool) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, false
	}
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint64(c - 'A' + 10)
		default:
			return 0, false
		}
		if v > 255 {
			return 0, false
		}
	}
	return uint8(v), true
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
