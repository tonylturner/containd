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
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
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
	mu           sync.RWMutex
	profiles     map[string]*LearnedProfile // keyed by "srcIP:dstIP:protocol"
	observations map[learnedTuple]*learnedObservation
}

// learnedTuple is the complete predicate tuple represented by one generated
// rule. Unit IDs apply only to Modbus; the other protocols use hasUnit=false.
type learnedTuple struct {
	protocol string
	source   string
	dest     string
	unitID   uint8
	hasUnit  bool
	fc       uint8
}

type learnedObservation struct {
	addresses     map[string]bool
	objectClasses map[uint16]bool
	readSeen      bool
	writeSeen     bool
}

// New creates a new Learner.
func New() *Learner {
	return &Learner{
		profiles:     make(map[string]*LearnedProfile),
		observations: make(map[learnedTuple]*learnedObservation),
	}
}

// RecordEvent updates the learned profile for a communication pair based on a DPI event.
func (l *Learner) RecordEvent(srcIP, dstIP string, ev dpi.Event) {
	if codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance); len(codes) > 0 {
		return
	}
	proto := strings.ToLower(ev.Proto)
	if !ics.Learnable(proto) || !isRequestEvent(proto, ev) {
		return
	}

	tuple, addresses, learnable := learnableTupleForEvent(proto, srcIP, dstIP, ev)
	if !learnable {
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

	observation, ok := l.observations[tuple]
	if !ok {
		observation = &learnedObservation{
			addresses:     make(map[string]bool),
			objectClasses: make(map[uint16]bool),
		}
		l.observations[tuple] = observation
	}
	for _, address := range addresses {
		observation.addresses[address] = true
	}
	if proto == "cip" {
		objectClass, ok := eventfields.Uint16(ev.Attributes, "object_class")
		if !ok {
			objectClass = 0
		}
		observation.objectClasses[objectClass] = true
	}
	if isWrite, ok := eventfields.Bool(ev.Attributes, eventfields.KeyIsWrite); ok {
		if isWrite {
			observation.writeSeen = true
		} else {
			observation.readSeen = true
		}
	}
}

func isRequestEvent(proto string, ev dpi.Event) bool {
	if ev.Kind == eventfields.KindRequest {
		return true
	}
	if proto != eventfields.ProtoDNP3 {
		return false
	}
	fc, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
	if !ok {
		return false
	}
	switch ev.Kind {
	case "restart":
		return fc == dnp3.FuncColdRestart || fc == dnp3.FuncWarmRestart
	case "control":
		return fc == dnp3.FuncStopApplication || fc == dnp3.FuncSaveConfiguration
	default:
		return false
	}
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
	}
}

func recordCIPAttributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, "service_code"); ok {
		p.FunctionCodes[v] = true
		p.ServiceCodes[uint16(v)] = true
	}
	if v, ok := eventfields.Uint16(ev.Attributes, "object_class"); ok {
		p.ObjectClasses[v] = true
	}
}

func recordDNP3Attributes(p *LearnedProfile, ev dpi.Event) {
	if v, ok := eventfields.Uint8(ev.Attributes, "function_code"); ok {
		p.FunctionCodes[v] = true
	}
}

// recordModbusAttributes adds each decoded span to the aggregate profile
// summary. Rule generation keeps these spans separately by unit and function
// code so an ALLOW cannot combine unrelated observations.
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

func learnableTupleForEvent(proto, srcIP, dstIP string, ev dpi.Event) (learnedTuple, []string, bool) {
	tuple := learnedTuple{protocol: proto, source: srcIP, dest: dstIP}
	switch proto {
	case eventfields.ProtoModbus:
		fc, okFC := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
		unitID, okUnit := eventfields.Uint8(ev.Attributes, eventfields.KeyUnitID)
		if !okFC || !okUnit {
			return learnedTuple{}, nil, false
		}
		spans, okSpans := modbus.AddressSpans(ev.Attributes)
		if !okSpans {
			return learnedTuple{}, nil, false
		}
		tuple.fc = fc
		tuple.unitID = unitID
		tuple.hasUnit = true
		addresses := make([]string, 0, len(spans))
		for _, span := range spans {
			if span.First == span.Last {
				addresses = append(addresses, fmt.Sprintf("%d", span.First))
			} else {
				addresses = append(addresses, fmt.Sprintf("%d-%d", span.First, span.Last))
			}
		}
		return tuple, addresses, true
	case eventfields.ProtoDNP3:
		fc, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
		if !ok {
			return learnedTuple{}, nil, false
		}
		if strings.HasPrefix(dnp3.FunctionCodeName(fc), "unknown_") {
			return learnedTuple{}, nil, false
		}
		tuple.fc = fc
		return tuple, nil, true
	case "cip":
		serviceCode, ok := eventfields.Uint8(ev.Attributes, "service_code")
		if !ok {
			return learnedTuple{}, nil, false
		}
		if strings.HasPrefix(cip.ServiceName(serviceCode), "Unknown(") {
			return learnedTuple{}, nil, false
		}
		if _, present := ev.Attributes["object_class"]; present {
			if _, ok := eventfields.Uint16(ev.Attributes, "object_class"); !ok {
				return learnedTuple{}, nil, false
			}
		}
		tuple.fc = serviceCode
		return tuple, nil, true
	default:
		return learnedTuple{}, nil, false
	}
}

// GenerateRules converts learned profiles into firewall rules.
func (l *Learner) GenerateRules() []config.Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	tuples := make([]learnedTuple, 0, len(l.observations))
	for tuple := range l.observations {
		tuples = append(tuples, tuple)
	}
	sort.Slice(tuples, func(i, j int) bool {
		a, b := tuples[i], tuples[j]
		if a.source != b.source {
			return a.source < b.source
		}
		if a.dest != b.dest {
			return a.dest < b.dest
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		if a.hasUnit != b.hasUnit {
			return !a.hasUnit
		}
		if a.unitID != b.unitID {
			return a.unitID < b.unitID
		}
		return a.fc < b.fc
	})
	generated := make([]config.Rule, 0, len(tuples))

	for _, tuple := range tuples {
		observation := l.observations[tuple]
		unitID := "none"
		icsPredicate := config.ICSPredicate{
			Protocol:     tuple.protocol,
			FunctionCode: []uint8{tuple.fc},
			Direction:    eventfields.KindRequest,
		}
		if tuple.hasUnit {
			unitID = fmt.Sprintf("%d", tuple.unitID)
			unit := tuple.unitID
			icsPredicate.UnitID = &unit
			icsPredicate.Addresses = sortedStringKeys(observation.addresses)
		} else if tuple.protocol == "cip" {
			icsPredicate.ObjectClasses = sortedUint16Keys(observation.objectClasses)
		}

		if observation.readSeen && !observation.writeSeen {
			icsPredicate.ReadOnly = true
		} else if observation.writeSeen && !observation.readSeen {
			icsPredicate.WriteOnly = true
		}

		ruleID := fmt.Sprintf("learned-%s-%s-%s-u%s-fc%02x", tuple.protocol,
			sanitizeIP(tuple.source), sanitizeIP(tuple.dest), unitID, tuple.fc)
		r := config.Rule{
			ID:           ruleID,
			Description:  fmt.Sprintf("Auto-learned %s unit %s function/service 0x%02x (%s -> %s)", tuple.protocol, unitID, tuple.fc, tuple.source, tuple.dest),
			Sources:      []string{tuple.source + "/32"},
			Destinations: []string{tuple.dest + "/32"},
			ICS:          icsPredicate,
			Action:       config.ActionAllow,
		}
		generated = append(generated, r)
	}
	return generated
}

// Clear resets all learned data.
func (l *Learner) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.profiles = make(map[string]*LearnedProfile)
	l.observations = make(map[learnedTuple]*learnedObservation)
}

func sanitizeIP(ip string) string {
	return strings.ReplaceAll(ip, ":", "-")
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

func sortedUint16Keys(m map[uint16]bool) []uint16 {
	if len(m) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
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
