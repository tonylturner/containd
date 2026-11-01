// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import "net/netip"

// Snapshot is an immutable rule set used by the data-plane fast path.
// It is intended to be hot-swapped atomically by the engine.
type Snapshot struct {
	// AdmissionParity is runtime state, restricted to zero or markabi.ParityBit.
	AdmissionParity   uint32
	ForwardMatches    map[string]ForwardMatch
	LocalIPv4ByDevice map[string][]netip.Addr
	DPIMode           string  // inherited ICS mode for this snapshot
	Version           string  // compiled rule version
	Firewall          []Entry // firewall rules
	// LocalInput are rules applied to traffic destined to the appliance itself (nftables input).
	// This is used for management plane, VPN listeners, etc.
	LocalInput []LocalServiceRule
	NAT        NATConfig
	IDS        IDSConfig
	// ZoneIfaces maps zone name -> interface names. Used for nftables bindings.
	ZoneIfaces map[string][]string
	Default    Action
	// IdentityBindings tag opener IPs with identity labels, sorted by IP.
	IdentityBindings []IdentityBinding
	// Gate is the scan selection the engine steers through the scanning gate.
	Gate GateSelection
}

// IdentityBinding tags one address with identity labels.
type IdentityBinding struct {
	IP         string
	Identities []string
}

// LocalServiceRule is a minimal allow rule for traffic destined to the appliance itself.
// If Ifaces is non-empty, it matches iifname against that set. If Zone is non-empty,
// it matches iifname against the zone interface set. If both are empty, it matches any.
type LocalServiceRule struct {
	ID     string
	Ifaces []string
	Zone   string
	Proto  string // tcp|udp
	Port   int
	// RecoverUnbound is set only for a management listener with logical grants.
	// Resolve in the engine namespace; an empty resolved set MUST omit the rule,
	// never turn it into an unconstrained allow.
	RecoverUnbound bool
	DeniedIfaces   []string
}

type NATConfig struct {
	Enabled      bool
	EgressZone   string
	SourceZones  []string
	PortForwards []PortForward
}

type PortForward struct {
	ID             string
	Enabled        bool
	Description    string
	IngressZone    string
	Proto          string
	ListenAddress  string
	ListenPort     int
	DestIP         string
	DestPort       int
	AllowedSources []string
}

// SchedulePredicate restricts a rule to a recurring time window.
type SchedulePredicate struct {
	DaysOfWeek []string // e.g. ["Monday","Tuesday"]
	StartTime  string   // HH:MM
	EndTime    string   // HH:MM
	Timezone   string   // IANA timezone
}

type Entry struct {
	ViaForwards  []string
	ID           string
	SourceZones  []string
	DestZones    []string
	Sources      []string
	Destinations []string
	Protocols    []Protocol
	Action       Action
	RateLimit    *RateLimit // RATE_LIMIT only
	Tag          string     // TAG only
	Log          bool       // log matching traffic
	// Identities restricts the entry to flows whose opener address is bound
	// (Snapshot.IdentityBindings) to any of these labels.
	Identities []string
	ICS        ICSPredicate
	Schedule   SchedulePredicate
}

// HasIdentityPredicate reports whether the entry is restricted to flows of
// the listed identities.
func (e Entry) HasIdentityPredicate() bool {
	return len(e.Identities) > 0
}

// HasSchedulePredicate reports whether the entry is restricted to a
// recurring time window. A timezone alone is no restriction.
func (e Entry) HasSchedulePredicate() bool {
	return !schedulePredicateEmpty(e.Schedule)
}

type Action string

// Actions mirror config.Action. ALLOW, DENY and RESET are terminal, with
// configured first-match order; RATE_LIMIT and TAG are effects that never decide.
const (
	ActionAllow     Action = "ALLOW"
	ActionDeny      Action = "DENY"
	ActionReset     Action = "RESET"
	ActionRateLimit Action = "RATE_LIMIT"
	ActionTag       Action = "TAG"
)

// RateLimit is a packet policer for one directional 5-tuple.
type RateLimit struct {
	PacketsPerSecond uint32
	Burst            uint32
}

type Protocol struct {
	Name string
	Port string // single or range
}

// ICSPredicate captures ICS-specific fields for all supported protocols.
type ICSPredicate struct {
	Protocol      string   // modbus, dnp3, cip, iec104
	FunctionCode  []uint8  // function/service codes (all protocols)
	UnitID        *uint8   // optional Modbus unit id
	Addresses     []string // address/register ranges as strings
	ObjectClasses []uint16 // CIP object classes
	ReadOnly      bool     // read-only class
	WriteOnly     bool     // write-only class
	Direction     string   // "request", "response", or "" (both)
	Mode          string   // "monitor" or "enforce"

	// IEC 60870-5-104 predicates. The Snapshot is JSON-marshalled to the
	// engine, so TypeIDs is []int: []uint8 would encode as base64.
	TypeIDs []int      `json:"typeIds,omitempty"` // 1..255
	Classes []string   `json:"classes,omitempty"` // monitor|control|system|unknown
	CA      []uint16   `json:"ca,omitempty"`      // 0..65534
	IOA     []IOARange `json:"ioa,omitempty"`
	// IEC 104 COT, originator, P/N, T and S/E predicates.
	COT               []int  `json:"cot,omitempty"`
	Originators       []int  `json:"originators,omitempty"`
	Negative          *bool  `json:"negative,omitempty"`
	Test              *bool  `json:"test,omitempty"`
	SelectExecute     string `json:"selectExecute,omitempty"`
	CommandStates     []int  `json:"commandStates,omitempty"`
	CommandQualifiers []int  `json:"commandQualifiers,omitempty"`

	// DNP3 station and object predicates; Addresses are point indexes.
	Masters     []uint16 `json:"masters,omitempty"`
	Outstations []uint16 `json:"outstations,omitempty"`
	Groups      []int    `json:"groups,omitempty"`
	Variations  []int    `json:"variations,omitempty"`

	// CIP target predicates beside ObjectClasses.
	Instances  []uint16 `json:"instances,omitempty"`
	Attributes []uint16 `json:"attributes,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// IOARange is a closed IEC104 information object address range,
// endpoints 0..16777215.
type IOARange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}
