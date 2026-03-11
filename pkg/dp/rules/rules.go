// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

// Snapshot is an immutable rule set used by the data-plane fast path.
// It is intended to be hot-swapped atomically by the engine.
type Snapshot struct {
	Version  string  // compiled rule version
	Firewall []Entry // firewall rules
	// LocalInput are rules applied to traffic destined to the appliance itself (nftables input).
	// This is used for management plane, VPN listeners, etc.
	LocalInput []LocalServiceRule
	NAT        NATConfig
	IDS        IDSConfig
	// ZoneIfaces maps zone name -> interface names. Used for nftables bindings.
	ZoneIfaces map[string][]string
	Default    Action
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
	ID           string
	SourceZones  []string
	DestZones    []string
	Sources      []string
	Destinations []string
	Protocols    []Protocol
	Action       Action
	Log          bool // log matching traffic
	// Future predicates
	Identities []string // user/group roles
	ICS        ICSPredicate
	Schedule   SchedulePredicate
}

type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

type Protocol struct {
	Name string
	Port string // single or range
}

// ICSPredicate captures ICS-specific fields for all supported protocols.
type ICSPredicate struct {
	Protocol      string   // modbus, dnp3, cip, s7comm, mms, bacnet, opcua
	FunctionCode  []uint8  // function/service codes (all protocols)
	UnitID        *uint8   // optional Modbus unit id
	Addresses     []string // address/register ranges as strings
	ObjectClasses []uint16 // CIP object classes
	ReadOnly      bool     // read-only class
	WriteOnly     bool     // write-only class
	Direction     string   // "request", "response", or "" (both)
	Mode          string   // "learn" or "enforce"
}
