// SPDX-License-Identifier: Apache-2.0

// Package coverage reports whether each semantic ICS firewall rule is
// actually enforced: mode alone never proves that a prohibited command is
// stopped. The static evaluation depends only on the rule snapshot and the
// data-plane settings, so a candidate preview and the applied engine agree;
// the engine overlays runtime faults on top of it.
package coverage

// State is the protection a semantic ICS rule provides.
type State string

const (
	// Monitoring: the effective mode is monitor; the rule observes by design.
	Monitoring State = "monitoring"
	// Enforcing: an inline path inspects every flow of the rule's scope.
	Enforcing State = "enforcing"
	// Partial: enforcing, but some flows of the scope can bypass inspection.
	Partial State = "partial"
	// NotEnforcing: the effective mode is enforce, but nothing stops a
	// prohibited command.
	NotEnforcing State = "not_enforcing"
)

// Code names one cause that lowers a rule's state.
type Code string

const (
	// NoInlinePath: nfqueueGroup is zero, so the engine cannot hold or drop.
	NoInlinePath Code = "no-inline-path"
	// EnforcementDisabled: nftables enforcement is off.
	EnforcementDisabled Code = "enforcement-disabled"
	// DPIDisabled: the DPI master switch is off.
	DPIDisabled Code = "dpi-disabled"
	// DecoderDisabled: the rule's protocol decoder is switched off.
	DecoderDisabled Code = "decoder-disabled"
	// QueueUnavailable: runtime only (Reason.Runtime is set); the configured
	// queue is not bound by this engine, so in-scope traffic is dropped by
	// the kernel rather than inspected.
	QueueUnavailable Code = "queue-unavailable"
	// ExclusionOverlap: an IP or CIDR exclusion meets the rule's scope.
	ExclusionOverlap Code = "exclusion-overlap"
	// DomainExclusion: a domain exclusion can resolve into the rule's scope.
	DomainExclusion Code = "domain-exclusion"
)

// Reason is one cause with an operator-facing message. Value names the
// exclusion for exclusion codes. Matches is the runtime count of flows the
// exclusion actually bypassed; zero in static evaluations. Runtime marks a
// reason that only the running engine reports (queue-unavailable); a static
// evaluation of the same snapshot and settings has every other reason, so a
// candidate and an applied rule differ in configuration only when they
// differ after dropping runtime reasons and ignoring Matches.
type Reason struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
	Matches uint64 `json:"matches,omitempty"`
	Runtime bool   `json:"runtime,omitempty"`
}

// Rule is the coverage of one firewall rule with an ICS protocol predicate.
// Mode is the effective mode (rule mode, then global dpiMode, then monitor).
type Rule struct {
	RuleID   string   `json:"ruleId"`
	Protocol string   `json:"protocol"`
	Mode     string   `json:"mode"`
	State    State    `json:"state"`
	Reasons  []Reason `json:"reasons,omitempty"`
}

// Exclusion is a DPI exclusion as the evaluator needs it.
type Exclusion struct {
	Value string
	Type  string // ip, cidr, domain
}

// Settings are the data-plane inputs of a static evaluation. ICSProtocols
// follows dataplane.dpiIcsProtocols: an absent key is enabled.
type Settings struct {
	Enforcement  bool
	QueueID      uint16
	DPIEnabled   bool
	DPIMode      string
	ICSProtocols map[string]bool
	Exclusions   []Exclusion
}
