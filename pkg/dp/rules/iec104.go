// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import "strings"

// ProtocolIEC104 is the ICS protocol name of IEC 60870-5-104 rules and
// events.
const ProtocolIEC104 = "iec104"

// iec104BroadcastCA is the broadcast common address. Object-bearing
// traffic to or from it never matches an ALLOW.
const iec104BroadcastCA = 65535

// IEC104Context is the decoded IEC 60870-5-104 metadata of one object (or
// S/U/error APDU) for rule evaluation. Direction stays in
// ICSContext.Direction. Fields the decoder could not read are nil or empty
// and satisfy no predicate on them; nonconformant content is not SafeRead.
type IEC104Context struct {
	APCIType  string // "I" | "S" | "U"
	TypeID    *uint8
	CA        *uint16
	IOA       *uint32
	Class     string
	SafeRead  bool // iec104.SafeRead
	Broadcast bool // I-frame with CA 65535
	// Cause of transmission, originator, P/N and T bits of the ASDU, and
	// Select (S/E=1) for command types that carry the qualifier; nil
	// when the APDU does not carry the field.
	COT        *uint8
	Originator *uint8
	Negative   *bool
	Test       *bool
	Select     *bool
}

// EffectiveMode resolves an ICS rule's mode: rule mode > global DPI mode >
// learn.
func EffectiveMode(ruleMode, globalMode string) string {
	if m := strings.ToLower(strings.TrimSpace(ruleMode)); m != "" {
		return m
	}
	if m := strings.ToLower(strings.TrimSpace(globalMode)); m != "" {
		return m
	}
	return "learn"
}

// IEC104Envelope reports whether a session falls inside the IEC104
// inspection envelope and the envelope's mode. ctx carries the
// opener-oriented session tuple: source = client, destination = server,
// port 2404. The envelope is the L3/L4 scope (zones, CIDRs, protocol and
// port) of the rules with ics.protocol iec104; ASDU predicates, identities
// and schedules do not narrow it, so it is a superset of what the rules
// can allow and everything inside it that no rule allows is denied. The
// mode is enforce if any matching rule's effective mode is enforce, else
// learn. No match returns (false, "").
func (e *Evaluator) IEC104Envelope(ctx EvalContext, globalMode string) (matched bool, mode string) {
	for i := range e.compiled {
		ce := &e.compiled[i]
		if ce.iec == nil || !matchZones(&ce.Entry, ctx) || !matchCIDRs(ce, ctx) || !matchProtoCompiled(ce, ctx) {
			continue
		}
		matched = true
		if EffectiveMode(ce.ICS.Mode, globalMode) == "enforce" {
			return true, "enforce"
		}
	}
	if matched {
		return true, "learn"
	}
	return false, ""
}

// EvaluateIEC104 evaluates one IEC104 object (or S/U/error APDU) against
// the IEC104 rules only, in DecisionOrder: any matching ALLOW wins, else
// the first matching DENY by rule ID. Other rules, including a broad
// tcp/2404 ALLOW, do not take part. No match is DENY whatever
// firewall.defaultAction says. ctx carries the session tuple, as for
// IEC104Envelope, and ICS.IEC104 must be set.
func (e *Evaluator) EvaluateIEC104(ctx EvalContext) (Action, *Entry) {
	if ctx.ICS == nil || ctx.ICS.IEC104 == nil {
		return ActionDeny, nil
	}
	for _, i := range e.decide {
		if ce := &e.compiled[i]; ce.iec != nil && ce.matches(ctx) {
			return ce.Action, &ce.Entry
		}
	}
	return ActionDeny, nil
}

// compiledIEC104 is an IEC104 predicate parsed once per snapshot.
type compiledIEC104 struct {
	typeIDs    [4]uint64 // bitset over Type IDs 0..255
	hasTypeIDs bool
	classes    []string
	ca         []uint16
	ioa        []IOARange
	// invalid marks a predicate that carries generic fields or writeOnly,
	// which validation rejects for iec104. It never matches.
	invalid bool
}

func compileIEC104(p ICSPredicate) *compiledIEC104 {
	c := &compiledIEC104{
		hasTypeIDs: len(p.TypeIDs) > 0,
		classes:    append([]string(nil), p.Classes...),
		ca:         append([]uint16(nil), p.CA...),
		ioa:        append([]IOARange(nil), p.IOA...),
		invalid: len(p.FunctionCode) > 0 || p.UnitID != nil || len(p.Addresses) > 0 ||
			len(p.ObjectClasses) > 0 || p.WriteOnly,
	}
	for _, id := range p.TypeIDs {
		if id >= 0 && id <= 255 {
			c.typeIDs[id/64] |= 1 << (uint(id) % 64)
		}
	}
	return c
}

// matchIEC104 matches the IEC104 predicate of an entry. Generic
// function-code, unit and address matching never runs on IEC104 events.
// A broadcast object never matches an ALLOW.
func matchIEC104(ce *compiledEntry, ctx EvalContext) bool {
	c, ics := ce.iec, ctx.ICS
	if c.invalid || ics == nil || ics.Protocol != ProtocolIEC104 || ics.IEC104 == nil {
		return false
	}
	obj := ics.IEC104
	if ce.Action == ActionAllow && isIEC104Broadcast(obj) {
		return false
	}
	if ce.ICS.Direction != "" && ce.ICS.Direction != ics.Direction {
		return false
	}
	// readOnly:false is no access constraint; it never means "writes only".
	if ce.ICS.ReadOnly && !obj.SafeRead {
		return false
	}
	if c.hasTypeIDs && (obj.TypeID == nil || c.typeIDs[*obj.TypeID/64]&(1<<(*obj.TypeID%64)) == 0) {
		return false
	}
	if len(c.classes) > 0 && !contains(c.classes, obj.Class) {
		return false
	}
	if len(c.ca) > 0 && (obj.CA == nil || !containsUint16(c.ca, *obj.CA)) {
		return false
	}
	return len(c.ioa) == 0 || (obj.IOA != nil && ioaInRanges(c.ioa, *obj.IOA))
}

func isIEC104Broadcast(obj *IEC104Context) bool {
	return obj.Broadcast || (obj.CA != nil && *obj.CA == iec104BroadcastCA)
}

func containsUint16(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func ioaInRanges(ranges []IOARange, ioa uint32) bool {
	for _, r := range ranges {
		if ioa >= r.Start && ioa <= r.End {
			return true
		}
	}
	return false
}
