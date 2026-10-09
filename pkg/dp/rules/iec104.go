// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

// IEC104Context is the decoded IEC 60870-5-104 metadata of one object (or
// S/U/error APDU) for rule evaluation. Direction stays in
// ICSContext.Direction.
type IEC104Context struct {
	APCIType    string // "I" | "S" | "U"
	TypeID      *uint8
	CA          *uint16
	IOA         *uint32
	Class       string
	SafeRead    bool // iec104.SafeRead
	Broadcast   bool // I-frame with CA 65535
	Malformed   bool
	Unsupported bool
}

// IEC104Envelope reports whether ctx falls inside the IEC104 inspection
// envelope and its effective mode. Not implemented yet: it never matches.
func (e *Evaluator) IEC104Envelope(_ EvalContext, _ string) (matched bool, mode string) {
	return false, ""
}

// EvaluateIEC104 evaluates the IEC104 rules only. Not implemented yet: it
// returns DENY with no matched rule, the no-match result.
func (e *Evaluator) EvaluateIEC104(_ EvalContext) (Action, *Entry) {
	return ActionDeny, nil
}
