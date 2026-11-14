// SPDX-License-Identifier: Apache-2.0

package rules

// MessageClass describes a protocol unit, independently of its authorization.
type MessageClass string

const (
	ClassUnknown    MessageClass = "unknown"
	ClassRequest    MessageClass = "request"
	ClassSolicited  MessageClass = "solicited"
	ClassAutonomous MessageClass = "autonomous"
	ClassSession    MessageClass = "session"
)

// MatchMessageClass tests only the class constraint, not the other predicates
// or request pairing. monitor is the effective mode, including inheritance.
// Transport-only rules and CIP retain their ordinary matching semantics.
func MatchMessageClass(p ICSPredicate, c *ICSContext, action Action, monitor bool) bool {
	if p.MessageClass != "" {
		if p.MessageClass != string(ClassAutonomous) && p.MessageClass != string(ClassSession) {
			return false
		}
		return c != nil && string(c.MessageClass) == p.MessageClass
	}
	if monitor || action != ActionAllow || p.Protocol == "" || p.Protocol == "cip" {
		return true
	}
	return c != nil && (c.MessageClass == ClassRequest || c.MessageClass == ClassSolicited)
}
