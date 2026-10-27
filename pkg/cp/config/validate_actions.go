// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
)

// Bounds of the RATE_LIMIT and TAG parameters.
const (
	MaxRatePacketsPerSecond = 1_000_000
	MaxRateBurst            = 1_000_000
	// MaxTagLabels is the number of distinct TAG labels a config may use.
	MaxTagLabels = 32
)

// tagLabelRE is the shape of a TAG label.
var tagLabelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)

// validateRuleAction checks a rule's action and the parameters it takes.
// labels collects the distinct TAG labels of the config so far; the call
// fails once they exceed MaxTagLabels.
//
// RESET, RATE_LIMIT and TAG act on the L3/L4 scope of a rule, so none takes
// an ICS protocol: IEC104 keeps sole ownership of session resets, and a
// semantic rate or label is not defined. A TAG label is a function of the
// snapshot and the flow tuple at open, so a TAG rule takes no schedule.
func validateRuleAction(r Rule, labels map[string]struct{}) error {
	switch r.Action {
	case ActionAllow, ActionDeny, ActionReset, ActionRateLimit, ActionTag:
	default:
		return fmt.Errorf("rule %s has invalid action %q; allowed values: %q, %q, %q, %q, %q",
			r.ID, r.Action, ActionAllow, ActionDeny, ActionReset, ActionRateLimit, ActionTag)
	}
	if r.Action != ActionRateLimit && r.RateLimit != nil {
		return fmt.Errorf("rule %s: rateLimit is only valid with action %s", r.ID, ActionRateLimit)
	}
	if r.Action != ActionTag && r.Tag != "" {
		return fmt.Errorf("rule %s: tag is only valid with action %s", r.ID, ActionTag)
	}
	if r.Action == ActionAllow || r.Action == ActionDeny {
		return nil
	}
	if r.ICS.Protocol != "" {
		return fmt.Errorf("rule %s: action %s cannot take an ics protocol; it acts on the rule's L3/L4 scope only", r.ID, r.Action)
	}
	switch r.Action {
	case ActionRateLimit:
		return validateRateLimit(r)
	case ActionTag:
		return validateTag(r, labels)
	}
	return nil
}

func validateRateLimit(r Rule) error {
	rl := r.RateLimit
	if rl == nil {
		return fmt.Errorf("rule %s: action %s needs rateLimit", r.ID, ActionRateLimit)
	}
	if rl.PacketsPerSecond < 1 || rl.PacketsPerSecond > MaxRatePacketsPerSecond {
		return fmt.Errorf("rule %s: rateLimit.packetsPerSecond %d is out of range 1-%d", r.ID, rl.PacketsPerSecond, MaxRatePacketsPerSecond)
	}
	if rl.Burst > MaxRateBurst {
		return fmt.Errorf("rule %s: rateLimit.burst %d is out of range 0-%d", r.ID, rl.Burst, MaxRateBurst)
	}
	return nil
}

func validateTag(r Rule, labels map[string]struct{}) error {
	if !tagLabelRE.MatchString(r.Tag) {
		return fmt.Errorf("rule %s: tag %q is invalid; use 1-32 characters a-z, 0-9, '_', '.' and '-', starting with a letter or digit", r.ID, r.Tag)
	}
	if r.Schedule != nil {
		return fmt.Errorf("rule %s: action %s cannot take a schedule; a tag is fixed when the flow opens", r.ID, ActionTag)
	}
	labels[r.Tag] = struct{}{}
	if len(labels) > MaxTagLabels {
		return fmt.Errorf("rule %s: tag %q exceeds the limit of %d distinct tag labels", r.ID, r.Tag, MaxTagLabels)
	}
	return nil
}
