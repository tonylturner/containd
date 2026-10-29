// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Equality is on matching predicates, not Go storage: enabled defaults to true,
// YAML/JSON have different numeric containers, and AND/OR are commutative with
// identity singleton groups. Do not equate numeric strings with numbers: the
// evaluator treats them differently for some operations.
func rulePredicateDifference(a, b config.IDSRule) string {
	if (a.ID == "") != (b.ID == "") {
		return "id"
	}
	for _, filter := range []struct{ name, a, b string }{
		{"proto", a.Proto, b.Proto}, {"kind", a.Kind, b.Kind}, {"srcAddr", a.SrcAddr, b.SrcAddr}, {"dstAddr", a.DstAddr, b.DstAddr},
		{"srcPort", a.SrcPort, b.SrcPort}, {"dstPort", a.DstPort, b.DstPort}, {"severity", a.Severity, b.Severity},
	} {
		if filter.a != filter.b {
			return filter.name
		}
	}
	if (a.Enabled != nil && !*a.Enabled) != (b.Enabled != nil && !*b.Enabled) {
		return "enabled"
	}
	if (a.Labels["evaluable"] == "false") != (b.Labels["evaluable"] == "false") {
		return "evaluable"
	}
	if firstNonEmpty(a.Action, "alert") != firstNonEmpty(b.Action, "alert") {
		return "action"
	}
	if len(a.ContentMatches) != len(b.ContentMatches) {
		return "contentMatches"
	}
	for i := range a.ContentMatches {
		if a.ContentMatches[i] != b.ContentMatches[i] {
			return fmt.Sprintf("contentMatches[%d]", i)
		}
	}
	if len(a.YARAStrings) != len(b.YARAStrings) {
		return "yaraStrings"
	}
	for i := range a.YARAStrings {
		left, right := a.YARAStrings[i], b.YARAStrings[i]
		left.Type = firstNonEmpty(left.Type, "text")
		right.Type = firstNonEmpty(right.Type, "text")
		if left != right {
			return fmt.Sprintf("yaraStrings[%d]", i)
		}
	}
	for _, key := range []string{"yara.condition", "activated_by", "count", "tag"} {
		left, right := a.Labels[key], b.Labels[key]
		if key == "yara.condition" && (len(a.YARAStrings) > 0 || len(b.YARAStrings) > 0) {
			left = firstNonEmpty(strings.TrimSpace(left), "any of them")
			right = firstNonEmpty(strings.TrimSpace(right), "any of them")
		}
		if left != right {
			return "labels." + key
		}
	}
	if !conditionsEquivalent(a.When, b.When) {
		return "when"
	}
	return ""
}

func conditionsEquivalent(a, b config.IDSCondition) bool {
	a = unwrapSingletonCondition(a)
	b = unwrapSingletonCondition(b)
	if a.Field != b.Field || defaultConditionOp(a) != defaultConditionOp(b) || !reflect.DeepEqual(canonicalPredicateValue(a.Value), canonicalPredicateValue(b.Value)) {
		return false
	}
	if (a.Not == nil) != (b.Not == nil) {
		return false
	}
	if a.Not != nil && !conditionsEquivalent(*a.Not, *b.Not) {
		return false
	}
	return conditionGroupsEquivalent(a.All, b.All) && conditionGroupsEquivalent(a.Any, b.Any)
}

func defaultConditionOp(c config.IDSCondition) string {
	if c.Field != "" && c.Op == "" {
		return "equals"
	}
	return c.Op
}

func unwrapSingletonCondition(c config.IDSCondition) config.IDSCondition {
	for c.Field == "" && c.Op == "" && c.Value == nil && c.Not == nil {
		if len(c.All) == 1 && len(c.Any) == 0 {
			c = c.All[0]
		} else if len(c.Any) == 1 && len(c.All) == 0 {
			c = c.Any[0]
		} else {
			break
		}
	}
	return c
}

func conditionGroupsEquivalent(a, b []config.IDSCondition) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, left := range a {
		found := false
		for j, right := range b {
			if !used[j] && conditionsEquivalent(left, right) {
				used[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func canonicalPredicateValue(value any) any {
	switch v := value.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case float32:
		return float64(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = canonicalPredicateValue(item)
		}
		return out
	case []string:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = canonicalPredicateValue(s)
		}
		return out
	default:
		return value
	}
}
