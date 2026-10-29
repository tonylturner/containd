// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Each leaf gets its own selection, avoiding map iteration order and selection
// name collisions in nested Boolean trees. Parentheses preserve grouping.
func sigmaConditionExpression(rule config.IDSRule, c config.IDSCondition, path string, det map[string]any) (string, error) {
	shapes := 0
	if len(c.All) > 0 {
		shapes++
	}
	if len(c.Any) > 0 {
		shapes++
	}
	if c.Not != nil {
		shapes++
	}
	if c.Field != "" || c.Op != "" || c.Value != nil {
		shapes++
	}
	if shapes != 1 {
		return "", sigmaRefusal(rule, path+" (empty or mixed condition has no exact detection inverse)")
	}
	for _, group := range []struct {
		name, op string
		children []config.IDSCondition
	}{{"all", " and ", c.All}, {"any", " or ", c.Any}} {
		if len(group.children) == 0 {
			continue
		}
		var parts []string
		for i, child := range group.children {
			expr, err := sigmaConditionExpression(rule, child, fmt.Sprintf("%s.%s[%d]", path, group.name, i), det)
			if err != nil {
				return "", err
			}
			parts = append(parts, expr)
		}
		return "(" + strings.Join(parts, group.op) + ")", nil
	}
	if c.Not != nil {
		expr, err := sigmaConditionExpression(rule, *c.Not, path+".not", det)
		return "not (" + expr + ")", err
	}
	field := c.Field
	switch field {
	case "proto", "kind", "flowid":
	default:
		if !strings.HasPrefix(field, "attr.") || !decoderAttribute(strings.TrimPrefix(field, "attr.")) {
			return "", sigmaRefusal(rule, path+".field="+fmt.Sprintf("%q", field))
		}
		field = strings.TrimPrefix(field, "attr.")
	}
	op := c.Op
	if op == "" {
		// The native evaluator defaults an omitted operator to equality.
		op = "equals"
	}
	switch op {
	case "equals", "in", "contains", "regex", "gt", "lt":
	default:
		return "", sigmaRefusal(rule, path+".op="+fmt.Sprintf("%q", c.Op))
	}
	list := false
	switch c.Value.(type) {
	case []any, []string:
		list = true
	}
	if list && op != "in" {
		return "", sigmaRefusal(rule, path+".value (a list requires in)")
	}
	if !sigmaExportValue(c.Value) {
		return "", sigmaRefusal(rule, path+".value (unsupported scalar or list shape)")
	}
	if op != "equals" && !(op == "in" && list) {
		field += "|" + op
	}
	name := fmt.Sprintf("selection_%d", len(det))
	det[name] = map[string]any{field: sigmaOutputValue(c.Value)}
	return name, nil
}

func sigmaExportValue(v any) bool {
	switch value := v.(type) {
	case nil, string, bool, int, int64, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return !math.IsNaN(value) && !math.IsInf(value, 0)
	case float32:
		return !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
	case []string:
		return true
	case []any:
		for _, item := range value {
			if !sigmaExportValue(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, item := range value {
			if !sigmaExportValue(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Equality is on matching predicates, not Go storage: enabled defaults to true,
// YAML/JSON have different numeric containers, and AND/OR are commutative with
// identity singleton groups. Do not equate numeric strings with numbers: the
// evaluator treats them differently for some operations.
func sigmaPredicateDifference(a, b config.IDSRule) string {
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
	if !sigmaConditionsEqual(a.When, b.When) {
		return "when"
	}
	return ""
}

func sigmaConditionsEqual(a, b config.IDSCondition) bool {
	a = sigmaUnwrapSingleton(a)
	b = sigmaUnwrapSingleton(b)
	if a.Field != b.Field || sigmaDefaultOp(a) != sigmaDefaultOp(b) || !reflect.DeepEqual(sigmaCanonicalValue(a.Value), sigmaCanonicalValue(b.Value)) {
		return false
	}
	if (a.Not == nil) != (b.Not == nil) {
		return false
	}
	if a.Not != nil && !sigmaConditionsEqual(*a.Not, *b.Not) {
		return false
	}
	return sigmaConditionGroupEqual(a.All, b.All) && sigmaConditionGroupEqual(a.Any, b.Any)
}

func sigmaDefaultOp(c config.IDSCondition) string {
	if c.Field != "" && c.Op == "" {
		return "equals"
	}
	return c.Op
}

func sigmaUnwrapSingleton(c config.IDSCondition) config.IDSCondition {
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

func sigmaConditionGroupEqual(a, b []config.IDSCondition) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, left := range a {
		found := false
		for j, right := range b {
			if !used[j] && sigmaConditionsEqual(left, right) {
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

func sigmaCanonicalValue(value any) any {
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
			out[key] = sigmaCanonicalValue(item)
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
			out[i] = sigmaCanonicalValue(s)
		}
		return out
	default:
		return value
	}
}

func sigmaOutputValue(value any) any {
	switch v := value.(type) {
	case float32:
		return float64(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = sigmaOutputValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sigmaOutputValue(item)
		}
		return out
	default:
		return value
	}
}
