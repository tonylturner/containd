// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Evaluator matches DPI events against snapshot IDS rules.
type Evaluator struct {
	cfg rules.IDSConfig
}

func New(cfg rules.IDSConfig) *Evaluator {
	return &Evaluator{cfg: cfg}
}

// Evaluate returns IDS alert events for a given DPI event.
func (e *Evaluator) Evaluate(ev dpi.Event) []dpi.Event {
	if e == nil || !e.cfg.Enabled || len(e.cfg.Rules) == 0 {
		return nil
	}
	var out []dpi.Event
	for _, r := range e.cfg.Rules {
		if r.ID == "" {
			continue
		}
		if r.Proto != "" && !strings.EqualFold(r.Proto, ev.Proto) {
			continue
		}
		if r.Kind != "" && !strings.EqualFold(r.Kind, ev.Kind) {
			continue
		}
		if !matchCond(r.When, ev) {
			continue
		}
		attrs := map[string]any{
			"rule_id":     r.ID,
			"severity":    r.Severity,
			"message":     firstNonEmpty(r.Message, r.Title, "IDS alert"),
			"event_proto": ev.Proto,
			"event_kind":  ev.Kind,
		}
		if len(r.Labels) > 0 {
			attrs["labels"] = r.Labels
		}
		if ev.Attributes != nil {
			attrs["event_attrs"] = ev.Attributes
		}
		out = append(out, dpi.Event{
			FlowID:     ev.FlowID,
			Proto:      "ids",
			Kind:       "alert",
			Attributes: attrs,
			Timestamp:  time.Now().UTC(),
		})
	}
	return out
}

func matchCond(c rules.IDSCondition, ev dpi.Event) bool {
	// Empty condition matches.
	if len(c.All) == 0 && len(c.Any) == 0 && c.Not == nil && c.Field == "" {
		return true
	}
	if len(c.All) > 0 {
		for _, child := range c.All {
			if !matchCond(child, ev) {
				return false
			}
		}
		return true
	}
	if len(c.Any) > 0 {
		for _, child := range c.Any {
			if matchCond(child, ev) {
				return true
			}
		}
		return false
	}
	if c.Not != nil {
		return !matchCond(*c.Not, ev)
	}
	return matchLeaf(c, ev)
}

func matchLeaf(c rules.IDSCondition, ev dpi.Event) bool {
	field := strings.ToLower(strings.TrimSpace(c.Field))
	if field == "" {
		return false
	}
	op := strings.ToLower(strings.TrimSpace(c.Op))
	if op == "" {
		op = "equals"
	}
	val := lookupField(field, ev)
	return evalOp(op, val, c.Value)
}

func lookupField(field string, ev dpi.Event) any {
	switch field {
	case "proto":
		return ev.Proto
	case "kind":
		return ev.Kind
	case "flowid":
		return ev.FlowID
	}
	if strings.HasPrefix(field, "attr.") {
		key := strings.TrimPrefix(field, "attr.")
		if ev.Attributes == nil {
			return nil
		}
		return ev.Attributes[key]
	}
	// Fallback: treat as attr.<field>.
	if ev.Attributes == nil {
		return nil
	}
	return ev.Attributes[field]
}

func evalOp(op string, actual any, expected any) bool {
	switch op {
	case "equals":
		return eq(actual, expected)
	case "contains":
		as, ok := toString(actual)
		if !ok {
			return false
		}
		es, ok := toString(expected)
		if !ok {
			return false
		}
		return strings.Contains(strings.ToLower(as), strings.ToLower(es))
	case "in":
		return inList(actual, expected)
	case "regex":
		as, ok := toString(actual)
		if !ok {
			return false
		}
		es, ok := toString(expected)
		if !ok || es == "" {
			return false
		}
		re, err := regexp.Compile(es)
		if err != nil {
			return false
		}
		return re.MatchString(as)
	case "gt":
		af, okA := toFloat(actual)
		ef, okE := toFloat(expected)
		return okA && okE && af > ef
	case "lt":
		af, okA := toFloat(actual)
		ef, okE := toFloat(expected)
		return okA && okE && af < ef
	default:
		return eq(actual, expected)
	}
}

func eq(a any, b any) bool {
	ab, okA := toBool(a)
	bb, okB := toBool(b)
	if okA && okB {
		return ab == bb
	}
	as, okA := toString(a)
	bs, okB := toString(b)
	if okA && okB {
		return strings.EqualFold(as, bs)
	}
	af, okA := toFloat(a)
	bf, okB := toFloat(b)
	if okA && okB {
		return af == bf
	}
	return false
}

func toBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "y", "on", "enabled", "enable":
			return true, true
		case "0", "false", "no", "n", "off", "disabled", "disable":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func inList(actual any, expected any) bool {
	switch e := expected.(type) {
	case []any:
		for _, item := range e {
			if eq(actual, item) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range e {
			if eq(actual, item) {
				return true
			}
		}
		return false
	default:
		return eq(actual, expected)
	}
}

func toString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case []byte:
		return string(t), true
	case fmt.Stringer:
		return t.String(), true
	default:
		return "", false
	}
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint8:
		return float64(t), true
	case uint16:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
