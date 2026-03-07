// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Signature defines a pattern for detecting known ICS attack activity.
type Signature struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"` // low, medium, high, critical
	Protocol    string      `json:"protocol"` // modbus, dnp3, cip, s7comm, or "" for any
	Conditions  []Condition `json:"conditions"`
	References  []string    `json:"references,omitempty"`
}

// Condition is a single matching predicate within a signature.
// All conditions in a signature must match (AND logic).
type Condition struct {
	Field string `json:"field"` // event attribute path: "function_code", "is_write", etc.
	Op    string `json:"op"`    // equals, in, gt, lt, contains, regex
	Value any    `json:"value"`
}

// Match represents a signature that matched an event.
type Match struct {
	Signature Signature `json:"signature"`
	Event     dpi.Event `json:"event"`
	Timestamp time.Time `json:"timestamp"`
}

// Engine evaluates DPI events against a set of loaded signatures.
type Engine struct {
	signatures []Signature
	mu         sync.RWMutex

	matchesMu sync.Mutex
	matches   []Match
	matchCap  int
}

// New creates a new signature engine with default capacity for match history.
func New() *Engine {
	return &Engine{
		matchCap: 4096,
		matches:  make([]Match, 0, 256),
	}
}

// LoadBuiltins loads the built-in ICS threat signatures.
func (e *Engine) LoadBuiltins() {
	for _, sig := range builtinSignatures() {
		e.Add(sig)
	}
}

// Add registers a signature with the engine.
func (e *Engine) Add(sig Signature) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.signatures = append(e.signatures, sig)
}

// Remove removes a signature by ID. Returns true if found and removed.
func (e *Engine) Remove(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, sig := range e.signatures {
		if sig.ID == id {
			e.signatures = append(e.signatures[:i], e.signatures[i+1:]...)
			return true
		}
	}
	return false
}

// List returns all loaded signatures.
func (e *Engine) List() []Signature {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Signature, len(e.signatures))
	copy(out, e.signatures)
	return out
}

// Matches returns recent signature matches, newest first, up to limit.
func (e *Engine) Matches(limit int) []Match {
	e.matchesMu.Lock()
	defer e.matchesMu.Unlock()
	n := len(e.matches)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Match, 0, limit)
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.matches[i])
	}
	return out
}

func (e *Engine) recordMatch(m Match) {
	e.matchesMu.Lock()
	defer e.matchesMu.Unlock()
	e.matches = append(e.matches, m)
	if len(e.matches) > e.matchCap {
		shift := len(e.matches) - e.matchCap
		e.matches = append([]Match{}, e.matches[shift:]...)
	}
}

// Match checks an event against all signatures and returns any matches.
func (e *Engine) Match(ev dpi.Event) []Match {
	e.mu.RLock()
	sigs := e.signatures
	e.mu.RUnlock()

	var out []Match
	for _, sig := range sigs {
		if !sigMatchesEvent(sig, ev) {
			continue
		}
		m := Match{
			Signature: sig,
			Event:     ev,
			Timestamp: time.Now().UTC(),
		}
		out = append(out, m)
		e.recordMatch(m)
	}
	return out
}

// sigMatchesEvent evaluates whether all conditions in a signature match the event.
func sigMatchesEvent(sig Signature, ev dpi.Event) bool {
	// Protocol filter: if the signature targets a specific protocol, the event must match.
	if sig.Protocol != "" && !strings.EqualFold(sig.Protocol, ev.Proto) {
		return false
	}
	for _, cond := range sig.Conditions {
		val := resolveField(cond.Field, ev)
		if !evalCondition(cond, val) {
			return false
		}
	}
	return true
}

// resolveField extracts the value for a given field name from the event.
func resolveField(field string, ev dpi.Event) any {
	switch field {
	case "proto":
		return ev.Proto
	case "kind":
		return ev.Kind
	case "flow_id":
		return ev.FlowID
	default:
		if ev.Attributes == nil {
			return nil
		}
		return ev.Attributes[field]
	}
}

// evalCondition evaluates a single condition against a resolved field value.
func evalCondition(cond Condition, fieldVal any) bool {
	switch cond.Op {
	case "equals", "eq":
		return equalsAny(fieldVal, cond.Value)
	case "in":
		return inAny(fieldVal, cond.Value)
	case "gt":
		return compareNumeric(fieldVal, cond.Value) > 0
	case "lt":
		return compareNumeric(fieldVal, cond.Value) < 0
	case "gte":
		return compareNumeric(fieldVal, cond.Value) >= 0
	case "lte":
		return compareNumeric(fieldVal, cond.Value) <= 0
	case "contains":
		return containsStr(fieldVal, cond.Value)
	case "regex":
		return matchesRegex(fieldVal, cond.Value)
	default:
		return false
	}
}

// equalsAny compares two values for equality, handling numeric type coercion.
func equalsAny(a, b any) bool {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if aOk && bOk {
		return af == bf
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// inAny checks if fieldVal is in the set represented by condVal (a slice).
func inAny(fieldVal, condVal any) bool {
	switch cv := condVal.(type) {
	case []any:
		for _, item := range cv {
			if equalsAny(fieldVal, item) {
				return true
			}
		}
	case []float64:
		fv, ok := toFloat64(fieldVal)
		if !ok {
			return false
		}
		for _, item := range cv {
			if fv == item {
				return true
			}
		}
	case []int:
		fv, ok := toFloat64(fieldVal)
		if !ok {
			return false
		}
		for _, item := range cv {
			if fv == float64(item) {
				return true
			}
		}
	}
	return false
}

// compareNumeric returns -1, 0, or 1 for a < b, a == b, a > b.
// Returns 0 if either is not numeric (treated as no match by callers via > 0 / < 0 checks).
func compareNumeric(a, b any) int {
	af, aOk := toFloat64(a)
	bf, bOk := toFloat64(b)
	if !aOk || !bOk {
		return 0
	}
	if af < bf {
		return -1
	}
	if af > bf {
		return 1
	}
	return 0
}

func containsStr(fieldVal, condVal any) bool {
	fs := fmt.Sprintf("%v", fieldVal)
	cs := fmt.Sprintf("%v", condVal)
	return strings.Contains(fs, cs)
}

func matchesRegex(fieldVal, condVal any) bool {
	pattern := fmt.Sprintf("%v", condVal)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(fmt.Sprintf("%v", fieldVal))
}

// toFloat64 attempts to convert an arbitrary value to float64.
func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int8:
		return float64(val), true
	case int16:
		return float64(val), true
	case int32:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint:
		return float64(val), true
	case uint8:
		return float64(val), true
	case uint16:
		return float64(val), true
	case uint32:
		return float64(val), true
	case uint64:
		return float64(val), true
	default:
		return 0, false
	}
}
