// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package eventfields

import (
	"encoding/json"
	"math"
	"strconv"
)

// Integer accessors accept Go integer kinds in range, and float64 or
// json.Number only when the value is exactly integral, finite and in range.
// Anything else (absent, nil, fraction, NaN/Inf, negative for unsigned, out
// of range, other kinds) is ok=false. They never truncate.

// Uint8 reads an integral attribute that fits uint8.
func Uint8(a map[string]any, k string) (uint8, bool) {
	v, ok := unsignedMax(a, k, math.MaxUint8)
	return uint8(v), ok
}

// Uint16 reads an integral attribute that fits uint16.
func Uint16(a map[string]any, k string) (uint16, bool) {
	v, ok := unsignedMax(a, k, math.MaxUint16)
	return uint16(v), ok
}

// Uint32 reads an integral attribute that fits uint32.
func Uint32(a map[string]any, k string) (uint32, bool) {
	v, ok := unsignedMax(a, k, math.MaxUint32)
	return uint32(v), ok
}

// Int64 reads an integral attribute that fits int64.
func Int64(a map[string]any, k string) (int64, bool) {
	neg, mag, ok := integral(a[k])
	switch {
	case !ok:
		return 0, false
	case !neg && mag <= math.MaxInt64:
		return int64(mag), true
	case neg && mag <= 1<<63:
		return int64(-mag), true // -(1<<63) wraps to MinInt64 exactly
	default:
		return 0, false
	}
}

// Float64 reads a finite numeric attribute: float32, float64, json.Number,
// or a Go integer that float64 represents exactly.
func Float64(a map[string]any, k string) (float64, bool) {
	var f float64
	switch v := a[k].(type) {
	case float64:
		f = v
	case float32:
		f = float64(v)
	case json.Number:
		parsed, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return 0, false
		}
		f = parsed
	default:
		neg, mag, ok := integerKind(v)
		if !ok || mag > 1<<53 {
			return 0, false
		}
		f = float64(mag)
		if neg {
			f = -f
		}
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// Bool reads a bool attribute; it accepts only bool.
func Bool(a map[string]any, k string) (bool, bool) {
	v, ok := a[k].(bool)
	return v, ok
}

// String reads a string attribute.
func String(a map[string]any, k string) (string, bool) {
	v, ok := a[k].(string)
	return v, ok
}

// Strings reads a []string or a []any whose elements are all strings and
// returns an owned copy.
func Strings(a map[string]any, k string) ([]string, bool) {
	switch v := a[k].(type) {
	case []string:
		return append(make([]string, 0, len(v)), v...), true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func unsignedMax(a map[string]any, k string, maxValue uint64) (uint64, bool) {
	neg, mag, ok := integral(a[k])
	if !ok || neg || mag > maxValue {
		return 0, false
	}
	return mag, true
}

// integral returns v as sign and magnitude when it is an exact integer.
func integral(v any) (neg bool, mag uint64, ok bool) {
	switch n := v.(type) {
	case float64:
		return integralFloat(n)
	case json.Number:
		if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
			return signed(i)
		}
		if u, err := strconv.ParseUint(string(n), 10, 64); err == nil {
			return false, u, true
		}
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return false, 0, false
		}
		return integralFloat(f)
	default:
		return integerKind(v)
	}
}

func integerKind(v any) (neg bool, mag uint64, ok bool) {
	switch n := v.(type) {
	case int:
		return signed(int64(n))
	case int8:
		return signed(int64(n))
	case int16:
		return signed(int64(n))
	case int32:
		return signed(int64(n))
	case int64:
		return signed(n)
	case uint:
		return false, uint64(n), true
	case uint8:
		return false, uint64(n), true
	case uint16:
		return false, uint64(n), true
	case uint32:
		return false, uint64(n), true
	case uint64:
		return false, n, true
	default:
		return false, 0, false
	}
}

func signed(i int64) (bool, uint64, bool) {
	if i < 0 {
		return true, uint64(-(i + 1)) + 1, true // safe for MinInt64
	}
	return false, uint64(i), true
}

func integralFloat(f float64) (bool, uint64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return false, 0, false
	}
	const two64 = 1 << 64
	switch {
	case f >= 0 && f < two64:
		return false, uint64(f), true
	case f < 0 && f >= -(1<<63):
		return true, uint64(-f), true
	default:
		return false, 0, false
	}
}
