// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package eventfields

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

// forms returns the attribute map in memory, after a JSON round trip into
// map[string]any (float64 numbers), and after one with UseNumber.
func forms(t *testing.T, attrs map[string]any) map[string]map[string]any {
	t.Helper()
	body, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var plain map[string]any
	if err := json.Unmarshal(body, &plain); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var numbers map[string]any
	if err := dec.Decode(&numbers); err != nil {
		t.Fatalf("decode UseNumber: %v", err)
	}
	return map[string]map[string]any{"memory": attrs, "json": plain, "json.Number": numbers}
}

// A decoded IEC104 event as a parser emits it.
func iecEvent() map[string]any {
	return map[string]any{
		KeyAPCIType:        "I",
		KeyDirection:       "request",
		KeyClass:           "control",
		KeySendSequence:    uint16(65535),
		KeyReceiveSequence: uint16(0),
		KeyTypeID:          uint8(46),
		KeyVSQ:             uint8(1),
		KeyObjectCount:     uint8(1),
		KeyCause:           uint8(6),
		KeyOriginator:      uint8(0),
		KeySQ:              false,
		KeyCOTTest:         false,
		KeyCOTNegative:     false,
		KeyIsWrite:         true,
		KeyCA:              uint16(65534),
		KeyIOA:             uint32(16777215),
		KeyObjectIndex:     uint8(0),
		KeySelect:          true,
		KeyQualifier:       uint8(2),
		KeyValue:           float32(1.5),
		KeySourceTime:      "2026-11-07T09:15:02.345",
		KeyAPDUID:          APDUID(SessionID("ab12", 26), DirClient, 4096),
		KeySessionID:       SessionID("ab12", 26),
		KeyAPDUIDs:         []string{"s/c/0", "s/c/14"},
	}
}

func TestAccessorsAgreeAcrossForms(t *testing.T) {
	for name, a := range forms(t, iecEvent()) {
		t.Run(name, func(t *testing.T) {
			if v, ok := String(a, KeyAPCIType); !ok || v != "I" {
				t.Fatalf("apci_type = %q/%v", v, ok)
			}
			if v, ok := Uint16(a, KeySendSequence); !ok || v != 65535 {
				t.Fatalf("send_sequence = %d/%v", v, ok)
			}
			if v, ok := Uint16(a, KeyReceiveSequence); !ok || v != 0 {
				t.Fatalf("receive_sequence = %d/%v (zero is a value, not absent)", v, ok)
			}
			if v, ok := Uint8(a, KeyTypeID); !ok || v != 46 {
				t.Fatalf("type_id = %d/%v", v, ok)
			}
			if v, ok := Uint16(a, KeyCA); !ok || v != 65534 {
				t.Fatalf("ca = %d/%v", v, ok)
			}
			if v, ok := Uint32(a, KeyIOA); !ok || v != 16777215 {
				t.Fatalf("ioa = %d/%v", v, ok)
			}
			if v, ok := Bool(a, KeySelect); !ok || !v {
				t.Fatalf("select = %v/%v", v, ok)
			}
			if v, ok := Bool(a, KeySQ); !ok || v {
				t.Fatalf("sq = %v/%v (false is a value, not absent)", v, ok)
			}
			if v, ok := Float64(a, KeyValue); !ok || v != 1.5 {
				t.Fatalf("value = %v/%v", v, ok)
			}
			if v, ok := Strings(a, KeyAPDUIDs); !ok || !reflect.DeepEqual(v, []string{"s/c/0", "s/c/14"}) {
				t.Fatalf("apdu_ids = %v/%v", v, ok)
			}
			if v, ok := String(a, KeyAPDUID); !ok || v != "ab12-1a/c/4096" {
				t.Fatalf("apdu_id = %q/%v", v, ok)
			}
			if _, ok := Uint8(a, KeyCA); ok {
				t.Fatal("ca 65534 must not fit uint8")
			}
			if _, ok := Uint8(a, "missing"); ok {
				t.Fatal("absent key must be ok=false")
			}
			if _, ok := Uint8(a, KeyAPCIType); ok {
				t.Fatal("string must not read as an integer")
			}
			if _, ok := Bool(a, KeyTypeID); ok {
				t.Fatal("number must not read as bool")
			}
		})
	}
}

func TestIntegerAccessorsAreStrict(t *testing.T) {
	cases := []struct {
		name string
		v    any
		u8   bool
		i64  int64
		iok  bool
	}{
		{"nil", nil, false, 0, false},
		{"int", 7, true, 7, true},
		{"int8 negative", int8(-1), false, -1, true},
		{"uint64 max", uint64(math.MaxUint64), false, 0, false},
		{"int64 min", int64(math.MinInt64), false, math.MinInt64, true},
		{"float integral", float64(255), true, 255, true},
		{"float 256", float64(256), false, 256, true},
		{"float fraction", 2.5, false, 0, false},
		{"float negative", -3.0, false, -3, true},
		{"float NaN", math.NaN(), false, 0, false},
		{"float Inf", math.Inf(1), false, 0, false},
		{"float 2^63", math.Ldexp(1, 63), false, 0, false},
		{"float -2^63", -math.Ldexp(1, 63), false, math.MinInt64, true},
		{"float32", float32(3), false, 0, false},
		{"number", json.Number("200"), true, 200, true},
		{"number exponent", json.Number("1e2"), true, 100, true},
		{"number fraction", json.Number("1.5"), false, 0, false},
		{"number big", json.Number("18446744073709551615"), false, 0, false},
		{"number garbage", json.Number("x"), false, 0, false},
		{"string", "7", false, 0, false},
		{"bool", true, false, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := map[string]any{"k": tc.v}
			if _, ok := Uint8(a, "k"); ok != tc.u8 {
				t.Fatalf("Uint8 ok = %v, want %v", ok, tc.u8)
			}
			got, ok := Int64(a, "k")
			if ok != tc.iok || (ok && got != tc.i64) {
				t.Fatalf("Int64 = %d/%v, want %d/%v", got, ok, tc.i64, tc.iok)
			}
		})
	}
	if v, ok := Uint32(map[string]any{"k": uint64(math.MaxUint32)}, "k"); !ok || v != math.MaxUint32 {
		t.Fatalf("Uint32 max = %d/%v", v, ok)
	}
	if _, ok := Uint32(map[string]any{"k": uint64(math.MaxUint32) + 1}, "k"); ok {
		t.Fatal("Uint32 must reject 2^32")
	}
	if _, ok := Uint16(map[string]any{"k": -1}, "k"); ok {
		t.Fatal("Uint16 must reject negatives")
	}
}

func TestFloatBoolStringAccessors(t *testing.T) {
	a := map[string]any{
		"i16":   int16(-300),
		"big":   uint64(1<<53 + 1),
		"nan":   math.NaN(),
		"num":   json.Number("2.25"),
		"t":     true,
		"one":   1,
		"s":     "x",
		"mixed": []any{"a", 1},
		"list":  []any{"a", "b"},
	}
	if v, ok := Float64(a, "i16"); !ok || v != -300 {
		t.Fatalf("Float64 int16 = %v/%v", v, ok)
	}
	if _, ok := Float64(a, "big"); ok {
		t.Fatal("Float64 must reject integers float64 cannot represent exactly")
	}
	if _, ok := Float64(a, "nan"); ok {
		t.Fatal("Float64 must reject NaN")
	}
	if v, ok := Float64(a, "num"); !ok || v != 2.25 {
		t.Fatalf("Float64 json.Number = %v/%v", v, ok)
	}
	if _, ok := Bool(a, "one"); ok {
		t.Fatal("Bool accepts only bool")
	}
	if _, ok := String(a, "one"); ok {
		t.Fatal("String accepts only string")
	}
	if _, ok := Strings(a, "mixed"); ok {
		t.Fatal("Strings must reject non-string elements")
	}
	src := []string{"a"}
	got, ok := Strings(map[string]any{"k": src}, "k")
	if !ok {
		t.Fatal("Strings []string")
	}
	got[0] = "z"
	if src[0] != "a" {
		t.Fatal("Strings must return an owned copy")
	}
	if v, ok := Strings(a, "list"); !ok || !reflect.DeepEqual(v, []string{"a", "b"}) {
		t.Fatalf("Strings []any = %v/%v", v, ok)
	}
}

func TestIDs(t *testing.T) {
	if got := SessionID("0123456789abcdef0123456789abcdef", 255); got != "0123456789abcdef0123456789abcdef-ff" {
		t.Fatalf("SessionID = %q", got)
	}
	if got := APDUID("run-1", DirServer, 0); got != "run-1/s/0" {
		t.Fatalf("APDUID = %q", got)
	}
}
