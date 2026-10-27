// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func iecMatches(t *testing.T, kind string, attrs map[string]any) []string {
	t.Helper()
	e := New()
	e.LoadBuiltins()
	// The JSON form must match like the in-memory form.
	raw, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	var rt map[string]any
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatal(err)
	}
	var ids [2][]string
	for i, a := range []map[string]any{attrs, rt} {
		for _, m := range e.Match(dpi.Event{Proto: "iec104", Kind: kind, Attributes: a}) {
			ids[i] = append(ids[i], m.Signature.ID)
		}
		sort.Strings(ids[i])
	}
	if len(ids[0]) != len(ids[1]) {
		t.Fatalf("in-memory %v vs JSON %v", ids[0], ids[1])
	}
	return ids[0]
}

func TestIEC104Signatures(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		attrs map[string]any
		want  []string
	}{
		{"execute", "request", map[string]any{"class": "control", "type_id": uint8(46), "select": false, "ca": uint16(1), "is_write": true},
			[]string{"IEC104-CONTROL-CMD"}},
		{"select", "request", map[string]any{"class": "control", "type_id": uint8(46), "select": true, "ca": uint16(1), "is_write": true},
			[]string{"IEC104-CONTROL-CMD", "IEC104-SELECT"}},
		{"confirmation", "response", map[string]any{"class": "control", "type_id": uint8(46), "select": false, "ca": uint16(1), "is_write": false}, nil},
		{"telemetry", "response", map[string]any{"class": "monitor", "type_id": uint8(13), "ca": uint16(1), "is_write": false}, nil},
		{"reset process", "request", map[string]any{"class": "system", "type_id": uint8(105), "ca": uint16(1), "is_write": true},
			[]string{"IEC104-SYSTEM-CMD"}},
		{"broadcast GI", "request", map[string]any{"class": "system", "type_id": uint8(100), "ca": uint16(65535), "is_write": false}, []string{"IEC104-BROADCAST"}},
		{"stopdt", "apci", map[string]any{"apci_type": "U", "u_function": "stopdt_act"}, []string{"IEC104-STOPDT"}},
		{"startdt", "apci", map[string]any{"apci_type": "U", "u_function": "startdt_act"}, nil},
		{"malformed", "malformed", map[string]any{"error": "profile: client sent monitor-direction type 3"}, []string{"IEC104-MALFORMED"}},
		{"unsupported", "unsupported", map[string]any{"type_id": uint8(104), "error": "unsupported type 104"}, []string{"IEC104-UNSUPPORTED"}},
	}
	for _, c := range cases {
		got := iecMatches(t, c.kind, c.attrs)
		if len(got) != len(c.want) {
			t.Fatalf("%s: matches = %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: matches = %v, want %v", c.name, got, c.want)
			}
		}
	}
}
