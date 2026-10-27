// SPDX-License-Identifier: Apache-2.0

package ics

import (
	"strings"
	"testing"
)

func TestParsingContract(t *testing.T) {
	for _, name := range []string{"modbus", "dnp3", "cip", "iec104"} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"", "tolerant", "strict"} {
				modes := map[string]string{name: mode}
				if err := ValidateParsing(modes); err != nil {
					t.Fatal(err)
				}
				want := Tolerant
				if mode == "strict" {
					want = Strict
				}
				if got := EffectiveParsing(modes, name); got != want {
					t.Fatalf("mode %q: got %q want %q", mode, got, want)
				}
			}
			for _, modes := range []map[string]string{nil, {}, {"other": "strict"}} {
				if got := EffectiveParsing(modes, name); got != Tolerant {
					t.Fatalf("absent key: got %q", got)
				}
			}
			for _, mode := range []string{"STRICT", " strict", "learn", "invalid"} {
				if err := ValidateParsing(map[string]string{name: mode}); err == nil || !strings.Contains(err.Error(), "dpiIcsParsing."+name) {
					t.Fatalf("invalid mode %q: %v", mode, err)
				}
			}
		})
	}
	if err := ValidateParsing(nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"enip", "s7comm", "MODBUS", ""} {
		if err := ValidateParsing(map[string]string{name: "strict"}); err == nil || !strings.Contains(err.Error(), "dpiIcsParsing") {
			t.Fatalf("unknown protocol %q: %v", name, err)
		}
	}
}
