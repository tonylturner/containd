// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package eventfields

import (
	"reflect"
	"testing"
)

func TestConformanceStringsRoundTrip(t *testing.T) {
	want := []string{"cip.reserved_bits", "cip.truncated_pdu"}
	for name, attrs := range forms(t, map[string]any{KeyConformance: want}) {
		t.Run(name, func(t *testing.T) {
			got, ok := Strings(attrs, KeyConformance)
			if !ok || !reflect.DeepEqual(got, want) {
				t.Fatalf("conformance = %v/%v", got, ok)
			}
			got[0] = "changed"
			again, _ := Strings(attrs, KeyConformance)
			if !reflect.DeepEqual(again, want) {
				t.Fatal("reader exposed the original codes")
			}
		})
	}
}
