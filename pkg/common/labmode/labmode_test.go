// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package labmode

import "testing"

func TestEnabled(t *testing.T) {
	for value, want := range map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"yes":   false,
		"on":    false,
		" 1":    false,
		"true ": false,
		"1":     true,
		"true":  true,
		"TRUE":  true,
		"True":  true,
	} {
		t.Setenv(envVar, value)
		if got := Enabled(); got != want {
			t.Errorf("Enabled() with %s=%q = %v, want %v", envVar, value, got, want)
		}
	}
}
