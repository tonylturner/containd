// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package common

import "testing"

func TestEnvBool(t *testing.T) {
	t.Setenv("CONTAIND_TEST_BOOL", "true")
	if !EnvBool("CONTAIND_TEST_BOOL", false) {
		t.Fatal("expected true from truthy env value")
	}

	t.Setenv("CONTAIND_TEST_BOOL", "off")
	if EnvBool("CONTAIND_TEST_BOOL", true) {
		t.Fatal("expected false from falsy env value")
	}

	t.Setenv("CONTAIND_TEST_BOOL", "bogus")
	if !EnvBool("CONTAIND_TEST_BOOL", true) {
		t.Fatal("expected fallback for invalid env bool")
	}
}

func TestEnvCSV(t *testing.T) {
	t.Setenv("CONTAIND_TEST_CSV", "eth0, eth1 ,, lan1")
	got := EnvCSV("CONTAIND_TEST_CSV")
	want := []string{"eth0", "eth1", "lan1"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d=%q want %q", i, got[i], want[i])
		}
	}
}
