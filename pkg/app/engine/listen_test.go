// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func TestListenAddr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		combined bool
		env      string
		want     string
	}{
		{"combined default", true, "", "127.0.0.1:8081"},
		{"split default", false, "", ":8081"},
		{"combined override", true, ":9091", ":9091"},
		{"split override", false, "127.0.0.1:9091", "127.0.0.1:9091"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_ENGINE_ADDR", tc.env)
			t.Setenv("NGFW_ENGINE_ADDR", "")
			if got := ListenAddr(tc.combined); got != tc.want {
				t.Fatalf("ListenAddr(%v) = %q, want %q", tc.combined, got, tc.want)
			}
		})
	}
}

func TestCombinedDefaultAcceptsReservation(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_ADDR", "")
	t.Setenv("NGFW_ENGINE_ADDR", "")
	r := &mgmtpath.Reservation{}
	if err := r.ValidateEngineBind(ListenAddr(true)); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateEngineBind(ListenAddr(false)); err == nil {
		t.Fatal("split wildcard bind accepted for reservation")
	}
}
