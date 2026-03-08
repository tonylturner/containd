// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package identity

import (
	"net"
	"testing"
)

func TestResolverRegisterAndResolve(t *testing.T) {
	r := NewResolver()
	ip := net.ParseIP("192.168.1.10")

	// No mapping yet.
	if ids := r.Resolve(ip); ids != nil {
		t.Fatalf("expected nil, got %v", ids)
	}

	r.Register(ip, []string{"admin", "devops"})
	ids := r.Resolve(ip)
	if len(ids) != 2 || ids[0] != "admin" || ids[1] != "devops" {
		t.Fatalf("expected [admin devops], got %v", ids)
	}

	// Overwrite mapping.
	r.Register(ip, []string{"guest"})
	ids = r.Resolve(ip)
	if len(ids) != 1 || ids[0] != "guest" {
		t.Fatalf("expected [guest], got %v", ids)
	}
}

func TestResolverRemove(t *testing.T) {
	r := NewResolver()
	ip := net.ParseIP("10.0.0.1")

	r.Register(ip, []string{"user1"})
	r.Remove(ip)

	if ids := r.Resolve(ip); ids != nil {
		t.Fatalf("expected nil after remove, got %v", ids)
	}
}

func TestResolverAll(t *testing.T) {
	r := NewResolver()
	r.Register(net.ParseIP("10.0.0.1"), []string{"a"})
	r.Register(net.ParseIP("10.0.0.2"), []string{"b", "c"})

	all := r.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(all))
	}

	found := map[string]bool{}
	for _, m := range all {
		found[m.IP] = true
	}
	if !found["10.0.0.1"] || !found["10.0.0.2"] {
		t.Fatalf("missing expected IPs in All(): %v", all)
	}
}

func TestResolverReturnsCopy(t *testing.T) {
	r := NewResolver()
	ip := net.ParseIP("10.0.0.1")
	r.Register(ip, []string{"orig"})

	ids := r.Resolve(ip)
	ids[0] = "mutated"

	// Original should be unchanged.
	ids2 := r.Resolve(ip)
	if ids2[0] != "orig" {
		t.Fatalf("Resolve did not return a copy; mutation leaked: got %v", ids2)
	}
}
