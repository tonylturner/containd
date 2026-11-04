// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestMgmtAllowedOnInterface_UsesRowName(t *testing.T) {
	f := false
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan", Access: config.InterfaceAccess{Mgmt: &f}},
		},
	}
	if mgmtAllowedOnInterface(cfg, "wan", false) {
		t.Fatalf("expected mgmt denied on the wan row")
	}
}

func TestSSHAllowedOnInterface_UsesRowName(t *testing.T) {
	f := false
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "mgmt", Access: config.InterfaceAccess{SSH: &f}},
		},
	}
	if sshAllowedOnInterface(cfg, "mgmt") {
		t.Fatalf("expected ssh denied on the mgmt row")
	}
}

func TestMgmtAllowedOnInterface_UnknownDefaultsAllow(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan"},
		},
	}
	if !mgmtAllowedOnInterface(cfg, "does-not-exist", false) {
		t.Fatalf("expected allow when interface cannot be mapped")
	}
	if !mgmtAllowedOnInterface(cfg, "", false) {
		t.Fatalf("expected allow for empty iface (localhost/unknown)")
	}
}
