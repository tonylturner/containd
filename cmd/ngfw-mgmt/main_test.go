package main

import (
	"testing"

	"github.com/containd/containd/pkg/cp/config"
)

func TestMgmtAllowedOnInterface_UsesDeviceBinding(t *testing.T) {
	f := false
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan", Device: "eth0", Access: config.InterfaceAccess{Mgmt: &f}},
		},
	}
	if mgmtAllowedOnInterface(cfg, "eth0", false) {
		t.Fatalf("expected mgmt denied on eth0 due to wan binding")
	}
}

func TestSSHAllowedOnInterface_UsesDeviceBinding(t *testing.T) {
	f := false
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "mgmt", Device: "eth1", Access: config.InterfaceAccess{SSH: &f}},
		},
	}
	if sshAllowedOnInterface(cfg, "eth1") {
		t.Fatalf("expected ssh denied on eth1 due to mgmt binding")
	}
}

func TestMgmtAllowedOnInterface_UnknownDefaultsAllow(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan", Device: "eth0"},
		},
	}
	if !mgmtAllowedOnInterface(cfg, "does-not-exist", false) {
		t.Fatalf("expected allow when interface cannot be mapped")
	}
	if !mgmtAllowedOnInterface(cfg, "", false) {
		t.Fatalf("expected allow for empty iface (localhost/unknown)")
	}
}

