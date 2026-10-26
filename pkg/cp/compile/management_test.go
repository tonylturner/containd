// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"encoding/json"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestManagementUnboundInvariant(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces[0].Device = "disabled-device"
	off := false
	cfg.Interfaces[0].Access = config.InterfaceAccess{Mgmt: &off, HTTP: &off, HTTPS: &off, SSH: &off}
	locals := ManagementLocalInput(cfg)
	if len(locals) == 0 {
		t.Fatal("no recovery listeners")
	}
	for _, rule := range locals {
		if !rule.RecoverUnbound || len(rule.Ifaces) != 0 || len(rule.DeniedIfaces) != 1 || rule.DeniedIfaces[0] != "disabled-device" {
			t.Fatalf("logical names or disabled device leaked: %+v", rule)
		}
	}
	if len(UnboundManagementPorts(cfg, []string{"eth0", "disabled-device"})) == 0 {
		t.Fatal("unbound appliance not reported")
	}
	// Exercise the snapshot wire boundary and actual enforcement compiler.
	wire, err := json.Marshal(rules.Snapshot{LocalInput: locals})
	if err != nil {
		t.Fatal(err)
	}
	var snap rules.Snapshot
	if err := json.Unmarshal(wire, &snap); err != nil {
		t.Fatal(err)
	}
	if _, err := enforce.NewCompiler().CompileFirewall(&snap); err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Interfaces {
		cfg.Interfaces[i].Access = cfg.Interfaces[0].Access
	}
	if got := ManagementLocalInput(cfg); len(got) != 0 {
		t.Fatalf("disabled access became recovery: %+v", got)
	}
	if len(UnboundManagementPorts(cfg, []string{"eth0"})) != 0 {
		t.Fatal("disabled policy reported as unbound")
	}
}

func TestManagementCompilesOnlyBoundDevices(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces[4].Device = "eth4"
	for _, rule := range ManagementLocalInput(cfg) {
		if len(rule.Ifaces) != 1 || rule.Ifaces[0] != "eth4" {
			t.Fatalf("not bound-only: %+v", rule)
		}
	}
	if len(UnboundManagementPorts(cfg, []string{"eth4"})) != 0 {
		t.Fatal("bound appliance reported as unbound")
	}
}

func TestManagementRecoveryExcludesDisabledKernelName(t *testing.T) {
	cfg := config.DefaultConfig()
	off := false
	cfg.Interfaces[0].Name = "eth0"
	cfg.Interfaces[0].Access = config.InterfaceAccess{Mgmt: &off, HTTP: &off, HTTPS: &off, SSH: &off}
	for _, rule := range ManagementLocalInput(cfg) {
		if len(rule.DeniedIfaces) != 1 || rule.DeniedIfaces[0] != "eth0" {
			t.Fatalf("disabled legacy kernel binding not excluded: %+v", rule)
		}
	}
}
