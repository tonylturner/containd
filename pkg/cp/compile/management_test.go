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

// managementPorts maps each management INPUT rule ID to its port.
func managementPorts(cfg *config.Config) map[string]int {
	out := map[string]int{}
	for _, rule := range ManagementLocalInput(cfg) {
		out[rule.ID] = rule.Port
	}
	return out
}

func samePorts(got, want map[string]int) bool {
	if len(got) != len(want) {
		return false
	}
	for id, port := range want {
		if got[id] != port {
			return false
		}
	}
	return true
}

// A configuration that leaves listener settings to their defaults is
// admitted on the listeners management serves for it, HTTPS included.
func TestManagementInputAdmitsDefaultListeners(t *testing.T) {
	cfg := config.DefaultConfig()
	want := map[string]int{"auto-allow-mgmt-http": 8080, "auto-allow-mgmt-https": 8443, "auto-allow-ssh": 2222}
	if got := managementPorts(cfg); !samePorts(got, want) {
		t.Fatalf("management input = %v, want %v", got, want)
	}
	off := false
	cfg.System.Mgmt.EnableHTTPS = &off
	delete(want, "auto-allow-mgmt-https")
	if got := managementPorts(cfg); !samePorts(got, want) {
		t.Fatalf("management input with HTTPS disabled = %v, want %v", got, want)
	}
}

// Environment-chosen listener addresses win over stored ones, in INPUT as
// in the listeners management binds.
func TestManagementInputAdmitsEnvironmentListeners(t *testing.T) {
	t.Setenv(config.EnvManagementHTTPAddr, ":18080")
	t.Setenv(config.EnvManagementHTTPSAddr, ":18443")
	t.Setenv(config.EnvSSHAddr, ":12222")
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPListenAddr = ":9090"
	want := map[string]int{"auto-allow-mgmt-http": 18080, "auto-allow-mgmt-https": 18443, "auto-allow-ssh": 12222}
	if got := managementPorts(cfg); !samePorts(got, want) {
		t.Fatalf("management input = %v, want %v", got, want)
	}
}

// A committed listener change binds at the next start; until then INPUT
// keeps admitting the listeners management has bound as well.
func TestManagementInputKeepsBoundListenersUntilRestart(t *testing.T) {
	config.SetBoundManagementListeners(config.EffectiveManagementListeners(config.DefaultConfig()))
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
	cfg := config.DefaultConfig()
	if got, want := managementPorts(cfg), map[string]int{"auto-allow-mgmt-http": 8080, "auto-allow-mgmt-https": 8443, "auto-allow-ssh": 2222}; !samePorts(got, want) {
		t.Fatalf("management input without a pending change = %v, want %v", got, want)
	}
	off := false
	cfg.System.Mgmt.HTTPListenAddr = ":9090"
	cfg.System.Mgmt.EnableHTTPS = &off
	cfg.System.SSH.ListenAddr = ":2200"
	want := map[string]int{
		"auto-allow-mgmt-http": 9090, "auto-allow-mgmt-http-bound": 8080,
		"auto-allow-mgmt-https-bound": 8443,
		"auto-allow-ssh":              2200, "auto-allow-ssh-bound": 2222,
	}
	if got := managementPorts(cfg); !samePorts(got, want) {
		t.Fatalf("management input with a pending listener change = %v, want %v", got, want)
	}
	// Access grants apply to bound listeners as to the configured ones.
	for i := range cfg.Interfaces {
		cfg.Interfaces[i].Access = config.InterfaceAccess{Mgmt: &off, SSH: &off}
	}
	if got := ManagementLocalInput(cfg); len(got) != 0 {
		t.Fatalf("revoked access still admits management: %+v", got)
	}
}
