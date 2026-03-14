// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"reflect"
	"testing"
)

func configCredential(label string) string {
	return label + "-Aa1!"
}

func TestRedactedCopyAndRestoreSecrets(t *testing.T) {
	wireGuardKey := configCredential("wireguard-private")
	managedPassword := configCredential("managed-openvpn")
	orig := DefaultConfig()
	orig.Services.VPN = VPNConfig{
		WireGuard: WireGuardConfig{
			PrivateKey: wireGuardKey,
		},
		OpenVPN: OpenVPNConfig{
			Managed: &OpenVPNManagedClientConfig{
				Remote:   "vpn.example.com",
				CA:       "ca-pem",
				Cert:     "cert-pem",
				Key:      "key-pem",
				Password: managedPassword,
			},
		},
	}

	redacted := orig.RedactedCopy()
	if redacted.Services.VPN.WireGuard.PrivateKey != "" {
		t.Fatal("expected wireguard private key to be redacted")
	}
	if redacted.Services.VPN.OpenVPN.Managed == nil || redacted.Services.VPN.OpenVPN.Managed.CA != "" || redacted.Services.VPN.OpenVPN.Managed.Cert != "" || redacted.Services.VPN.OpenVPN.Managed.Key != "" || redacted.Services.VPN.OpenVPN.Managed.Password != "" {
		t.Fatalf("expected openvpn managed secrets to be redacted, got %+v", redacted.Services.VPN.OpenVPN.Managed)
	}
	if orig.Services.VPN.WireGuard.PrivateKey != wireGuardKey {
		t.Fatal("expected original config to remain unchanged")
	}

	cfgRoundTrip := redacted.RedactedCopy()
	cfgRoundTrip.RestoreRedactedSecrets(orig)
	if cfgRoundTrip.Services.VPN.WireGuard.PrivateKey != wireGuardKey {
		t.Fatal("expected config secret restore to repopulate wireguard key")
	}
	if cfgRoundTrip.Services.VPN.OpenVPN.Managed == nil || cfgRoundTrip.Services.VPN.OpenVPN.Managed.Password != managedPassword {
		t.Fatalf("expected config secret restore to repopulate openvpn secrets, got %+v", cfgRoundTrip.Services.VPN.OpenVPN.Managed)
	}

	vpnRoundTrip := redacted.Services.VPN.RedactedVPNCopy()
	vpnRoundTrip.RestoreRedactedSecrets(orig.Services.VPN)
	if vpnRoundTrip.WireGuard.PrivateKey != wireGuardKey {
		t.Fatal("expected vpn secret restore to repopulate wireguard key")
	}
	if vpnRoundTrip.OpenVPN.Managed == nil || vpnRoundTrip.OpenVPN.Managed.CA != "ca-pem" || vpnRoundTrip.OpenVPN.Managed.Key != "key-pem" {
		t.Fatalf("expected vpn secret restore to repopulate managed secrets, got %+v", vpnRoundTrip.OpenVPN.Managed)
	}
}

func TestValidateInterfaceTypeHelpers(t *testing.T) {
	byName := map[string]Interface{
		"lan0": {Name: "lan0", Type: "physical"},
		"br0":  {Name: "br0", Type: "bridge", Members: []string{"lan0"}},
	}

	if err := validateBridgeInterface(Interface{Name: "br1", Type: "bridge", Members: []string{"lan0"}}, byName); err != nil {
		t.Fatalf("validateBridgeInterface(valid): %v", err)
	}
	if err := validateBridgeInterface(Interface{Name: "br1", Type: "bridge", Members: []string{"br0"}}, byName); err == nil {
		t.Fatal("expected nested bridge validation error")
	}
	if err := validateVLANInterface(Interface{Name: "vlan10", Type: "vlan", Parent: "lan0", VLANID: 10}); err != nil {
		t.Fatalf("validateVLANInterface(valid): %v", err)
	}
	if err := validateVLANInterface(Interface{Name: "vlan0", Type: "vlan", VLANID: 0}); err == nil {
		t.Fatal("expected invalid vlan validation error")
	}
}

func TestValidateRoutingHelpers(t *testing.T) {
	ifaces := []Interface{
		{Name: "wan", Device: "eth0", Zone: "wan"},
		{Name: "lan1", Device: "eth1", Zone: "lan"},
	}
	ifaceSet := routingIfaceSet(ifaces)
	if _, ok := ifaceSet["eth0"]; !ok {
		t.Fatal("expected routingIfaceSet to include device bindings")
	}

	gwByName, err := validateGateways([]Gateway{{
		Name:    "wan-gw",
		Alias:   "upstream",
		Address: "203.0.113.1",
		Iface:   "eth0",
	}}, ifaceSet)
	if err != nil {
		t.Fatalf("validateGateways(valid): %v", err)
	}
	if _, err := validateGateways([]Gateway{{Name: "wan-gw", Alias: "wan-gw", Address: "203.0.113.1"}}, ifaceSet); err == nil {
		t.Fatal("expected gateway alias conflict error")
	}

	if err := validateRoutes([]StaticRoute{{
		Dst:     "default",
		Gateway: "wan-gw",
		Iface:   "eth0",
		Table:   100,
		Metric:  10,
	}}, gwByName, ifaceSet); err != nil {
		t.Fatalf("validateRoutes(valid): %v", err)
	}
	if err := validateRoutes([]StaticRoute{{Dst: "10.0.0.0/24", Gateway: "missing"}}, gwByName, ifaceSet); err == nil {
		t.Fatal("expected invalid route gateway error")
	}

	if err := validateRoutingRules([]PolicyRule{{Table: 100, Priority: 1000, Src: "10.0.0.0/24"}}); err != nil {
		t.Fatalf("validateRoutingRules(valid): %v", err)
	}
	if err := validateRoutingRules([]PolicyRule{{Table: 100, Priority: 1000}, {Table: 101, Priority: 1000}}); err == nil {
		t.Fatal("expected duplicate routing priority error")
	}

	gotZones := defaultNATSourceZones(map[string]struct{}{"wan": {}, "lan": {}, "dmz": {}}, "wan")
	wantZones := []string{"dmz", "lan"}
	if !reflect.DeepEqual(gotZones, wantZones) {
		t.Fatalf("defaultNATSourceZones = %v, want %v", gotZones, wantZones)
	}
}

func TestValidateVPNHelpers(t *testing.T) {
	if err := validateWireGuardPeer(WGPeer{
		PublicKey:           "peer-public",
		AllowedIPs:          []string{"10.10.0.0/24"},
		Endpoint:            "vpn.example.com:51820",
		PersistentKeepalive: 15,
	}); err != nil {
		t.Fatalf("validateWireGuardPeer(valid): %v", err)
	}
	if err := validateWireGuardPeer(WGPeer{PublicKey: "", AllowedIPs: []string{"10.10.0.0/24"}}); err == nil {
		t.Fatal("expected missing public key error")
	}

	if err := validateManagedOpenVPN(&OpenVPNManagedClientConfig{
		Remote: "vpn.example.com",
		CA:     "ca",
		Cert:   "cert",
		Key:    "key",
	}, "client"); err != nil {
		t.Fatalf("validateManagedOpenVPN(valid): %v", err)
	}
	if err := validateManagedOpenVPN(&OpenVPNManagedClientConfig{
		Remote:   "vpn.example.com",
		CA:       "ca",
		Cert:     "cert",
		Key:      "key",
		Username: "user",
	}, "client"); err == nil {
		t.Fatal("expected username/password mismatch error")
	}

	zoneSet := map[string]struct{}{"wan": {}}
	ifaceSet := map[string]struct{}{"eth0": {}}
	if err := validateOpenVPNServer(&OpenVPNManagedServerConfig{
		ListenPort:      1194,
		Proto:           "udp",
		ListenZone:      "wan",
		ListenInterfaces: []string{"eth0"},
		TunnelCIDR:      "10.9.0.0/24",
		PushDNS:         []string{"1.1.1.1"},
		PushRoutes:      []string{"10.20.0.0/24"},
	}, "server", zoneSet, ifaceSet); err != nil {
		t.Fatalf("validateOpenVPNServer(valid): %v", err)
	}
	if err := validateOpenVPNServer(&OpenVPNManagedServerConfig{
		TunnelCIDR: "10.9.0.0/24",
		PushDNS:    []string{"not-an-ip"},
	}, "server", zoneSet, ifaceSet); err == nil {
		t.Fatal("expected invalid push DNS error")
	}

	if err := validateVPNPort("vpn", 0, 1194); err != nil {
		t.Fatalf("validateVPNPort(default): %v", err)
	}
	if err := validateVPNPort("vpn", 70000, 70000); err == nil {
		t.Fatal("expected invalid vpn port error")
	}
	if err := validateVPNProto("vpn", ""); err != nil {
		t.Fatalf("validateVPNProto(default): %v", err)
	}
	if err := validateVPNProto("vpn", "icmp"); err == nil {
		t.Fatal("expected invalid vpn proto error")
	}
}
