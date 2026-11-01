// SPDX-License-Identifier: Apache-2.0
package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateDaemonSinks(t *testing.T) {
	tests := []struct {
		name     string
		validate func(string) error
		valid    []string
		invalid  []string
	}{
		{"site", ValidateProxySiteID, []string{"app_1", "_site-2"}, []string{"", "1app", "../app", "app/name", strings.Repeat("a", 65)}},
		{"hostname", ValidateProxyHostname, []string{"app.example.com", "*.example.com", "example.com.", "10.0.0.1", "2001:db8::1"}, []string{"", "*", "app.*", ".example.com", "*.*.example.com", "*.10.0.0.1", "http://example.com", "a..com", "-x.com"}},
		{"backend", ValidateProxyBackend, []string{"app.example:80", "192.0.2.1:443", "[2001:db8::1]:8443"}, []string{"", "http://app:80", "app", "app:0", "app:65536", "app:-1", "app:+80", "app:http", "app:80:90", "[app]:80", "[::1%lo0]:80", "2001:db8::1:80"}},
		{"certRef", ValidateProxyCertRef, []string{"app-2026", "Cert_1"}, []string{"", ".", "..", "../cert", "a/b", "a\\b", "cert.crt", strings.Repeat("a", 129)}},
		{"listenZone", ValidateProxyListenZone, []string{"lan", "vlan.1", "zone-2"}, []string{"", "zone/name", "../zone"}},
		{"remote", ValidateOpenVPNRemote, []string{"vpn.example.com", "192.0.2.1", "2001:db8::1"}, []string{"", "vpn.example:1194", "[::1]", "::1%lo0", "*.example.com", "../vpn", "--config"}},
		{"unbound", ValidateUnboundForwarder, []string{"1.1.1.1", "1.1.1.1@5353", "2001:db8::1", "2001:db8::1@53"}, []string{"", "dns.example", "1.1.1.1@0", "1.1.1.1@65536", "1.1.1.1@+53", "1.1.1.1@domain", "1.1.1.1@53@54", "1.1.1.1#tls", "[::1]", "::1%lo0", "../1.1.1.1"}},
		{"chrony", ValidateChronyServer, []string{"time.example.com", "192.0.2.1", "2001:db8::1"}, []string{"", "time.example:123", "[::1]", "*.example.com", "../time"}},
		{"socket", ValidateClamdSocketPath, []string{"/run/clamav/clamd.sock", "/tmp/clamd-1_socket"}, []string{"", "/", "relative.sock", "/run/../clamd.sock", "/run/./clamd.sock", "/run//clamd.sock", "/run/clamd.sock/", "/run\\clamd.sock"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, s := range tt.valid {
				if err := tt.validate(s); err != nil {
					t.Errorf("rejected %q: %v", s, err)
				}
			}
			for _, s := range tt.invalid {
				if err := tt.validate(s); err == nil {
					t.Errorf("accepted %q", s)
				}
			}
			for _, delimiter := range []string{"\r", "\n", "\x00", " ", "\t", ";", "{", "}", "#", "'", "\""} {
				for _, s := range []string{delimiter + tt.valid[0], tt.valid[0] + delimiter, tt.valid[0] + delimiter + "injected"} {
					if err := tt.validate(s); err == nil {
						t.Errorf("accepted unsafe input %q", s)
					}
				}
			}
		})
	}
}

func TestValidateDaemonAuthRecords(t *testing.T) {
	for _, s := range []string{"password", "spaces ;{}#'\" are data", "é日本語", "../password"} {
		if err := ValidateOpenVPNAuthLine(s); err != nil {
			t.Errorf("rejected legitimate credential: %v", err)
		}
	}
	for _, s := range []string{"", "secret\ninjected", "secret\r", "\x00secret"} {
		err := ValidateOpenVPNAuthLine(s)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("unsafe credential accepted or echoed: %v", err)
		}
	}
}

func TestValidateDaemonDormantFields(t *testing.T) {
	tests := []struct {
		name    string
		service string
		mutate  func(*ServicesConfig)
	}{
		{"dns", ServiceDNS, func(s *ServicesConfig) { s.DNS.UpstreamServers = []string{"1.1.1.1\nserver:"} }},
		{"ntp", ServiceNTP, func(s *ServicesConfig) { s.NTP.Servers = []string{"pool.example iburst"} }},
		{"av", ServiceAV, func(s *ServicesConfig) { s.AV.ClamAV.SocketPath = "/run/clamd\nUser root" }},
		{"site", ServiceProxy, func(s *ServicesConfig) {
			s.Proxy.Reverse.Sites = []ReverseProxySite{{Name: "app;{}", ListenPort: 80, Backends: []string{"127.0.0.1:80"}}}
		}},
		{"backend", ServiceProxy, func(s *ServicesConfig) {
			s.Proxy.Reverse.Sites = []ReverseProxySite{{Name: "app", ListenPort: 80, Backends: []string{"127.0.0.1:80 weight=2"}}}
		}},
		{"hostname", ServiceProxy, func(s *ServicesConfig) {
			s.Proxy.Reverse.Sites = []ReverseProxySite{{Name: "app", ListenPort: 80, Backends: []string{"127.0.0.1:80"}, Hostnames: []string{"app;}"}}}
		}},
		{"tls", ServiceProxy, func(s *ServicesConfig) {
			s.Proxy.Reverse.Sites = []ReverseProxySite{{Name: "app", ListenPort: 443, Backends: []string{"127.0.0.1:80"}, TLSEnabled: true}}
		}},
		{"cert", ServiceProxy, func(s *ServicesConfig) {
			s.Proxy.Reverse.Sites = []ReverseProxySite{{Name: "app", ListenPort: 80, Backends: []string{"127.0.0.1:80"}, CertRef: "../cert"}}
		}},
		{"domain", ServiceProxy, func(s *ServicesConfig) { s.Proxy.Forward.AllowedDomains = []string{"app;"} }},
		{"zone", ServiceProxy, func(s *ServicesConfig) { s.Proxy.Forward.ListenZones = []string{"missing"} }},
		{"clients", ServiceProxy, func(s *ServicesConfig) { s.Proxy.Forward.AllowedClients = []string{""} }},
		{"upstream", ServiceProxy, func(s *ServicesConfig) { s.Proxy.Forward.Upstream = " " }},
		{"remote", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Managed = &OpenVPNManagedClientConfig{Remote: "vpn.example\nup injected"}
		}},
		{"auth", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Managed = &OpenVPNManagedClientConfig{Password: "secret\ninjected"}
		}},
		{"endpoint", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{PublicEndpoint: "vpn.example;up"}
		}},
		{"proto", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{Proto: " udp "}
		}},
		{"pushDNS", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{PushDNS: []string{"1.1.1.1\npush injected"}}
		}},
		{"route", ServiceOpenVPN, func(s *ServicesConfig) {
			s.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{PushRoutes: []string{" 10.0.0.0/8"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Services = ServicesConfig{}
			tt.mutate(&cfg.Services)
			err := cfg.Validate()
			var fault *ServiceConfigError
			if !errors.As(err, &fault) || fault.Service != tt.service {
				t.Fatalf("expected %s service error, got %v", tt.service, err)
			}
			if (tt.name == "clients" || tt.name == "upstream") && !strings.Contains(err.Error(), "not supported yet; clear this field") {
				t.Fatalf("unsupported field lacks repair instruction: %v", err)
			}
		})
	}
}

func TestValidateDaemonDisabledEmptyAndPEM(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services = ServicesConfig{}
	cfg.Services.VPN.OpenVPN.Managed = &OpenVPNManagedClientConfig{}
	cfg.Services.VPN.OpenVPN.Server = &OpenVPNManagedServerConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty disabled services rejected: %v", err)
	}
	// PEM is written to separate material files, not interpolated as directives.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	cfg.Services.VPN.OpenVPN = OpenVPNConfig{
		Enabled: true, Mode: "client",
		Managed: &OpenVPNManagedClientConfig{Remote: "2001:db8::1", CA: certPEM, Cert: certPEM,
			Key:      keyPEM,
			Username: "operator", Password: "spaces ;{}#'\""},
	}
	cfg.Services.Proxy.Forward.ListenZones = []string{cfg.Zones[0].Name}
	cfg.Services.Proxy.Reverse.Sites = []ReverseProxySite{{
		Name: "app", ListenPort: 443, Hostnames: []string{"*.example.com"},
		Backends: []string{"[2001:db8::1]:8443"}, TLSEnabled: true, CertRef: "app-cert",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid structured service input rejected: %v", err)
	}
}

func TestServiceConfigErrorsJoinAndUnwrap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services.DNS.UpstreamServers = []string{"unsafe\n"}
	cfg.Services.NTP.Servers = []string{"unsafe\n"}
	err := cfg.Validate()
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != 2 {
		t.Fatalf("did not collect both services: %v", err)
	}
	cause := errors.New("cause")
	if !errors.Is(&ServiceConfigError{Service: ServiceProxy, Err: cause}, cause) {
		t.Fatal("service error does not unwrap")
	}
}

func TestServiceConfigErrorsIdentifyUnits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services.Syslog.Forwarders = []SyslogForwarder{{Port: -1}}
	cfg.Services.DNS.UpstreamServers = []string{"invalid"}
	cfg.Services.NTP.Servers = []string{"invalid\n"}
	cfg.Services.AV = AVConfig{Enabled: true, Mode: "invalid"}
	cfg.Services.Proxy.Forward.Upstream = "unsupported"
	cfg.Services.DHCP.Router = "invalid"
	cfg.Services.VPN.WireGuard.ListenPort = -1
	cfg.Services.VPN.OpenVPN.Mode = "invalid"
	err := ValidateServiceConfigs(cfg)
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("service errors not joined: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range joined.Unwrap() {
		var fault *ServiceConfigError
		if !errors.As(e, &fault) {
			t.Fatalf("untyped service error: %v", e)
		}
		seen[fault.Service] = true
	}
	for _, name := range []string{ServiceSyslog, ServiceDNS, ServiceNTP, ServiceAV, ServiceProxy, ServiceDHCP, ServiceWireGuard, ServiceOpenVPN} {
		if !seen[name] {
			t.Errorf("missing error for %s", name)
		}
	}
}
