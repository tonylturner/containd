// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestResolveFiles(t *testing.T) {
	for _, tt := range []struct {
		name, envCert, envKey, cfgCert, cfgKey, wantCert, wantKey string
		wantCertSource, wantKeySource                             string
		nilConfig                                                 bool
	}{
		{name: "nil config", nilConfig: true, wantCert: DefaultCertFile, wantKey: DefaultKeyFile, wantCertSource: "default", wantKeySource: "default"},
		{name: "defaults", wantCert: DefaultCertFile, wantKey: DefaultKeyFile, wantCertSource: "default", wantKeySource: "default"},
		{name: "config", cfgCert: " /cfg/cert ", cfgKey: " /cfg/key ", wantCert: "/cfg/cert", wantKey: "/cfg/key", wantCertSource: "system.mgmt.tlsCertFile", wantKeySource: "system.mgmt.tlsKeyFile"},
		{name: "environment", envCert: " /env/cert ", envKey: " /env/key ", cfgCert: "/cfg/cert", cfgKey: "/cfg/key", wantCert: "/env/cert", wantKey: "/env/key", wantCertSource: "CONTAIND_TLS_CERT_FILE", wantKeySource: "CONTAIND_TLS_KEY_FILE"},
		{name: "independent cert override", envCert: "/env/cert", cfgKey: "/cfg/key", wantCert: "/env/cert", wantKey: "/cfg/key", wantCertSource: "CONTAIND_TLS_CERT_FILE", wantKeySource: "system.mgmt.tlsKeyFile"},
		{name: "independent key override", envKey: "/env/key", cfgCert: "/cfg/cert", wantCert: "/cfg/cert", wantKey: "/env/key", wantCertSource: "system.mgmt.tlsCertFile", wantKeySource: "CONTAIND_TLS_KEY_FILE"},
		{name: "whitespace", envCert: " ", envKey: " ", cfgCert: " ", cfgKey: " ", wantCert: DefaultCertFile, wantKey: DefaultKeyFile, wantCertSource: "default", wantKeySource: "default"},
		{name: "environment without config", nilConfig: true, envCert: "/env/cert", wantCert: "/env/cert", wantKey: DefaultKeyFile, wantCertSource: "CONTAIND_TLS_CERT_FILE", wantKeySource: "default"},
		{name: "explicit defaults", envCert: DefaultCertFile, cfgKey: DefaultKeyFile, wantCert: DefaultCertFile, wantKey: DefaultKeyFile, wantCertSource: "CONTAIND_TLS_CERT_FILE", wantKeySource: "system.mgmt.tlsKeyFile"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTAIND_TLS_CERT_FILE", tt.envCert)
			t.Setenv("CONTAIND_TLS_KEY_FILE", tt.envKey)
			var cfg *config.Config
			if !tt.nilConfig {
				cfg = &config.Config{}
				cfg.System.Mgmt.TLSCertFile = tt.cfgCert
				cfg.System.Mgmt.TLSKeyFile = tt.cfgKey
			}
			cert, key := ResolveFiles(cfg)
			if cert != tt.wantCert || key != tt.wantKey {
				t.Fatalf("ResolveFiles = %q, %q; want %q, %q", cert, key, tt.wantCert, tt.wantKey)
			}
			certInfo, keyInfo := ResolveFilesWithSources(cfg)
			if certInfo.Path != tt.wantCert || certInfo.Source != tt.wantCertSource {
				t.Fatalf("certificate = %+v; want path %q, source %q", certInfo, tt.wantCert, tt.wantCertSource)
			}
			if keyInfo.Path != tt.wantKey || keyInfo.Source != tt.wantKeySource {
				t.Fatalf("key = %+v; want path %q, source %q", keyInfo, tt.wantKey, tt.wantKeySource)
			}
		})
	}
}

func TestManagedIdentitySelection(t *testing.T) {
	for _, tc := range []struct {
		name, cert, key string
		managed         bool
	}{
		{"implicit defaults", "", "", true},
		{"explicit defaults", DefaultCertFile, DefaultKeyFile, true},
		{"cleaned defaults", "/data/tls/./server.crt", "/data/tls/../tls/server.key", true},
		{"external certificate", "/custom/cert", DefaultKeyFile, false},
		{"external bundle", "/custom/bundle", "/custom/bundle", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_TLS_CERT_FILE", "")
			t.Setenv("CONTAIND_TLS_KEY_FILE", "")
			cfg := &config.Config{}
			cfg.System.Mgmt.TLSCertFile = tc.cert
			cfg.System.Mgmt.TLSKeyFile = tc.key
			if Managed(cfg) != tc.managed {
				t.Fatal("wrong identity mode")
			}
			c, k := IdentityFiles(cfg)
			if tc.managed && (c != DefaultBundleFile || k != c) {
				t.Fatal("not using bundle")
			}
		})
	}
}
