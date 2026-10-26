// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestResolveFiles(t *testing.T) {
	for _, tt := range []struct {
		name, envCert, envKey, cfgCert, cfgKey, wantCert, wantKey string
		nilConfig                                                 bool
	}{
		{name: "nil config", nilConfig: true, wantCert: DefaultCertFile, wantKey: DefaultKeyFile},
		{name: "defaults", wantCert: DefaultCertFile, wantKey: DefaultKeyFile},
		{name: "config", cfgCert: "/cfg/cert", cfgKey: "/cfg/key", wantCert: "/cfg/cert", wantKey: "/cfg/key"},
		{name: "environment", envCert: " /env/cert ", envKey: " /env/key ", cfgCert: "/cfg/cert", cfgKey: "/cfg/key", wantCert: "/env/cert", wantKey: "/env/key"},
		{name: "independent cert override", envCert: "/env/cert", cfgKey: "/cfg/key", wantCert: "/env/cert", wantKey: "/cfg/key"},
		{name: "independent key override", envKey: "/env/key", cfgCert: "/cfg/cert", wantCert: "/cfg/cert", wantKey: "/env/key"},
		{name: "whitespace", envCert: " ", cfgCert: " ", cfgKey: " ", wantCert: DefaultCertFile, wantKey: DefaultKeyFile},
		{name: "environment without config", nilConfig: true, envCert: "/env/cert", wantCert: "/env/cert", wantKey: DefaultKeyFile},
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
		})
	}
}
