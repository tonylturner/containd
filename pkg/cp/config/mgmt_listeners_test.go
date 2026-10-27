// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestResolveManagementListeners(t *testing.T) {
	off := false
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
		env  map[string]string
		want ManagementListeners
	}{
		{"nil config", nil, nil, ManagementListeners{
			HTTP: ManagementListener{":8080", true}, HTTPS: ManagementListener{":8443", true}, SSH: ManagementListener{":2222", true}}},
		{"stored", &Config{System: SystemConfig{
			Mgmt: MgmtConfig{ListenAddr: ":7070", HTTPListenAddr: ":9090", HTTPSListenAddr: "10.0.0.1:9443", EnableHTTPS: &off},
			SSH:  SSHConfig{ListenAddr: ":2200"}}}, nil, ManagementListeners{
			HTTP: ManagementListener{":9090", true}, HTTPS: ManagementListener{"10.0.0.1:9443", false}, SSH: ManagementListener{":2200", true}}},
		{"legacy alias", &Config{System: SystemConfig{Mgmt: MgmtConfig{ListenAddr: ":7070", HTTPListenAddr: " ", EnableHTTP: &off}}}, nil, ManagementListeners{
			HTTP: ManagementListener{":7070", false}, HTTPS: ManagementListener{":8443", true}, SSH: ManagementListener{":2222", true}}},
		{"environment", &Config{System: SystemConfig{Mgmt: MgmtConfig{HTTPListenAddr: ":9090", HTTPSListenAddr: ":9443"}, SSH: SSHConfig{ListenAddr: ":2200"}}},
			map[string]string{EnvManagementHTTPAddr: ":18080", EnvManagementHTTPSAddr: ":18443", EnvSSHAddr: ":12222"}, ManagementListeners{
				HTTP: ManagementListener{":18080", true}, HTTPS: ManagementListener{":18443", true}, SSH: ManagementListener{":12222", true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveManagementListeners(tc.cfg, env(tc.env)); got != tc.want {
				t.Fatalf("listeners = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestManagementListenerPort(t *testing.T) {
	for addr, want := range map[string]int{":8080": 8080, "10.0.0.1:8443": 8443, "[::]:2222": 2222, "127.0.0.1:0": 0, "nope": 0, ":99999": 0} {
		if got := (ManagementListener{Addr: addr, Enabled: true}).Port(); got != want {
			t.Fatalf("Port(%q) = %d, want %d", addr, got, want)
		}
	}
	if got := (ManagementListener{Addr: ":8080"}).Port(); got != 0 {
		t.Fatalf("a listener that is not served has port %d", got)
	}
}
