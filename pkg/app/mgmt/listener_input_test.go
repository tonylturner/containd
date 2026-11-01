// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// The listeners management binds and the management INPUT the compiler
// admits come from one resolution: every served port is admitted, with
// environment addresses and with the stored configuration's defaults.
func TestManagementInputAdmitsServedListeners(t *testing.T) {
	dir := t.TempDir()
	sshTestKeyPair(t, dir, "server")
	stored := config.DefaultConfig()
	stored.System.Mgmt.TLSCertFile = filepath.Join(dir, "server.crt")
	stored.System.Mgmt.TLSKeyFile = filepath.Join(dir, "server.key")
	for _, tc := range []struct {
		name string
		env  map[string]string
		want []int
	}{
		{"defaults", nil, []int{8080, 8443, 2222}},
		{"environment", map[string]string{config.EnvManagementHTTPAddr: ":18080", config.EnvManagementHTTPSAddr: ":18443", config.EnvSSHAddr: ":12222"},
			[]int{18080, 18443, 12222}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			listener, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), stored, nil)
			if err != nil {
				t.Fatal(err)
			}
			served := configuredBinds(listener).record()
			ssh := config.ManagementListener{Addr: resolveSSHRuntimeConfig(stored).sshAddr, Enabled: true}
			for i, l := range []config.ManagementListener{served.HTTP, served.HTTPS, ssh} {
				if l.Port() != tc.want[i] {
					t.Fatalf("served listeners = %+v, SSH %+v, want ports %v", served, ssh, tc.want)
				}
			}
			admitted := map[int]bool{}
			for _, rule := range compile.ManagementLocalInput(stored) {
				admitted[rule.Port] = true
			}
			for _, port := range tc.want {
				if !admitted[port] {
					t.Fatalf("served port %d not admitted: %v", port, admitted)
				}
			}
			if len(admitted) != len(tc.want) {
				t.Fatalf("admitted ports %v, want exactly %v", admitted, tc.want)
			}
		})
	}
}
