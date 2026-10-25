// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// ApplianceDefaults is the single first-boot/factory-reset configuration builder.
// Discovery changes only the new in-memory config; callers preflight before any
// persistence or destructive action.
func ApplianceDefaults(r *mgmtpath.Reservation) *config.Config {
	def := config.DefaultConfig()
	config.ApplyBootstrapEnvDefaults(def)
	def.System.Hostname = "containd"
	def.System.Mgmt.ListenAddr = ":8080"
	def.System.Mgmt.HTTPListenAddr = ":8080"
	def.System.Mgmt.HTTPSListenAddr = ":8443"
	t := true
	def.System.Mgmt.EnableHTTP = &t
	def.System.Mgmt.EnableHTTPS = &t
	def.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
	def.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
	def.System.SSH.ListenAddr = ":2222"
	def.System.SSH.AuthorizedKeysDir = "/data/ssh/authorized_keys.d"
	if r != nil {
		// Enforcement is part of the reservation substrate, not a student
		// preference. The engine independently checks deployment enforcement.
		def.DataPlane.Enforcement = true
		def.DataPlane.EnforceTable = "containd"
		def.System.Mgmt.ListenAddr = fmt.Sprintf(":%d", r.Port)
		def.System.Mgmt.HTTPListenAddr = fmt.Sprintf(":%d", r.Port)
		if config.ManagementListenerOverlaps(def.System.Mgmt.HTTPSListenAddr, r) {
			f := false
			def.System.Mgmt.EnableHTTPS = &f
		}
		if config.ManagementListenerOverlaps(def.System.SSH.ListenAddr, r) {
			def.System.SSH.ListenAddr = "127.0.0.1:0"
		}
	}
	AutoBindDefaultInterfaceDevicesReserved(def, r)
	return def
}
