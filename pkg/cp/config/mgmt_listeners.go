// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"strconv"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/common"
)

// Default management listener addresses, used when neither the environment
// nor the stored configuration sets one.
const (
	DefaultManagementHTTPAddr  = ":8080"
	DefaultManagementHTTPSAddr = ":8443"
	DefaultSSHAddr             = ":2222"
)

// Environment variables that set management listener addresses. They take
// precedence over the stored configuration.
const (
	EnvManagementHTTPAddr  = "CONTAIND_MGMT_ADDR"
	EnvManagementHTTPSAddr = "CONTAIND_MGMT_HTTPS_ADDR"
	EnvSSHAddr             = "CONTAIND_SSH_ADDR"
)

// ManagementListener is one management socket: its bind address and
// whether management serves it.
type ManagementListener struct {
	Addr    string
	Enabled bool
}

// Port is the TCP port of the listener; 0 when it is not served or its
// address names no port.
func (l ManagementListener) Port() int {
	if !l.Enabled {
		return 0
	}
	_, port, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

// ManagementListeners are the management HTTP, HTTPS and SSH listeners.
type ManagementListeners struct {
	HTTP, HTTPS, SSH ManagementListener
}

// ResolveManagementListeners is the one resolution of the listeners
// management binds for cfg: each address from env first, then from the
// stored configuration (HTTP: httpListenAddr, then the legacy listenAddr),
// then the default; a blank value counts as unset. HTTP and HTTPS are
// served unless the configuration disables them; SSH is always attempted.
// A nil cfg is the empty configuration.
func ResolveManagementListeners(cfg *Config, env func(string) string) ManagementListeners {
	var sys SystemConfig
	if cfg != nil {
		sys = cfg.System
	}
	first := common.FirstNonEmpty
	return ManagementListeners{
		HTTP: ManagementListener{
			Addr:    first(env(EnvManagementHTTPAddr), sys.Mgmt.HTTPListenAddr, sys.Mgmt.ListenAddr, DefaultManagementHTTPAddr),
			Enabled: sys.Mgmt.EnableHTTP == nil || *sys.Mgmt.EnableHTTP,
		},
		HTTPS: ManagementListener{
			Addr:    first(env(EnvManagementHTTPSAddr), sys.Mgmt.HTTPSListenAddr, DefaultManagementHTTPSAddr),
			Enabled: sys.Mgmt.EnableHTTPS == nil || *sys.Mgmt.EnableHTTPS,
		},
		SSH: ManagementListener{
			Addr:    first(env(EnvSSHAddr), sys.SSH.ListenAddr, DefaultSSHAddr),
			Enabled: true,
		},
	}
}

// ProcessEnv reads a listener variable from this process's environment,
// trimmed.
func ProcessEnv(name string) string { return common.EnvTrimmed(name, "") }

// EffectiveManagementListeners resolves cfg's listeners under this process's
// environment: the listeners management binds when it starts with cfg.
func EffectiveManagementListeners(cfg *Config) ManagementListeners {
	return ResolveManagementListeners(cfg, ProcessEnv)
}

var boundManagementListeners atomic.Pointer[ManagementListeners]

// SetBoundManagementListeners records the listeners the management server
// of this process has bound. Listener settings bind only at startup, so a
// committed listener change leaves these in place until a restart. The
// zero value records that nothing is bound.
func SetBoundManagementListeners(l ManagementListeners) {
	boundManagementListeners.Store(&l)
}

// BoundManagementListeners returns the listeners recorded by
// SetBoundManagementListeners; the zero value in a process whose
// management has bound nothing, such as a separate engine process.
func BoundManagementListeners() ManagementListeners {
	if l := boundManagementListeners.Load(); l != nil {
		return *l
	}
	return ManagementListeners{}
}
