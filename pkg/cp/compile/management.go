// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"strings"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func compileMgmtLocalInput(cfg *config.Config) []rules.LocalServiceRule {
	httpAddr := cfg.System.Mgmt.HTTPListenAddr
	if strings.TrimSpace(httpAddr) == "" {
		httpAddr = cfg.System.Mgmt.ListenAddr
	}
	httpEnabled := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
	httpsEnabled := strings.TrimSpace(cfg.System.Mgmt.HTTPSListenAddr) != ""
	if cfg.System.Mgmt.EnableHTTPS != nil {
		httpsEnabled = *cfg.System.Mgmt.EnableHTTPS
	}
	listeners := []struct {
		id      string
		port    int
		enabled bool
		access  func(config.InterfaceAccess) bool
	}{
		{"auto-allow-mgmt-http", listenPortOrDefault(httpAddr, 8080), httpEnabled,
			func(a config.InterfaceAccess) bool { return granted(a.Mgmt) && granted(a.HTTP) }},
		{"auto-allow-mgmt-https", listenPortOrDefault(cfg.System.Mgmt.HTTPSListenAddr, 8443), httpsEnabled,
			func(a config.InterfaceAccess) bool { return granted(a.Mgmt) && granted(a.HTTPS) }},
		{"auto-allow-ssh", listenPortOrDefault(cfg.System.SSH.ListenAddr, 2222), true,
			func(a config.InterfaceAccess) bool { return granted(a.SSH) }},
	}
	var out []rules.LocalServiceRule
	for _, listener := range listeners {
		if !listener.enabled || listener.port == 0 {
			continue
		}
		rule := rules.LocalServiceRule{ID: listener.id, Proto: "tcp", Port: listener.port}
		for _, iface := range cfg.Interfaces {
			device := strings.TrimSpace(iface.Device)
			if listener.access(iface.Access) {
				rule.RecoverUnbound = true
				if device != "" {
					rule.Ifaces = append(rule.Ifaces, device)
				}
			} else {
				// Legacy/virtual rows may name a kernel device directly. Never
				// let recovery override their explicit access denial either.
				if device == "" {
					device = strings.TrimSpace(iface.Name)
				}
				if device != "" {
					rule.DeniedIfaces = append(rule.DeniedIfaces, device)
				}
			}
		}
		if rule.RecoverUnbound {
			out = append(out, rule)
		}
	}
	return out
}

func granted(value *bool) bool { return value == nil || *value }

// UnboundManagementPorts reports the same per-listener recovery predicate used
// by enforcement. This is degraded binding state, not reservation authority.
func UnboundManagementPorts(cfg *config.Config, live []string) []int {
	var ports []int
	if cfg == nil {
		return ports
	}
	for _, rule := range compileMgmtLocalInput(cfg) {
		if _, recovery := mgmtpath.ResolveBindings(rule.Ifaces, rule.DeniedIfaces, live); recovery {
			ports = append(ports, rule.Port)
		}
	}
	return ports
}
