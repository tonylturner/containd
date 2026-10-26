// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"strings"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ManagementLocalInput derives the management listener INPUT allows from the
// stored interface access grants. It is shared by the compiled policy and by
// management recovery, which keeps exactly this access when it drops transit.
//
// Each listener is admitted on the port it binds under cfg at the next start
// (config.EffectiveManagementListeners) and, when that differs, on the port
// this process's management has bound (config.BoundManagementListeners):
// listener settings bind only at startup, so a committed listener change
// must keep admitting the sockets that serve until the restart.
func ManagementLocalInput(cfg *config.Config) []rules.LocalServiceRule {
	next := config.EffectiveManagementListeners(cfg)
	bound := config.BoundManagementListeners()
	listeners := []struct {
		id          string
		next, bound config.ManagementListener
		access      func(config.InterfaceAccess) bool
	}{
		{"auto-allow-mgmt-http", next.HTTP, bound.HTTP,
			func(a config.InterfaceAccess) bool { return granted(a.Mgmt) && granted(a.HTTP) }},
		{"auto-allow-mgmt-https", next.HTTPS, bound.HTTPS,
			func(a config.InterfaceAccess) bool { return granted(a.Mgmt) && granted(a.HTTPS) }},
		{"auto-allow-ssh", next.SSH, bound.SSH,
			func(a config.InterfaceAccess) bool { return granted(a.SSH) }},
	}
	var out []rules.LocalServiceRule
	for _, listener := range listeners {
		port := listener.next.Port()
		if port != 0 {
			out = appendListenerInput(out, cfg, listener.id, port, listener.access)
		}
		if served := listener.bound.Port(); served != 0 && served != port {
			out = appendListenerInput(out, cfg, listener.id+"-bound", served, listener.access)
		}
	}
	return out
}

// appendListenerInput appends the allow of port on the interfaces whose
// access grants the listener, when any does.
func appendListenerInput(out []rules.LocalServiceRule, cfg *config.Config, id string, port int, access func(config.InterfaceAccess) bool) []rules.LocalServiceRule {
	rule := rules.LocalServiceRule{ID: id, Proto: "tcp", Port: port}
	for _, iface := range cfg.Interfaces {
		device := strings.TrimSpace(iface.Device)
		if access(iface.Access) {
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
	if !rule.RecoverUnbound {
		return out
	}
	return append(out, rule)
}

func granted(value *bool) bool { return value == nil || *value }

// UnboundManagementPorts reports the same per-listener recovery predicate used
// by enforcement. This is degraded binding state, not reservation authority.
func UnboundManagementPorts(cfg *config.Config, live []string) []int {
	var ports []int
	if cfg == nil {
		return ports
	}
	for _, rule := range ManagementLocalInput(cfg) {
		if _, recovery := mgmtpath.ResolveBindings(rule.Ifaces, rule.DeniedIfaces, live); recovery {
			ports = append(ports, rule.Port)
		}
	}
	return ports
}
