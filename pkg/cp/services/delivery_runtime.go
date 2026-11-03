// SPDX-License-Identifier: Apache-2.0
package services

import (
	"encoding/json"
	"os/exec"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func serviceOwnerInput(s config.ServicesConfig, name protection.SubsystemName) any {
	switch name {
	case protection.SubsystemDNS:
		return s.DNS
	case protection.SubsystemNTP:
		return s.NTP
	case protection.SubsystemSyslog:
		return s.Syslog
	case protection.SubsystemForwardProxy:
		return s.Proxy.Forward
	case protection.SubsystemReverseProxy:
		return s.Proxy.Reverse
	case protection.SubsystemOpenVPN:
		return s.VPN.OpenVPN
	case protection.SubsystemDHCP:
		return s.DHCP
	}
	return nil
}

func processLive(cmd *exec.Cmd, done <-chan struct{}) bool {
	if cmd == nil || cmd.Process == nil || done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// ownerRuntime reads the owner's confirmed configuration and existing lifecycle
// facts. An unsupervised daemon cannot prove a running listener.
func (m *Manager) ownerRuntime(name protection.SubsystemName, enabled bool) (string, bool) {
	var cfg any
	live := false
	switch name {
	case protection.SubsystemDNS:
		m.DNS.mu.Lock()
		defer m.DNS.mu.Unlock()
		cfg = m.DNS.lastCfg
		live = m.DNS.lastCfg.Enabled == enabled && ((!enabled && m.DNS.cmd == nil) ||
			(enabled && m.DNS.running && processLive(m.DNS.cmd, m.DNS.done)))
	case protection.SubsystemNTP:
		m.NTP.mu.Lock()
		defer m.NTP.mu.Unlock()
		cfg = m.NTP.lastCfg
		live = m.NTP.lastCfg.Enabled == enabled && ((!enabled && m.NTP.cmd == nil) ||
			(enabled && processLive(m.NTP.cmd, m.NTP.done)))
	case protection.SubsystemSyslog:
		m.Syslog.mu.Lock()
		defer m.Syslog.mu.Unlock()
		cfg = m.Syslog.config
		live = m.Syslog.applied && (len(m.Syslog.config.Forwarders) > 0) == enabled
		if enabled {
			live = live && m.Syslog.cancel != nil && m.Syslog.done != nil
			if live {
				select {
				case <-m.Syslog.done:
					live = false
				default:
				}
			}
		} else {
			live = live && m.Syslog.cancel == nil
		}
	case protection.SubsystemForwardProxy, protection.SubsystemReverseProxy:
		m.Proxy.mu.Lock()
		defer m.Proxy.mu.Unlock()
		cmd, done := m.Proxy.envoyCmd, m.Proxy.envoyDone
		cfg = m.Proxy.lastCfg.Forward
		if name == protection.SubsystemReverseProxy {
			cmd, done, cfg = m.Proxy.nginxCmd, m.Proxy.nginxDone, m.Proxy.lastCfg.Reverse
		}
		live = processLive(cmd, done)
		if !enabled {
			service := "forward-proxy"
			if name == protection.SubsystemReverseProxy {
				service = "reverse-proxy"
			}
			live = cmd == nil && trafficAbsent(m.Proxy.BaseDir, service)
		}
	case protection.SubsystemOpenVPN:
		m.VPN.mu.Lock()
		defer m.VPN.mu.Unlock()
		cfg = m.VPN.lastCfg.OpenVPN
		live = m.VPN.ovpnRunning && processLive(m.VPN.ovpnCmd, m.VPN.ovpnWaitCh)
		if !enabled {
			live = m.VPN.ovpnCmd == nil && !m.VPN.ovpnRunning && trafficAbsent(m.VPN.BaseDir, "openvpn")
		}
	}
	data, _ := json.Marshal(cfg)
	return string(data), live
}
