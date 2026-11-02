// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// applySide mutates only one proxy owner. A retry of Envoy must not restart
// healthy Nginx (or remove its rendered configuration), and vice versa.
func (m *ProxyManager) applySide(ctx context.Context, cfg config.ProxyConfig, forward bool) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	name, enabled := "forward-proxy", cfg.Forward.Enabled
	selected := config.ProxyConfig{Forward: cfg.Forward}
	if !forward {
		name, enabled = "reverse-proxy", cfg.Reverse.Enabled
		selected = config.ProxyConfig{Reverse: cfg.Reverse}
	}
	// Stop does not depend on validation/rendering of dormant or broken material.
	if !enabled {
		return m.stopSide(ctx, forward)
	}
	if err := m.checkProxyConfig(selected); err != nil {
		return serviceConfigError(config.ServiceProxy, err)
	}
	if !m.Supervise {
		return errors.New("proxy supervision disabled")
	}
	// After a manager restart, clear any orphan before claiming new startup.
	if err := stopPriorTraffic(ctx, m.BaseDir, name); err != nil {
		return err
	}
	if err := m.prepareRenderDirs(); err != nil {
		return err
	}
	files, err := m.proxyFiles(selected)
	if err != nil {
		return &daemonRenderError{err}
	}
	file := files[0]
	if !forward {
		file = files[1]
	}
	if file.body == nil {
		return serviceConfigError(config.ServiceProxy, errors.New("enabled proxy has no runtime configuration"))
	}
	if err := publishDaemonFiles(ctx, file); err != nil {
		return err
	}
	if forward {
		err = m.startOrRestartEnvoy(ctx)
	} else {
		err = m.startOrRestartNginx(ctx)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	done := m.envoyDone
	if !forward {
		done = m.nginxDone
	}
	m.mu.Unlock()
	// Local process stability, not a network/upstream-availability probe.
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return errors.New("proxy exited during startup")
	case <-timer.C:
	}
	m.mu.Lock()
	if forward {
		m.lastCfg.Forward = cfg.Forward
	} else {
		m.lastCfg.Reverse = cfg.Reverse
	}
	applied := m.lastCfg
	m.lastRender = time.Now().UTC()
	m.mu.Unlock()
	m.syncAccessTailers(applied)
	return nil
}

func (m *ProxyManager) stopSide(ctx context.Context, forward bool) error {
	name := "forward-proxy"
	if !forward {
		name = "reverse-proxy"
	}
	if err := stopPriorTraffic(ctx, m.BaseDir, name); err != nil {
		return err
	}
	var err error
	if forward {
		err = m.stopEnvoy()
		m.stopEnvoyAccessTailer()
	} else {
		name = "reverse-proxy"
		err = m.stopNginx()
		m.stopNginxAccessTailer()
	}
	if err != nil {
		return err
	}
	if err := stopPriorTraffic(ctx, m.BaseDir, name); err != nil {
		return err
	}
	m.mu.Lock()
	if forward {
		m.lastCfg.Forward = config.ForwardProxyConfig{}
	} else {
		m.lastCfg.Reverse = config.ReverseProxyConfig{}
	}
	m.mu.Unlock()
	return nil
}

func (m *VPNManager) applyDelivery(ctx context.Context, cfg config.VPNConfig) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if cfg.OpenVPN.Enabled {
		if _, err := m.preflight(cfg.OpenVPN); err != nil {
			return openVPNConfigError(err)
		}
	}
	// Discover owned descendants before reaping a known master; this also
	// proves absence when the manager has no in-memory process handle.
	if err := stopPriorTraffic(ctx, m.BaseDir, "openvpn"); err != nil {
		return err
	}
	if err := m.stopOpenVPN(); err != nil {
		return err
	}
	if !cfg.OpenVPN.Enabled {
		m.mu.Lock()
		m.lastCfg.OpenVPN = config.OpenVPNConfig{}
		m.mu.Unlock()
		return nil
	}
	return m.applyVPNLocked(ctx, cloneVPNConfig(cfg))
}

// Rendered paths are stable ownership markers for pre-existing runtimes. They
// never select an unrelated daemon merely by its binary name or listening port.
func trafficConfigPaths(base, name string) []string {
	switch name {
	case "forward-proxy":
		return []string{filepath.Join(base, "envoy-forward.yaml")}
	case "reverse-proxy":
		return []string{filepath.Join(base, "nginx-reverse.conf")}
	case "openvpn":
		return []string{filepath.Join(base, "openvpn-import", "openvpn.conf"), filepath.Join(openVPNManagedDir(), "openvpn.conf"), filepath.Join(openVPNManagedServerDir(), "openvpn.conf")}
	}
	return nil
}

// Inherited by daemon workers so ownership survives rewritten command lines.
func trafficOwnerTag(base, name string) string {
	abs, err := filepath.Abs(base)
	if err != nil {
		abs = base
	}
	return "CONTAIND_TRAFFIC_OWNER=" + abs + ":" + name
}
