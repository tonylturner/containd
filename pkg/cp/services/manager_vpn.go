// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// OpenVPNClients is the service-owned credential authority. IDs, not names,
// select credentials; config/candidate rollback cannot alter this authority.
// Download is read-only. RevokeResult distinguishes persistence from runtime.
type OpenVPNClients interface {
	ListOpenVPNClients(context.Context) (OpenVPNClientList, error)
	CreateOpenVPNClient(context.Context, string) (OpenVPNCredential, error)
	DownloadOpenVPNClient(context.Context, string) ([]byte, error)
	RevokeOpenVPNClient(context.Context, string) (OpenVPNRevokeResult, error)
}

func (m *Manager) ListOpenVPNClients(ctx context.Context) (OpenVPNClientList, error) {
	return m.VPN.ListOpenVPNClients(ctx)
}
func (m *Manager) CreateOpenVPNClient(ctx context.Context, name string) (OpenVPNCredential, error) {
	return m.VPN.CreateOpenVPNClient(ctx, name)
}
func (m *Manager) DownloadOpenVPNClient(ctx context.Context, id string) ([]byte, error) {
	return m.VPN.DownloadOpenVPNClient(ctx, id)
}
func (m *Manager) RevokeOpenVPNClient(ctx context.Context, id string) (OpenVPNRevokeResult, error) {
	return m.VPN.RevokeOpenVPNClient(ctx, id)
}

func openVPNConfigError(err error) error {
	if err == nil {
		return nil
	}
	return &config.ServiceConfigError{Service: config.ServiceOpenVPN, Err: err}
}

// preflight is pure: in particular no PKI, directories or credential files are
// created. The returned parsed profile is used directly, avoiding a second read
// of untrusted ConfigPath between validation and publication.
func (m *VPNManager) preflight(cfg config.OpenVPNConfig) (*OpenVPNProfile, error) {
	if cfg.Mode != "" && cfg.Mode != "client" && cfg.Mode != "server" {
		return nil, fmt.Errorf("invalid OpenVPN mode")
	}
	if !cfg.Enabled {
		return nil, validateDormantOpenVPN(cfg)
	}
	if cfg.Managed != nil {
		if cfg.Enabled && cfg.Mode == "server" {
			return nil, fmt.Errorf("managed client requires client mode")
		}
		if _, err := validateOpenVPNManagedClient(cfg.Managed); err != nil {
			return nil, err
		}
	}
	if cfg.Server != nil {
		if cfg.Enabled && cfg.Mode != "server" {
			return nil, fmt.Errorf("server requires server mode")
		}
		if _, err := validateOpenVPNManagedServer(cfg.Server); err != nil {
			return nil, err
		}
	}
	var p *OpenVPNProfile
	if strings.TrimSpace(cfg.ConfigPath) != "" {
		var err error
		p, err = readOpenVPNProfile(cfg.ConfigPath)
		if err != nil {
			return nil, err
		}
	}
	if !m.SuperviseOpenVPN {
		return nil, fmt.Errorf("openvpn enabled but supervision disabled")
	}
	if m.OpenVPNPath == "" {
		return nil, fmt.Errorf("openvpn binary not present")
	}
	if cfg.Mode == "server" && cfg.Server == nil {
		return nil, fmt.Errorf("server requires managed server settings")
	}
	if cfg.Server == nil && cfg.Managed == nil && p == nil {
		return nil, fmt.Errorf("openvpn requires a profile or managed settings")
	}
	return p, nil
}

func (m *VPNManager) Validate(ctx context.Context, cfg config.VPNConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := m.preflight(cfg.OpenVPN)
	return openVPNConfigError(err)
}

func (m *VPNManager) Apply(ctx context.Context, cfg config.VPNConfig) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.applyVPNLocked(ctx, cloneVPNConfig(cfg))
}

func (m *VPNManager) applyVPNLocked(ctx context.Context, cfg config.VPNConfig) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if err != nil {
			m.lastError = err.Error()
			m.ovpnLastError = err.Error()
		} else {
			m.lastError = ""
			m.ovpnLastError = ""
		}
	}()
	p, validationErr := m.preflight(cfg.OpenVPN)
	if validationErr != nil {
		return openVPNConfigError(validationErr)
	}
	if err = os.MkdirAll(m.BaseDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "vpn.json")
	if !cfg.WireGuard.Enabled && !cfg.OpenVPN.Enabled {
		if err = m.stopOpenVPN(); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		b, e := json.MarshalIndent(cfg, "", "  ")
		if e != nil {
			return e
		}
		if err = atomicWriteFile(path, b, 0o600); err != nil {
			return err
		}
	}
	if cfg.OpenVPN.Enabled {
		var configPath string
		var crlNumber int64
		switch {
		case cfg.OpenVPN.Mode == "server":
			configPath, crlNumber, err = m.renderOpenVPNManagedServer(cfg.OpenVPN.Server)
		case cfg.OpenVPN.Managed != nil:
			configPath, err = m.renderOpenVPNManagedClient(cfg.OpenVPN.Managed)
		default:
			configPath, err = m.renderOpenVPNProfile(p)
		}
		if err != nil {
			return err
		}
		if err = m.startOpenVPN(ctx, configPath); err != nil {
			return err
		}
		m.mu.Lock()
		if m.ovpnRunning {
			m.ovpnCRLNumber = crlNumber
		}
		m.mu.Unlock()
	} else {
		if err = m.stopOpenVPN(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.mu.Unlock()
	return nil
}

// The digest includes all daemon-consumed material, not mtimes or just a path.
// This function only receives containd-rendered files; untrusted references
// have already been eliminated by the bounded parser.
func openVPNMaterialRevision(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	configDigest := sha256.Sum256(b)
	_, _ = h.Write(configDigest[:])
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "ca", "cert", "key", "tls-auth", "tls-crypt", "auth-user-pass", "crl-verify":
		default:
			continue
		}
		file := strings.Trim(f[1], `"`)
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(f[0]))
		_, _ = h.Write([]byte{0})
		materialDigest := sha256.Sum256(data)
		_, _ = h.Write(materialDigest[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Keep applied state independent from callers' mutable candidate snapshots.
func cloneVPNConfig(cfg config.VPNConfig) config.VPNConfig {
	cfg.WireGuard.ListenInterfaces = append([]string(nil), cfg.WireGuard.ListenInterfaces...)
	cfg.WireGuard.Peers = append([]config.WGPeer(nil), cfg.WireGuard.Peers...)
	for n := range cfg.WireGuard.Peers {
		cfg.WireGuard.Peers[n].AllowedIPs = append([]string(nil), cfg.WireGuard.Peers[n].AllowedIPs...)
	}
	if cfg.OpenVPN.Managed != nil {
		value := *cfg.OpenVPN.Managed
		cfg.OpenVPN.Managed = &value
	}
	if cfg.OpenVPN.Server != nil {
		value := *cfg.OpenVPN.Server
		value.ListenInterfaces = append([]string(nil), value.ListenInterfaces...)
		value.PushDNS = append([]string(nil), value.PushDNS...)
		value.PushRoutes = append([]string(nil), value.PushRoutes...)
		cfg.OpenVPN.Server = &value
	}
	return cfg
}
