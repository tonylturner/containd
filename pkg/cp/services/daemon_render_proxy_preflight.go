// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func (m *ProxyManager) checkProxyConfig(cfg config.ProxyConfig) error {
	// Runtime managers receive only the service model, not the zone inventory.
	// Store validation checks membership; recheck every zone's sink grammar here.
	for _, z := range cfg.Forward.ListenZones {
		if err := config.ValidateProxyListenZone(z); err != nil {
			return err
		}
	}
	structural := cfg
	structural.Forward.ListenZones = nil
	if err := validateDaemonService(config.ServicesConfig{Proxy: structural}); err != nil {
		return err
	}
	if err := validateDaemonPaths(m.BaseDir, m.CertsDir); err != nil {
		return err
	}
	if !cfg.Reverse.Enabled {
		return nil
	}
	for _, site := range cfg.Reverse.Sites {
		if !site.TLSEnabled {
			continue
		}
		if err := m.checkCertificate(site.CertRef); err != nil {
			return fmt.Errorf("site %s TLS: %w", site.Name, err)
		}
	}
	return nil
}

func (m *ProxyManager) checkCertificate(ref string) error {
	if err := config.ValidateProxyCertRef(ref); err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(m.CertsDir)
	if err != nil {
		return fmt.Errorf("certificate directory: %w", err)
	}
	paths := make([]string, 0, 2)
	for _, ext := range []string{".crt", ".key"} {
		path, err := filepath.EvalSymlinks(filepath.Join(root, ref+ext))
		if err != nil {
			return fmt.Errorf("certificate material: %w", err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("certificate material escapes certs directory")
		}
		paths = append(paths, path)
	}
	pair, err := tls.LoadX509KeyPair(paths[0], paths[1])
	if err != nil {
		return fmt.Errorf("read matching certificate/key pair: %w", err)
	}
	now := time.Now()
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse certificate: %w", err)
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("certificate is not currently valid")
		}
	}
	return nil
}

func (m *ProxyManager) prepareRenderDirs() error {
	for _, path := range []string{m.BaseDir, filepath.Join(filepath.Dir(m.BaseDir), "logs")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	for _, sub := range []string{"body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		if err := os.MkdirAll(filepath.Join(m.BaseDir, "nginx-tmp", sub), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (m *ProxyManager) proxyFiles(cfg config.ProxyConfig) ([]daemonFile, error) {
	forward, err := m.renderForward(cfg.Forward)
	if err != nil {
		return nil, err
	}
	reverse, err := m.renderReverse(cfg.Reverse)
	if err != nil {
		return nil, err
	}
	return []daemonFile{
		{path: filepath.Join(m.BaseDir, "envoy-forward.yaml"), body: forward, check: m.checkForward},
		{path: filepath.Join(m.BaseDir, "nginx-reverse.conf"), body: reverse, check: m.checkReverse},
	}, nil
}

func (m *ProxyManager) checkForward(ctx context.Context, path string) error {
	if _, err := os.Stat(m.EnvoyPath); os.IsNotExist(err) {
		return nil
	}
	return checkDaemon(ctx, m.EnvoyPath, "--mode", "validate", "-c", path)
}

func (m *ProxyManager) checkReverse(ctx context.Context, path string) error {
	if _, err := os.Stat(m.NginxPath); os.IsNotExist(err) {
		return nil
	}
	return checkDaemon(ctx, m.NginxPath, "-t", "-c", path)
}

// Validate renders only in disposable storage; it never publishes active files
// or changes the supervised processes.
func (m *ProxyManager) Validate(ctx context.Context, cfg config.ProxyConfig) error {
	if err := m.checkProxyConfig(cfg); err != nil {
		return serviceConfigError(config.ServiceProxy, err)
	}
	dir, err := os.MkdirTemp("", "containd-proxy-validate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	preview := &ProxyManager{BaseDir: filepath.Join(dir, "services"), CertsDir: m.CertsDir, EnvoyPath: m.EnvoyPath, NginxPath: m.NginxPath}
	if err := preview.prepareRenderDirs(); err != nil {
		return err
	}
	files, err := preview.proxyFiles(cfg)
	if err != nil {
		return err
	}
	return serviceConfigError(config.ServiceProxy, publishDaemonFiles(ctx, files...))
}
