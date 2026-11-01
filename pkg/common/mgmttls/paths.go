// SPDX-License-Identifier: Apache-2.0

// Package mgmttls publishes and loads management TLS identities atomically.
package mgmttls

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	DefaultDataDir    = "/data"
	bundleRelative    = "tls/server.pem"
	DefaultCertFile   = DefaultDataDir + "/tls/server.crt"
	DefaultKeyFile    = DefaultDataDir + "/tls/server.key"
	DefaultBundleFile = DefaultDataDir + "/" + bundleRelative
)

// Managed reports whether both resolved paths select containd's default identity.
func Managed(cfg *config.Config) bool {
	cert, key := ResolveFiles(cfg)
	return filepath.Clean(cert) == DefaultCertFile && filepath.Clean(key) == DefaultKeyFile
}

// IdentityFiles selects the single managed bundle or the read-only external files.
func IdentityFiles(cfg *config.Config) (string, string) {
	return IdentityFilesIn(cfg, DefaultDataDir)
}

// IdentityFilesIn resolves the listener and upload paths with a supplied
// appliance data root. Only the managed bundle is rebased; external paths
// always retain their resolved locations.
func IdentityFilesIn(cfg *config.Config, dataDir string) (string, string) {
	if Managed(cfg) {
		bundle := filepath.Join(dataDir, bundleRelative)
		return bundle, bundle
	}
	return ResolveFiles(cfg)
}

// ResolvedFile identifies a listener file and the setting that selected it.
type ResolvedFile struct {
	Path string
	// Source is an environment variable name, dotted config field, or "default".
	Source string
}

// ResolveFiles applies environment overrides, configured paths, then defaults.
// Certificate and key overrides are independent.
func ResolveFiles(cfg *config.Config) (certFile, keyFile string) {
	cert, key := ResolveFilesWithSources(cfg)
	return cert.Path, key.Path
}

// ResolveFilesWithSources resolves listener files with their selection sources.
func ResolveFilesWithSources(cfg *config.Config) (cert, key ResolvedFile) {
	var cfgCert, cfgKey string
	if cfg != nil {
		cfgCert = cfg.System.Mgmt.TLSCertFile
		cfgKey = cfg.System.Mgmt.TLSKeyFile
	}
	return resolveFile("CONTAIND_TLS_CERT_FILE", cfgCert, "system.mgmt.tlsCertFile", DefaultCertFile),
		resolveFile("CONTAIND_TLS_KEY_FILE", cfgKey, "system.mgmt.tlsKeyFile", DefaultKeyFile)
}

func resolveFile(env, configured, field, fallback string) ResolvedFile {
	if path := strings.TrimSpace(os.Getenv(env)); path != "" {
		return ResolvedFile{Path: path, Source: env}
	}
	if path := strings.TrimSpace(configured); path != "" {
		return ResolvedFile{Path: path, Source: field}
	}
	return ResolvedFile{Path: fallback, Source: "default"}
}
