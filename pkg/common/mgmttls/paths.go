// SPDX-License-Identifier: Apache-2.0

// Package mgmttls resolves the management listener's certificate and key paths.
package mgmttls

import (
	"os"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	DefaultCertFile = "/data/tls/server.crt"
	DefaultKeyFile  = "/data/tls/server.key"
)

// ResolveFiles applies environment overrides, configured paths, then defaults.
// Certificate and key overrides are independent.
func ResolveFiles(cfg *config.Config) (certFile, keyFile string) {
	certFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_CERT_FILE"))
	keyFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_KEY_FILE"))
	if cfg != nil {
		if certFile == "" {
			certFile = strings.TrimSpace(cfg.System.Mgmt.TLSCertFile)
		}
		if keyFile == "" {
			keyFile = strings.TrimSpace(cfg.System.Mgmt.TLSKeyFile)
		}
	}
	if certFile == "" {
		certFile = DefaultCertFile
	}
	if keyFile == "" {
		keyFile = DefaultKeyFile
	}
	return certFile, keyFile
}
