// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type tlsInfoResponse struct {
	HTTPListenAddr  string `json:"httpListenAddr,omitempty"`
	HTTPSListenAddr string `json:"httpsListenAddr,omitempty"`
	HTTPEnabled     bool   `json:"httpEnabled"`
	HTTPSEnabled    bool   `json:"httpsEnabled"`

	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`

	CertSubject  string   `json:"certSubject,omitempty"`
	CertIssuer   string   `json:"certIssuer,omitempty"`
	CertNotAfter string   `json:"certNotAfter,omitempty"`
	CertDNSNames []string `json:"certDnsNames,omitempty"`
	CertIPs      []string `json:"certIps,omitempty"`
}

func getTLSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "config store unavailable")
			return
		}
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}

		// The listeners management binds when it starts with this
		// configuration, under this process's environment.
		listeners := config.EffectiveManagementListeners(cfg)
		certFile, keyFile := mgmttls.ResolveFiles(cfg)

		resp := tlsInfoResponse{
			HTTPListenAddr:  listeners.HTTP.Addr,
			HTTPSListenAddr: listeners.HTTPS.Addr,
			HTTPEnabled:     listeners.HTTP.Enabled,
			HTTPSEnabled:    listeners.HTTPS.Enabled,
			CertFile:        certFile,
			KeyFile:         keyFile,
		}

		if certDER, err := readFirstCertDER(certFile); err == nil && len(certDER) > 0 {
			if cert, err := x509.ParseCertificate(certDER); err == nil && cert != nil {
				resp.CertSubject = cert.Subject.String()
				resp.CertIssuer = cert.Issuer.String()
				resp.CertNotAfter = cert.NotAfter.UTC().Format(time.RFC3339Nano)
				resp.CertDNSNames = append([]string(nil), cert.DNSNames...)
				for _, ip := range cert.IPAddresses {
					if ip != nil {
						resp.CertIPs = append(resp.CertIPs, ip.String())
					}
				}
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}

type setTLSCertRequest struct {
	CertPEM string `json:"certPEM"`
	KeyPEM  string `json:"keyPEM"`
}

func setTLSCertHandler(store config.Store) gin.HandlerFunc {
	return tlsCertUploadHandler(store, "/data")
}

// tlsCertUploadHandler writes the management certificate and key, which must
// both be under dataDir.
func tlsCertUploadHandler(store config.Store, dataDir string) gin.HandlerFunc {
	under := filepath.Clean(dataDir) + string(os.PathSeparator)
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "config store unavailable")
			return
		}
		var req setTLSCertRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		req.CertPEM = strings.TrimSpace(req.CertPEM)
		req.KeyPEM = strings.TrimSpace(req.KeyPEM)
		if req.CertPEM == "" || req.KeyPEM == "" {
			apiError(c, http.StatusBadRequest, "certPEM and keyPEM required")
			return
		}

		// Validate the pair before writing.
		pair, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
		if err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid cert/key pair", err.Error())
			return
		}

		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		cert, key := mgmttls.ResolveFilesWithSources(cfg)
		certFile, keyFile := cert.Path, key.Path

		if !strings.HasPrefix(filepath.Clean(certFile)+string(os.PathSeparator), under) {
			apiError(c, http.StatusConflict, fmt.Sprintf("TLS certificate path %q (source: %s) must be under %s", certFile, cert.Source, dataDir))
			return
		}
		if !strings.HasPrefix(filepath.Clean(keyFile)+string(os.PathSeparator), under) {
			apiError(c, http.StatusConflict, fmt.Sprintf("TLS key path %q (source: %s) must be under %s", keyFile, key.Source, dataDir))
			return
		}

		if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
			internalError(c, err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
			internalError(c, err)
			return
		}

		// Write key first with restrictive perms, then cert.
		if err := os.WriteFile(keyFile, []byte(req.KeyPEM+"\n"), 0o600); err != nil {
			internalError(c, err)
			return
		}
		if err := os.WriteFile(certFile, []byte(req.CertPEM+"\n"), 0o644); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "system.tls.cert.set", Target: certFile, Detail: certAuditDetail(pair.Leaf)})
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

type setTrustedCARequest struct {
	PEM   string `json:"pem"`
	Clear bool   `json:"clear"`
}

func setTrustedCAHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return trustedCAUploadHandler(store, engine, "/data")
}

// trustedCABundlePath is management's storage path for the additional CA bundle.
func trustedCABundlePath(cfg *config.Config) string {
	return firstNonEmpty(cfg.System.Mgmt.TrustedCAFile, trust.DefaultBundlePath)
}

// pushTrustedCA sends the stored bundle's content and revision to the engine.
// The engine never reads management's file.
func pushTrustedCA(ctx context.Context, cfg *config.Config, engine EngineClient) error {
	if engine == nil {
		return errors.New("engine unavailable")
	}
	b, err := trust.LoadBundle(trustedCABundlePath(cfg))
	if err != nil {
		return err
	}
	return engine.ConfigureTrust(ctx, b)
}

// trustedCAUploadHandler keeps the storage boundary explicit and testable.
// A stored bundle is pushed to the engine at once. When the engine cannot
// apply it, the upload still succeeds with status "stored" and a warning,
// and the next config apply retries it.
func trustedCAUploadHandler(store config.Store, engine EngineClient, dataDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			apiError(c, http.StatusServiceUnavailable, "config store unavailable")
			return
		}
		var req setTrustedCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		pemText := strings.TrimSpace(req.PEM)
		if req.Clear && pemText != "" {
			apiError(c, http.StatusBadRequest, "clear and pem are mutually exclusive")
			return
		}
		if !req.Clear && pemText == "" {
			apiErrorDetail(c, http.StatusBadRequest, "invalid PEM CA bundle", "CA bundle is empty; use clear to remove additional trust")
			return
		}
		bundle, err := trust.NewBundle([]byte(pemText))
		if err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid PEM CA bundle", err.Error())
			return
		}

		// Serialize with config applies so they push the same bundle.
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		path := trustedCABundlePath(cfg)
		if !strings.HasPrefix(filepath.Clean(path)+string(os.PathSeparator), filepath.Clean(dataDir)+string(os.PathSeparator)) {
			apiError(c, http.StatusBadRequest, "trustedCAFile must be under /data")
			return
		}
		if err := trust.WriteBundle(path, []byte(bundle.PEM)); err != nil {
			internalError(c, err)
			return
		}
		status, warnings := "updated", []string{}
		record := audit.Record{Action: "system.tls.trusted_ca.set", Target: bundle.Revision}
		if err := pushTrustedCA(c.Request.Context(), cfg, engine); err != nil {
			status = "stored"
			warnings = append(warnings, fmt.Sprintf("trust: %v", err))
			record.Result, record.Detail = "warning", warnings[0]
		}
		auditLog(c, record)
		setWarningHeader(c, warnings)
		c.JSON(http.StatusOK, gin.H{"status": status, "revision": bundle.Revision, "warnings": warnings})
	}
}

// certAuditDetail identifies a replaced management certificate in the audit log.
func certAuditDetail(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return fmt.Sprintf("subject=%s notAfter=%s", cert.Subject, cert.NotAfter.UTC().Format(time.RFC3339))
}

func readFirstCertDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" && len(block.Bytes) > 0 {
			return block.Bytes, nil
		}
	}
	return nil, errors.New("no certificate found")
}
