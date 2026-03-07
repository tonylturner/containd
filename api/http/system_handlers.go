// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/gin-gonic/gin"
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
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config store unavailable"})
			return
		}
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}

		httpAddr := firstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr, ":8080")
		httpsAddr := firstNonEmpty(cfg.System.Mgmt.HTTPSListenAddr, ":8443")
		httpEnabled := boolDefault(cfg.System.Mgmt.EnableHTTP, true)
		httpsEnabled := boolDefault(cfg.System.Mgmt.EnableHTTPS, true)
		certFile := firstNonEmpty(cfg.System.Mgmt.TLSCertFile, "/data/tls/server.crt")
		keyFile := firstNonEmpty(cfg.System.Mgmt.TLSKeyFile, "/data/tls/server.key")

		resp := tlsInfoResponse{
			HTTPListenAddr:  httpAddr,
			HTTPSListenAddr: httpsAddr,
			HTTPEnabled:     httpEnabled,
			HTTPSEnabled:    httpsEnabled,
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
	return func(c *gin.Context) {
		if store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config store unavailable"})
			return
		}
		var req setTLSCertRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		req.CertPEM = strings.TrimSpace(req.CertPEM)
		req.KeyPEM = strings.TrimSpace(req.KeyPEM)
		if req.CertPEM == "" || req.KeyPEM == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "certPEM and keyPEM required"})
			return
		}

		// Validate the pair before writing.
		if _, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cert/key pair", "detail": err.Error()})
			return
		}

		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		certFile := firstNonEmpty(cfg.System.Mgmt.TLSCertFile, "/data/tls/server.crt")
		keyFile := firstNonEmpty(cfg.System.Mgmt.TLSKeyFile, "/data/tls/server.key")

		if !strings.HasPrefix(filepath.Clean(certFile)+string(os.PathSeparator), string(os.PathSeparator)+"data"+string(os.PathSeparator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tlsCertFile must be under /data"})
			return
		}
		if !strings.HasPrefix(filepath.Clean(keyFile)+string(os.PathSeparator), string(os.PathSeparator)+"data"+string(os.PathSeparator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tlsKeyFile must be under /data"})
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

		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

type setTrustedCARequest struct {
	PEM string `json:"pem"`
}

func setTrustedCAHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config store unavailable"})
			return
		}
		var req setTrustedCARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		pemText := strings.TrimSpace(req.PEM)
		if pemText == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "pem required"})
			return
		}
		if _, err := readAnyPEM(pemText); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid PEM", "detail": err.Error()})
			return
		}

		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		path := firstNonEmpty(cfg.System.Mgmt.TrustedCAFile, "/data/tls/trusted_ca.pem")
		if !strings.HasPrefix(filepath.Clean(path)+string(os.PathSeparator), string(os.PathSeparator)+"data"+string(os.PathSeparator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "trustedCAFile must be under /data"})
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			internalError(c, err)
			return
		}
		if err := os.WriteFile(path, []byte(pemText+"\n"), 0o644); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

func readAnyPEM(s string) ([]byte, error) {
	var found bool
	b := []byte(s)
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		found = true
	}
	if !found {
		return nil, errors.New("no PEM blocks found")
	}
	return []byte(s), nil
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
