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
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type tlsInfoResponse struct {
	// HTTPListenAddr, HTTPSListenAddr, HTTPEnabled and HTTPSEnabled are the
	// listeners management binds when it next starts with this
	// configuration.
	HTTPListenAddr  string `json:"httpListenAddr,omitempty"`
	HTTPSListenAddr string `json:"httpsListenAddr,omitempty"`
	HTTPEnabled     bool   `json:"httpEnabled"`
	HTTPSEnabled    bool   `json:"httpsEnabled"`
	// BoundHTTPListenAddr and BoundHTTPSListenAddr are the addresses of the
	// listeners management has bound now; empty when that listener is not
	// bound.
	BoundHTTPListenAddr  string `json:"boundHttpListenAddr,omitempty"`
	BoundHTTPSListenAddr string `json:"boundHttpsListenAddr,omitempty"`
	// HTTPListenChanges and HTTPSListenChanges report that the next start
	// binds another listener than the bound one (see listenerChanges).
	HTTPListenChanges  bool `json:"httpListenChanges"`
	HTTPSListenChanges bool `json:"httpsListenChanges"`

	// CertFile and KeyFile are the files the HTTPS listener serves when
	// management next starts with this configuration, and the Cert fields
	// describe that certificate.
	CertFile     string   `json:"certFile,omitempty"`
	KeyFile      string   `json:"keyFile,omitempty"`
	CertSubject  string   `json:"certSubject,omitempty"`
	CertIssuer   string   `json:"certIssuer,omitempty"`
	CertNotAfter string   `json:"certNotAfter,omitempty"`
	CertDNSNames []string `json:"certDnsNames,omitempty"`
	CertIPs      []string `json:"certIps,omitempty"`

	// ServedCertFile and ServedKeyFile are the files the bound HTTPS
	// listener serves now, and the ServedCert fields describe that
	// certificate; all empty when no HTTPS listener is bound. All file
	// paths are cleaned, so equal strings name the same file.
	ServedCertFile     string `json:"servedCertFile,omitempty"`
	ServedKeyFile      string `json:"servedKeyFile,omitempty"`
	ServedCertSubject  string `json:"servedCertSubject,omitempty"`
	ServedCertNotAfter string `json:"servedCertNotAfter,omitempty"`
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
		bound := config.BoundManagementListeners()
		certFile, keyFile := mgmttls.ResolveFiles(cfg)
		served := currentServedManagement()

		resp := tlsInfoResponse{
			HTTPListenAddr:       listeners.HTTP.Addr,
			HTTPSListenAddr:      listeners.HTTPS.Addr,
			HTTPEnabled:          listeners.HTTP.Enabled,
			HTTPSEnabled:         listeners.HTTPS.Enabled,
			BoundHTTPListenAddr:  boundAddr(bound.HTTP),
			BoundHTTPSListenAddr: boundAddr(bound.HTTPS),
			HTTPListenChanges:    listenerChanges(bound.HTTP, listeners.HTTP),
			HTTPSListenChanges:   listenerChanges(bound.HTTPS, listeners.HTTPS),
			CertFile:             cleanFilePath(certFile),
			KeyFile:              cleanFilePath(keyFile),
			ServedCertFile:       cleanFilePath(served.CertFile),
			ServedKeyFile:        cleanFilePath(served.KeyFile),
		}

		if cert := readCertificate(resp.CertFile); cert != nil {
			resp.CertSubject = cert.Subject.String()
			resp.CertIssuer = cert.Issuer.String()
			resp.CertNotAfter = formatNotAfter(cert)
			resp.CertDNSNames = append([]string(nil), cert.DNSNames...)
			for _, ip := range cert.IPAddresses {
				if ip != nil {
					resp.CertIPs = append(resp.CertIPs, ip.String())
				}
			}
		}
		// The bound listener reloads its files at the next handshake after
		// they change, so the file is what it serves.
		if cert := readCertificate(resp.ServedCertFile); cert != nil {
			resp.ServedCertSubject = cert.Subject.String()
			resp.ServedCertNotAfter = formatNotAfter(cert)
		}

		c.JSON(http.StatusOK, resp)
	}
}

// boundAddr is the address of a bound listener; empty when it is not bound.
func boundAddr(l config.ManagementListener) string {
	if !l.Enabled {
		return ""
	}
	return l.Addr
}

// listenerChanges reports that next binds another listener than bound: one
// of them is served and the other not, or they differ in host or port. The
// bound record names its socket's address, so every wildcard spelling of
// next ("", 0.0.0.0, ::) is the wildcard socket a TCP listen binds, which
// the record spells [::] (0.0.0.0 without IPv6). A host name differs from
// every bound address: the next start resolves it afresh.
func listenerChanges(bound, next config.ManagementListener) bool {
	if !bound.Enabled || !next.Enabled {
		return bound.Enabled != next.Enabled
	}
	b, boundOK := listenEndpoint(bound.Addr)
	n, nextOK := listenEndpoint(next.Addr)
	return !boundOK || !nextOK || b != n
}

// listenEndpoint is the IP and port a TCP listen on addr binds, with every
// wildcard host as the unspecified IPv6 address; false when addr is not an
// IP or empty host with a numeric port.
func listenEndpoint(addr string) (netip.AddrPort, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ip := netip.IPv6Unspecified()
	if host != "" {
		parsed, err := netip.ParseAddr(host)
		if err != nil {
			return netip.AddrPort{}, false
		}
		if parsed = parsed.Unmap(); !parsed.IsUnspecified() {
			ip = parsed
		}
	}
	return netip.AddrPortFrom(ip, uint16(p)), true
}

// cleanFilePath cleans a file path as sameFilePath compares it; empty stays
// empty.
func cleanFilePath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

// readCertificate is the first certificate of a PEM file; nil when the file
// is missing or holds none.
func readCertificate(path string) *x509.Certificate {
	der, err := readFirstCertDER(path)
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}

func formatNotAfter(cert *x509.Certificate) string {
	return cert.NotAfter.UTC().Format(time.RFC3339Nano)
}

type setTLSCertRequest struct {
	CertPEM string `json:"certPEM"`
	KeyPEM  string `json:"keyPEM"`
}

func setTLSCertHandler(store config.Store) gin.HandlerFunc {
	return tlsCertUploadHandler(store, "/data")
}

// tlsCertUploadHandler writes the management certificate and key files that
// management serves when it next starts with the saved configuration, which
// must both be under dataDir. The bound HTTPS listener reloads the files it
// serves at its next TLS handshake after they change, so when they are those
// files the upload is served at once (status "updated"). Otherwise it is
// served from the next start (status "stored", with a warning that says so).
// An upload that would replace only one of the served files is refused: the
// listener would pair it with the other one.
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

		served := currentServedManagement()
		liveCert, liveKey := served.CertFile != "" && sameFilePath(certFile, served.CertFile), served.KeyFile != "" && sameFilePath(keyFile, served.KeyFile)
		if liveCert != liveKey {
			apiError(c, http.StatusConflict, fmt.Sprintf("the HTTPS listener serves certificate %q with key %q; writing certificate %q (source: %s) and key %q (source: %s) would pair a new file with a served one", served.CertFile, served.KeyFile, certFile, cert.Source, keyFile, key.Source))
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
		status, warnings := "updated", []string{}
		switch {
		case served.CertFile == "":
			status = "stored"
			warnings = append(warnings, "no HTTPS listener is bound; the certificate is served when management next starts with HTTPS enabled")
		case !liveCert:
			status = "stored"
			warnings = append(warnings, fmt.Sprintf("the HTTPS listener serves %q; the certificate is served from the next management start", served.CertFile))
		}
		auditLog(c, audit.Record{Action: "system.tls.cert.set", Target: certFile, Detail: certAuditDetail(pair.Leaf)})
		setWarningHeader(c, warnings)
		c.JSON(http.StatusOK, gin.H{"status": status, "warnings": warnings})
	}
}

func sameFilePath(a, b string) bool {
	return cleanFilePath(a) == cleanFilePath(b)
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
	return common.FirstNonEmpty(cfg.System.Mgmt.TrustedCAFile, trust.DefaultBundlePath)
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
