// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"crypto/x509"
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
	ServedCertFile     string   `json:"servedCertFile,omitempty"`
	ServedKeyFile      string   `json:"servedKeyFile,omitempty"`
	ServedCertSubject  string   `json:"servedCertSubject,omitempty"`
	ServedCertNotAfter string   `json:"servedCertNotAfter,omitempty"`
	ServedCertDNSNames []string `json:"servedCertDnsNames,omitempty"`
	ServedCertIPs      []string `json:"servedCertIps,omitempty"`
	ReloadError        string   `json:"reloadError,omitempty"`
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
		certFile, keyFile := mgmttls.IdentityFiles(cfg)
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

		var leaf *x509.Certificate
		if served.TLS != nil {
			var err error
			leaf, err = served.TLS.PublicLeaf()
			if err != nil {
				resp.ReloadError = err.Error()
			}
		} else if served.CertFile != "" {
			if pair, err := mgmttls.ReadPair(resp.ServedCertFile, resp.ServedKeyFile); err == nil {
				leaf = pair.Leaf
			}
		}
		if leaf != nil {
			resp.ServedCertSubject = leaf.Subject.String()
			resp.ServedCertNotAfter = formatNotAfter(leaf)
			resp.ServedCertDNSNames, resp.ServedCertIPs = certSANs(leaf)
		}

		configuredLeaf := leaf
		if resp.CertFile != resp.ServedCertFile || resp.KeyFile != resp.ServedKeyFile {
			configuredLeaf = nil
			if pair, err := mgmttls.ReadPair(resp.CertFile, resp.KeyFile); err == nil {
				configuredLeaf = pair.Leaf
			}
		}
		if cert := configuredLeaf; cert != nil {
			resp.CertSubject = cert.Subject.String()
			resp.CertIssuer = cert.Issuer.String()
			resp.CertNotAfter = formatNotAfter(cert)
			resp.CertDNSNames, resp.CertIPs = certSANs(cert)
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

func formatNotAfter(cert *x509.Certificate) string {
	return cert.NotAfter.UTC().Format(time.RFC3339Nano)
}

// certSANs are a certificate's DNS name and IP address subject alternative
// names; nil when it has none of that kind.
func certSANs(cert *x509.Certificate) (dnsNames, ips []string) {
	dnsNames = append(dnsNames, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		if ip != nil {
			ips = append(ips, ip.String())
		}
	}
	return dnsNames, ips
}

type setTLSCertRequest struct {
	CertPEM string `json:"certPEM"`
	KeyPEM  string `json:"keyPEM"`
}

func setTLSCertHandler(store config.Store) gin.HandlerFunc {
	return tlsCertUploadHandler(store, "/data")
}

// tlsCertUploadHandler publishes only the managed identity. dataDir is the
// appliance data root; external paths are read-only even beneath this directory.
func tlsCertUploadHandler(store config.Store, dataDir string) gin.HandlerFunc {
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
		pair, err := mgmttls.ParseBundle([]byte(req.CertPEM + "\n" + req.KeyPEM + "\n"))
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
		if !mgmttls.Managed(cfg) {
			apiError(c, http.StatusConflict, fmt.Sprintf("external TLS paths are read-only: certificate %q (source: %s), key %q (source: %s); unset CONTAIND_TLS_CERT_FILE/CONTAIND_TLS_KEY_FILE and clear system.mgmt.tlsCertFile/tlsKeyFile or restore their default paths to use the managed bundle", cert.Path, cert.Source, key.Path, key.Source))
			return
		}
		certFile := filepath.Join(dataDir, "tls", "server.pem")
		served := currentServedManagement()
		liveCert := sameFilePath(certFile, served.CertFile) && sameFilePath(certFile, served.KeyFile)
		if err := mgmttls.Publish(certFile, []byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
			apiErrorDetail(c, http.StatusInternalServerError, "TLS bundle publication failed", err.Error())
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
