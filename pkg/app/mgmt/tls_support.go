// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func resolveTLSFiles(cfg *config.Config) (certFile, keyFile string) {
	certFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_CERT_FILE"))
	keyFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_KEY_FILE"))
	if certFile == "" && cfg != nil {
		certFile = cfg.System.Mgmt.TLSCertFile
	}
	if keyFile == "" && cfg != nil {
		keyFile = cfg.System.Mgmt.TLSKeyFile
	}
	if certFile == "" {
		certFile = "/data/tls/server.crt"
	}
	if keyFile == "" {
		keyFile = "/data/tls/server.key"
	}
	return certFile, keyFile
}

func hstsHandler(enabled bool, maxAgeSeconds int, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 31536000
	}
	value := "max-age=" + strconv.Itoa(maxAgeSeconds)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", value)
		}
		next.ServeHTTP(w, r)
	})
}

func corsHandler(next http.Handler, allowedOrigins []string) http.Handler {
	if len(allowedOrigins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false
		for _, o := range allowedOrigins {
			o = strings.TrimSpace(o)
			if o != "" && o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS, PUT")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}

		if r.Method == http.MethodOptions {
			if allowed {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func frameOptionsHandler(next http.Handler, allowedOrigins []string) http.Handler {
	if len(allowedOrigins) == 0 {
		return next
	}
	cspValue := "'self'"
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			cspValue += " " + o
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+cspValue)
		next.ServeHTTP(w, r)
	})
}

func getAllowedOrigins() []string {
	val := os.Getenv("CONTAIND_ALLOWED_ORIGINS")
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var origins []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "*" {
			continue
		}
		origins = append(origins, p)
	}
	return origins
}

func redirectToHTTPSHandler(httpsAddr string, next http.Handler) http.Handler {
	httpsPort := portOf(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if host == "" {
			host = "localhost"
		}
		if strings.Contains(host, "@") {
			next.ServeHTTP(w, r)
			return
		}
		h, _, err := net.SplitHostPort(host)
		if err == nil && h != "" {
			host = h
		}
		if httpsPort != "" {
			host = net.JoinHostPort(host, httpsPort)
		}
		target := "https://" + host + r.URL.RequestURI() // nosemgrep: go.lang.security.injection.open-redirect.open-redirect -- appliance-local HTTP->HTTPS upgrade redirect preserving the requested host.
		http.Redirect(w, r, target, http.StatusFound)
	})
}

type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.Mutex
	cert    *tls.Certificate
	certM   time.Time
	keyM    time.Time
	lastErr error
}

func newCertReloader(certFile, keyFile string) *certReloader {
	return &certReloader{certFile: certFile, keyFile: keyFile}
}

func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cm := modTime(r.certFile)
	km := modTime(r.keyFile)
	if r.cert == nil || !cm.Equal(r.certM) || !km.Equal(r.keyM) {
		c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if err != nil {
			r.lastErr = err
			return nil, err
		}
		r.cert = &c
		r.certM = cm
		r.keyM = km
		r.lastErr = nil
	}
	return r.cert, nil
}

func modTime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

func ensureSelfSignedTLSFiles(certFile, keyFile string, extraIPs []string) (string, string, error) {
	if certFile == "" || keyFile == "" {
		return "", "", errors.New("tls cert/key file required")
	}
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return certFile, keyFile, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
		return "", "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "containd",
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}
	for _, s := range extraIPs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certOut, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, keyOut, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}
