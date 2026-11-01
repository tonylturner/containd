// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func resolveTLSFiles(cfg *config.Config) (certFile, keyFile string) {
	return mgmttls.ResolveFiles(cfg)
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

// certReloader shares its immutable identity with status and loopback pins.
type certReloader = mgmttls.Loader

func newCertReloader(certFile, keyFile string) *certReloader {
	return mgmttls.NewLoader(certFile, keyFile)
}

func ensureTLSIdentity(cfg *config.Config, extraIPs []string, logf func(string, ...any)) (string, string, error) {
	cert, key := mgmttls.IdentityFiles(cfg)
	if mgmttls.Managed(cfg) {
		err := mgmttls.EnsureManaged(cert, mgmttls.DefaultCertFile, mgmttls.DefaultKeyFile,
			func() ([]byte, []byte, error) { return selfSignedTLS(extraIPs) }, logf)
		return cert, key, err
	}
	_, err := mgmttls.ReadPair(cert, key)
	return cert, key, err
}

func selfSignedTLS(extraIPs []string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certOut, keyOut, nil
}
