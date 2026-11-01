// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestTLSUploadPathRefusal(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, kind string
		env                bool
	}{
		{"environment certificate", "CONTAIND_TLS_CERT_FILE", "certificate", true},
		{"environment key", "CONTAIND_TLS_KEY_FILE", "key", true},
		{"configured certificate", "system.mgmt.tlsCertFile", "certificate", false},
		{"configured key", "system.mgmt.tlsKeyFile", "key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_TLS_CERT_FILE", "")
			t.Setenv("CONTAIND_TLS_KEY_FILE", "")
			// Neither the refused file nor the other member may be touched.
			dir := t.TempDir()
			path := filepath.Join(dir, "outside.pem")
			const original = "unchanged"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.TLSCertFile = ""
			cfg.System.Mgmt.TLSKeyFile = ""
			if tc.env {
				// An in-bound config value must not mask an env override.
				cfg.System.Mgmt.TLSCertFile = "/data/unused-cert.pem"
				cfg.System.Mgmt.TLSKeyFile = "/data/unused-key.pem"
				t.Setenv(tc.source, " "+path+" ")
			} else if tc.kind == "certificate" {
				cfg.System.Mgmt.TLSCertFile = " " + path + " "
			} else {
				cfg.System.Mgmt.TLSKeyFile = " " + path + " "
			}
			router := gin.New()
			router.POST("/upload", setTLSCertHandler(&mockStore{cfg: cfg}))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
			var resp struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusConflict || !strings.Contains(resp.Error, tc.source) || !strings.Contains(resp.Error, path) || !strings.Contains(resp.Error, "managed bundle") {
				t.Fatalf("got %d %s; want actionable 409 naming %s", rec.Code, rec.Body.String(), tc.source)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != original {
				t.Fatalf("refused upload changed file: %q, %v", got, err)
			}
		})
	}
}

// recordServed records what the bound listeners serve until the test ends.
func recordServed(t *testing.T, served ServedManagement) {
	t.Helper()
	SetServedManagement(served)
	t.Cleanup(func() { SetServedManagement(ServedManagement{}) })
}

// An upload writes the files the saved settings name. It is served at once
// only when the bound HTTPS listener serves those files; after a listener
// fallback, or with HTTPS off, it waits for the next start and says so.
func TestTLSUploadSaysWhenItTakesEffect(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	for _, tc := range []struct {
		name          string
		served        func(dir string) ServedManagement
		code          int
		status, warns string
	}{
		{"served files", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "server.pem"), KeyFile: filepath.Join(dir, "tls", "server.pem")}
		}, http.StatusOK, "updated", ""},
		{"fallback files", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "server.crt"), KeyFile: filepath.Join(dir, "tls", "server.key")}
		}, http.StatusOK, "stored", "the certificate is served from the next management start"},
		{"no HTTPS listener", func(string) ServedManagement { return ServedManagement{} },
			http.StatusOK, "stored", "no HTTPS listener is bound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			served := tc.served(dir)
			recordServed(t, served)
			cfg := config.DefaultConfig()
			bundle := filepath.Join(dir, "tls", "server.pem")
			cfg.System.Mgmt.TLSCertFile = mgmttls.DefaultCertFile
			cfg.System.Mgmt.TLSKeyFile = mgmttls.DefaultKeyFile
			router := gin.New()
			router.POST("/upload", tlsCertUploadHandler(&mockStore{cfg: cfg}, dir))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
			if rec.Code != tc.code {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body)
			}
			pair, err := mgmttls.ReadPair(bundle, bundle)
			if err != nil || pair.Leaf == nil {
				t.Fatalf("bundle not published: %v", err)
			}

			var resp struct {
				Status   string   `json:"status"`
				Warnings []string `json:"warnings"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			header := rec.Header().Values("X-Containd-Warnings")
			if resp.Status != tc.status || (tc.warns == "") != (len(resp.Warnings) == 0) || len(header) != len(resp.Warnings) {
				t.Fatalf("response %+v, header %q", resp, header)
			}
			if tc.warns != "" && (!strings.Contains(resp.Warnings[0], tc.warns) || served.CertFile != "" && !strings.Contains(resp.Warnings[0], served.CertFile)) {
				t.Fatalf("warning %q does not say when the upload is served", resp.Warnings[0])
			}
			if served.CertFile != "" && served.CertFile != bundle {
				if _, err := os.Stat(served.CertFile); !os.IsNotExist(err) {
					t.Fatalf("upload touched the served fallback certificate: %v", err)
				}
			}
		})
	}
}

// sanTestCertPEM is a self-signed PEM certificate for commonName with the
// given DNS and IP subject alternative names.
func sanTestCertPEM(t *testing.T, commonName string, dnsNames []string, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// The readout names the files and certificate the bound HTTPS listener
// serves, and the listeners management has bound, next to the ones the
// next start serves, which a listener fallback or a later save makes
// differ. Each certificate's subject alternative names come from its own
// file. Paths are cleaned, so equal strings name the same file.
func TestTLSInfoShowsServedCertificate(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	t.Setenv(config.EnvManagementHTTPAddr, "")
	t.Setenv(config.EnvManagementHTTPSAddr, "")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedPEM, savedKey := generateTestCertPEM(t)
	servedPEM, servedKey := sanTestCertPEM(t, "appliance.example", []string{"appliance.example"},
		[]net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")})
	savedCert, servedCert := filepath.Join(dir, "tls", "saved.crt"), filepath.Join(dir, "tls", "server.crt")
	if err := os.WriteFile(savedCert, []byte(savedPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servedCert, servedPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls", "saved.key"), []byte(savedKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls", "server.key"), servedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPSListenAddr = ":9443"
	cfg.System.Mgmt.TLSCertFile = dir + "/tls/./saved.crt"
	cfg.System.Mgmt.TLSKeyFile = dir + "//tls/saved.key"
	read := func() tlsInfoResponse {
		t.Helper()
		router := gin.New()
		router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
		var got tlsInfoResponse
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	bindConsoleTest(t, config.ManagementListeners{
		HTTP:  config.ManagementListener{Addr: ":8080", Enabled: true},
		HTTPS: config.ManagementListener{Addr: ":8443", Enabled: true},
	})
	recordServed(t, ServedManagement{CertFile: dir + "/tls/../tls/server.crt", KeyFile: dir + "/tls/server.key/"})
	got := read()
	if got.CertFile != savedCert || got.KeyFile != filepath.Join(dir, "tls", "saved.key") ||
		got.ServedCertFile != servedCert || got.ServedKeyFile != filepath.Join(dir, "tls", "server.key") {
		t.Fatalf("fallback files = %+v", got)
	}
	if !strings.Contains(got.CertSubject, "containd.local") || got.CertNotAfter == "" ||
		!strings.Contains(got.ServedCertSubject, "appliance.example") || got.ServedCertNotAfter == "" || got.ServedCertNotAfter == got.CertNotAfter {
		t.Fatalf("certificates = %+v", got)
	}
	if !slices.Equal(got.CertDNSNames, []string{"containd.local", "lab.containd.local"}) || got.CertIPs != nil ||
		!slices.Equal(got.ServedCertDNSNames, []string{"appliance.example"}) ||
		!slices.Equal(got.ServedCertIPs, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("subject alternative names = %+v", got)
	}
	if got.BoundHTTPListenAddr != ":8080" || got.BoundHTTPSListenAddr != ":8443" || got.HTTPSListenAddr != ":9443" {
		t.Fatalf("listeners = %+v", got)
	}

	// The saved files served now name the same file however they are spelled.
	SetServedManagement(ServedManagement{CertFile: savedCert, KeyFile: filepath.Join(dir, "tls", "saved.key")})
	if got := read(); got.ServedCertFile != got.CertFile || got.ServedKeyFile != got.KeyFile || got.ServedCertSubject != got.CertSubject ||
		!slices.Equal(got.ServedCertDNSNames, got.CertDNSNames) || got.ServedCertIPs != nil {
		t.Fatalf("served saved files = %+v", got)
	}

	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: ":8080", Enabled: true}, HTTPS: config.ManagementListener{Addr: ":8443"}})
	SetServedManagement(ServedManagement{})
	if got := read(); got.ServedCertFile != "" || got.ServedKeyFile != "" || got.ServedCertSubject != "" || got.ServedCertNotAfter != "" ||
		got.ServedCertDNSNames != nil || got.ServedCertIPs != nil || got.BoundHTTPSListenAddr != "" || got.BoundHTTPListenAddr != ":8080" {
		t.Fatalf("readout without HTTPS = %+v", got)
	}
}

// The readout says whether the next start binds another listener than the
// bound one. A bound listener is recorded at its socket's address, so a
// wildcard listen is recorded as [::] (0.0.0.0 without IPv6), which every
// wildcard spelling of the same port binds again. A listener bound at a
// specific address in place of a wildcard, as a reserved endpoint or
// loopback fallback is, still differs.
func TestTLSInfoComparesBoundAndNextListeners(t *testing.T) {
	t.Setenv(config.EnvManagementHTTPAddr, "")
	t.Setenv(config.EnvManagementHTTPSAddr, "")
	listen := func(addr string) (string, string) {
		t.Helper()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return ln.Addr().String(), port
	}
	wildcard, wildPort := listen(":0")
	if host, _, _ := net.SplitHostPort(wildcard); host != "::" && host != "0.0.0.0" {
		t.Fatalf("wildcard listener recorded as %s", wildcard)
	}
	specific, specificPort := listen("127.0.0.1:0")
	on := func(addr string) config.ManagementListener {
		return config.ManagementListener{Addr: addr, Enabled: true}
	}
	for _, tc := range []struct {
		name    string
		bound   config.ManagementListener
		next    string
		enabled bool
		changes bool
	}{
		{"default wildcard", on(wildcard), ":" + wildPort, true, false},
		{"IPv4 wildcard", on(wildcard), "0.0.0.0:" + wildPort, true, false},
		{"IPv6 wildcard", on(wildcard), "[::]:" + wildPort, true, false},
		{"zero-padded port", on(wildcard), ":0" + wildPort, true, false},
		{"other port", on(wildcard), ":" + specificPort, true, true},
		{"specific address", on(specific), "127.0.0.1:" + specificPort, true, false},
		{"IPv4-mapped address", on(specific), "[::ffff:127.0.0.1]:" + specificPort, true, false},
		{"specific address in place of the wildcard", on(specific), ":" + specificPort, true, true},
		{"wildcard in place of a specific address", on(wildcard), "127.0.0.1:" + wildPort, true, true},
		{"host name", on(specific), "localhost:" + specificPort, true, true},
		{"disabled at the next start", on(wildcard), ":" + wildPort, false, true},
		{"not bound", config.ManagementListener{}, ":" + wildPort, true, true},
		{"neither", config.ManagementListener{}, ":" + wildPort, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bindConsoleTest(t, config.ManagementListeners{HTTP: tc.bound, HTTPS: tc.bound})
			enabled := tc.enabled
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.EnableHTTP = tc.next, &enabled
			cfg.System.Mgmt.HTTPSListenAddr, cfg.System.Mgmt.EnableHTTPS = tc.next, &enabled
			router := gin.New()
			router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("status %d, %v: %s", rec.Code, err, rec.Body)
			}
			if got["httpListenChanges"] != tc.changes || got["httpsListenChanges"] != tc.changes {
				t.Fatalf("bound %+v, next %q enabled=%v: %s", tc.bound, tc.next, tc.enabled, rec.Body)
			}
		})
	}
}
