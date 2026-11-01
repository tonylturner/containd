// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// isolateRuntimeRecord points the record at a temporary store directory and
// restores the process's bound-management state afterwards.
func isolateRuntimeRecord(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CONTAIND_CONFIG_DB", filepath.Join(dir, "config.db"))
	bound := config.BoundManagementListeners()
	t.Cleanup(func() {
		config.SetBoundManagementListeners(bound)
		httpapi.SetServedManagement(httpapi.ServedManagement{})
	})
	return dir
}

func TestRuntimeRecordRoundTripAndPermissions(t *testing.T) {
	dir := isolateRuntimeRecord(t)
	path := RuntimeRecordPath()
	if want := filepath.Join(dir, "run", "management.json"); path != want {
		t.Fatalf("path %s, want %s", path, want)
	}
	// An existing directory with a wider mode is narrowed.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := RuntimeRecord{
		Listeners: config.ManagementListeners{
			HTTP:  config.ManagementListener{Addr: ":8080", Enabled: true},
			HTTPS: config.ManagementListener{Addr: ":8443", Enabled: true},
			SSH:   config.ManagementListener{Addr: "[::]:2222", Enabled: true},
		},
		Served: httpapi.ServedManagement{CertFile: "/data/tls/server.crt", KeyFile: "/data/tls/server.key", HTTPRedirects: true, HTTPLoopback: true},
	}
	for i := 0; i < 2; i++ { // the second write replaces the first
		if err := writeRuntimeRecord(path, rec); err != nil {
			t.Fatal(err)
		}
	}
	got, err := readRuntimeRecord(path)
	if err != nil || !reflect.DeepEqual(got, rec) {
		t.Fatalf("read %+v, %v; want %+v", got, err, rec)
	}
	for p, want := range map[string]os.FileMode{filepath.Dir(path): 0o700, path: 0o600} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v; want %v", p, info.Mode().Perm(), err, want)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("run directory holds %v, %v; want only the record", entries, err)
	}
}

func TestRuntimeRecordPublisherWritesBoundAndRemoves(t *testing.T) {
	isolateRuntimeRecord(t)
	bound := config.ManagementListeners{HTTP: config.ManagementListener{Addr: ":8080", Enabled: true}, SSH: config.ManagementListener{Addr: ":2222", Enabled: true}}
	config.SetBoundManagementListeners(bound)
	p := &runtimeRecordPublisher{path: RuntimeRecordPath(), served: httpapi.ServedManagement{HTTPLoopback: true}}
	if err := p.publish(); err != nil {
		t.Fatal(err)
	}
	got, err := readRuntimeRecord(p.path)
	if err != nil || got.Listeners != bound || !got.Served.HTTPLoopback {
		t.Fatalf("record %+v, %v", got, err)
	}
	for i := 0; i < 2; i++ {
		if err := p.remove(); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
	}
	if _, err := os.Stat(p.path); !os.IsNotExist(err) {
		t.Fatalf("record remains: %v", err)
	}
}

func TestRuntimeRecordResolvesRelativeServedCertificateFromManagementDirectory(t *testing.T) {
	dir := isolateRuntimeRecord(t)
	managementDir := filepath.Join(dir, "management")
	cliDir := filepath.Join(dir, "cli")
	for _, path := range []string{managementDir, cliDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := os.WriteFile(filepath.Join(managementDir, "served.crt"), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.Chdir(managementDir); err != nil {
		t.Fatal(err)
	}
	wantCert, err := filepath.Abs("served.crt")
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := filepath.Abs("served.key")
	if err != nil {
		t.Fatal(err)
	}
	config.SetBoundManagementListeners(config.ManagementListeners{HTTPS: listener(srv)})
	p := &runtimeRecordPublisher{
		path: RuntimeRecordPath(),
		served: httpapi.ServedManagement{
			CertFile: "served.crt",
			KeyFile:  "served.key",
		},
	}
	if err := p.publish(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cliDir); err != nil {
		t.Fatal(err)
	}

	rec, err := readRuntimeRecord(p.path)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Served.CertFile != wantCert || rec.Served.KeyFile != wantKey {
		t.Fatalf("published served paths = %q, %q; want %q, %q", rec.Served.CertFile, rec.Served.KeyFile, wantCert, wantKey)
	}
	baseURL, client, err := LocalManagementAPI()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(baseURL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d; want 200", resp.StatusCode)
	}
}

func TestLocalManagementAPIWithoutRecord(t *testing.T) {
	dir := isolateRuntimeRecord(t)
	for _, setup := range []func(){
		func() {}, // missing
		func() { // unreadable
			if err := os.MkdirAll(filepath.Join(dir, "run"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(RuntimeRecordPath(), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		setup()
		if _, _, err := LocalManagementAPI(); err == nil || !strings.Contains(err.Error(), "management is not running") {
			t.Fatalf("error %v", err)
		}
	}
}

// writeRecordFor writes rec as management would.
func writeRecordFor(t *testing.T, rec RuntimeRecord) {
	t.Helper()
	if err := writeRuntimeRecord(RuntimeRecordPath(), rec); err != nil {
		t.Fatal(err)
	}
}

func listener(srv *httptest.Server) config.ManagementListener {
	return config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}
}

func get(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	resp, err := client.Get(url)
	if err == nil {
		_ = resp.Body.Close()
	}
	return resp, err
}

// The CLI calls the bound HTTP listener the record names, and follows no
// redirect.
func TestLocalManagementAPISelectsHTTPFromRecord(t *testing.T) {
	isolateRuntimeRecord(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	writeRecordFor(t, RuntimeRecord{Listeners: config.ManagementListeners{HTTP: listener(srv), HTTPS: config.ManagementListener{Addr: "127.0.0.1:1", Enabled: true}}})
	baseURL, client, err := LocalManagementAPI()
	if err != nil || baseURL != srv.URL {
		t.Fatalf("selected %q, %v; want %s", baseURL, err, srv.URL)
	}
	if resp, err := get(t, client, baseURL+"/api/v1/health"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %v, %v", resp, err)
	}
	if _, err := get(t, client, baseURL+"/elsewhere"); err == nil {
		t.Fatal("redirect followed")
	}
}

// An HTTPS-only record, or one whose HTTP listener redirects, selects the
// HTTPS listener pinned to the certificate it serves.
func TestLocalManagementAPIPinsHTTPSFromRecord(t *testing.T) {
	dir := isolateRuntimeRecord(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	served := filepath.Join(dir, "served.crt")
	wrong := filepath.Join(dir, "other.crt")
	for path, der := range map[string][]byte{served: srv.Certificate().Raw, wrong: otherCertificate(t)} {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	httpsURL := "https://" + srv.Listener.Addr().String()
	for name, rec := range map[string]RuntimeRecord{
		"https only": {
			Listeners: config.ManagementListeners{HTTPS: listener(srv)},
			Served:    httpapi.ServedManagement{CertFile: served},
		},
		"http redirects": {
			Listeners: config.ManagementListeners{HTTP: config.ManagementListener{Addr: "127.0.0.1:1", Enabled: true}, HTTPS: listener(srv)},
			Served:    httpapi.ServedManagement{CertFile: served, HTTPRedirects: true},
		},
	} {
		writeRecordFor(t, rec)
		baseURL, client, err := LocalManagementAPI()
		if err != nil || baseURL != httpsURL {
			t.Fatalf("%s: selected %q, %v; want %s", name, baseURL, err, httpsURL)
		}
		if resp, err := get(t, client, baseURL+"/api/v1/health"); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: health: %v, %v", name, resp, err)
		}
	}
	// A certificate other than the served one is refused.
	writeRecordFor(t, RuntimeRecord{Listeners: config.ManagementListeners{HTTPS: listener(srv)}, Served: httpapi.ServedManagement{CertFile: wrong}})
	baseURL, client, err := LocalManagementAPI()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, client, baseURL+"/api/v1/health"); err == nil {
		t.Fatal("a listener without the served certificate was trusted")
	}
}

// otherCertificate is a self-signed certificate for the httptest server's
// name that the server does not serve.
func otherCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "other"},
		DNSNames:     []string{"example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestRuntimeRecordTracksPublicBundleSnapshot(t *testing.T) {
	dir := isolateRuntimeRecord(t)
	bundle := filepath.Join(dir, "server.pem")
	cert, key, err := selfSignedTLS(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgmttls.Publish(bundle, cert, key); err != nil {
		t.Fatal(err)
	}
	loader := mgmttls.NewLoader(bundle, bundle)
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: loader.GetCertificate}
	srv.StartTLS()
	defer srv.Close()
	config.SetBoundManagementListeners(config.ManagementListeners{HTTPS: listener(srv)})
	p := &runtimeRecordPublisher{path: RuntimeRecordPath(), served: httpapi.ServedManagement{CertFile: bundle, KeyFile: bundle, TLS: loader}}
	if err := p.publish(); err != nil {
		t.Fatal(err)
	}
	loader.OnChange(func() {
		if err := p.publish(); err != nil {
			t.Error(err)
		}
	})
	defer loader.OnChange(nil)
	base, client, err := LocalManagementAPI()
	if err != nil {
		t.Fatal(err)
	}
	request := func() {
		t.Helper()
		resp, err := client.Get(base + "/health")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
	}
	request()
	first, err := readRuntimeRecord(p.path)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err = selfSignedTLS(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgmttls.Publish(bundle, cert, key); err != nil {
		t.Fatal(err)
	}
	// The listener and record adopt the same snapshot before the local CLI dials.
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	second, err := readRuntimeRecord(p.path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Served.LeafPEM == "" || second.Served.LeafPEM == first.Served.LeafPEM {
		t.Fatal("record did not track rotation")
	}
	request()
	if err := os.WriteFile(bundle, []byte("invalid external rotation"), 0o600); err != nil {
		t.Fatal(err)
	}
	request() // pins the retained public snapshot rather than rereading invalid files
	data, err := os.ReadFile(p.path)
	if err != nil || strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatal("runtime record exposed a key")
	}
	if err := p.remove(); err != nil {
		t.Fatal(err)
	}
}
