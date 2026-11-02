// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// The console and SSH CLI sessions call the same loopback URL: the bound
// HTTP listener unless it redirects to the bound HTTPS listener or does not
// accept loopback connections, then HTTPS.
func TestLoopbackManagementAPIChoosesTheListener(t *testing.T) {
	httpOn := config.ManagementListener{Addr: "[::]:8080", Enabled: true}
	httpsOn := config.ManagementListener{Addr: ":8443", Enabled: true}
	httpHost := config.ManagementListener{Addr: "10.10.10.10:8080", Enabled: true}
	httpLoopback := config.ManagementListener{Addr: "127.0.0.1:8080", Enabled: true}
	for _, tc := range []struct {
		name     string
		bound    config.ManagementListeners
		served   ServedManagement
		want     string
		wantPins bool
	}{
		{"HTTP", config.ManagementListeners{HTTP: httpOn}, ServedManagement{}, "http://127.0.0.1:8080", false},
		{"HTTP on 127.0.0.1", config.ManagementListeners{HTTP: httpLoopback}, ServedManagement{}, "http://127.0.0.1:8080", false},
		{"HTTP with a loopback socket", config.ManagementListeners{HTTP: httpHost}, ServedManagement{HTTPLoopback: true}, "http://127.0.0.1:8080", false},
		{"HTTP not on loopback", config.ManagementListeners{HTTP: httpHost, HTTPS: httpsOn}, ServedManagement{CertFile: "/c"}, "https://127.0.0.1:8443", true},
		{"HTTP and HTTPS", config.ManagementListeners{HTTP: httpOn, HTTPS: httpsOn}, ServedManagement{CertFile: "/c"}, "http://127.0.0.1:8080", false},
		{"HTTP redirecting to HTTPS", config.ManagementListeners{HTTP: httpOn, HTTPS: httpsOn}, ServedManagement{CertFile: "/c", HTTPRedirects: true}, "https://127.0.0.1:8443", true},
		{"HTTPS only", config.ManagementListeners{HTTPS: httpsOn}, ServedManagement{CertFile: "/c"}, "https://127.0.0.1:8443", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bindConsoleTest(t, tc.bound)
			recordServed(t, tc.served)
			baseURL, client, err := LoopbackManagementAPI()
			if err != nil || baseURL != tc.want {
				t.Fatalf("LoopbackManagementAPI = %q, %v; want %q", baseURL, err, tc.want)
			}
			if _, pins := client.Transport.(*http.Transport); pins != tc.wantPins {
				t.Fatalf("client transport %T, want pinning %v", client.Transport, tc.wantPins)
			}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "http://untrusted.example/execute", nil)
			console, err := cliAPIForRequest(c)
			if err != nil || console.BaseURL != baseURL {
				t.Fatalf("console URL = %+v, %v; want %q", console, err, baseURL)
			}
		})
	}
}

// The HTTP loopback client refuses redirects, so a bearer token never
// follows one to another listener.
func TestLoopbackManagementAPIRefusesHTTPRedirect(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		leaked.Add(1)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}})
	recordServed(t, ServedManagement{})
	baseURL, client, err := LoopbackManagementAPI()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer loopback-secret")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, errLoopbackRedirect) || leaked.Load() != 0 {
		t.Fatalf("redirect: %v, leaked calls %d", err, leaked.Load())
	}
}

func TestLoopbackHTTPSFailureNamesExpiredCertificateValidity(t *testing.T) {
	now := time.Now().UTC()
	cert, key := generateTestCertPEMWithValidity(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	path := filepath.Join(t.TempDir(), "server.pem")
	if err := mgmttls.Publish(path, []byte(cert), []byte(key)); err != nil {
		t.Fatal(err)
	}
	loader := mgmttls.NewLoader(path, path)
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	leaf := loader.LastLeaf()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{GetCertificate: loader.GetCertificate}
	server.StartTLS()
	defer server.Close()

	bound := config.ManagementListeners{HTTPS: config.ManagementListener{
		Addr: server.Listener.Addr().String(), Enabled: true,
	}}
	bindConsoleTest(t, bound)
	recordServed(t, ServedManagement{CertFile: path, KeyFile: path, TLS: loader})
	baseURL, client, err := LoopbackManagementAPI()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "has expired") ||
		!strings.Contains(err.Error(), "NotBefore="+leaf.NotBefore.UTC().Format(time.RFC3339Nano)) ||
		!strings.Contains(err.Error(), "NotAfter="+leaf.NotAfter.UTC().Format(time.RFC3339Nano)) ||
		!strings.Contains(err.Error(), "current UTC time=") {
		t.Fatalf("loopback TLS error omitted certificate validity: %v", err)
	}
}

// Without a listener to call on 127.0.0.1 there is no URL, and the console
// says so: a port management did not bind on loopback is never called.
func TestLoopbackManagementAPIWithoutListener(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bound  config.ManagementListeners
		served ServedManagement
		want   string
	}{
		{"none bound", config.ManagementListeners{}, ServedManagement{}, "no management HTTP or HTTPS listener bound"},
		{"HTTP without a port", config.ManagementListeners{HTTP: config.ManagementListener{Addr: "10.10.10.10", Enabled: true}}, ServedManagement{}, "no management HTTP or HTTPS listener bound"},
		{"HTTPS without a certificate", config.ManagementListeners{HTTPS: config.ManagementListener{Addr: ":8443", Enabled: true}}, ServedManagement{}, "the bound HTTPS listener recorded no certificate"},
		{"HTTP not on loopback", config.ManagementListeners{HTTP: config.ManagementListener{Addr: "10.10.10.10:8080", Enabled: true}}, ServedManagement{}, "no bound management HTTP or HTTPS listener accepts connections on 127.0.0.1"},
		{"HTTPS not on loopback", config.ManagementListeners{HTTPS: config.ManagementListener{Addr: "10.10.10.10:8443", Enabled: true}}, ServedManagement{CertFile: "/c"}, "no bound management HTTP or HTTPS listener accepts connections on 127.0.0.1"},
		{"HTTP on another loopback address", config.ManagementListeners{HTTP: config.ManagementListener{Addr: "127.0.0.2:8080", Enabled: true}}, ServedManagement{}, "no bound management HTTP or HTTPS listener accepts connections on 127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bindConsoleTest(t, tc.bound)
			recordServed(t, tc.served)
			if baseURL, _, err := LoopbackManagementAPI(); err == nil || err.Error() != tc.want {
				t.Fatalf("LoopbackManagementAPI = %q, %v; want %q", baseURL, err, tc.want)
			}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/execute", nil)
			if _, err := cliAPIForRequest(c); err == nil || !strings.HasPrefix(err.Error(), "console: "+tc.want) {
				t.Fatalf("console error = %v", err)
			}
		})
	}
}
