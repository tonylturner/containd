// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLICommandsHandlerIncludesExpectedCommands(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/cli/commands", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var commands []string
	if err := json.Unmarshal(rec.Body.Bytes(), &commands); err != nil {
		t.Fatalf("decode commands: %v", err)
	}
	if len(commands) == 0 {
		t.Fatal("expected commands")
	}
	if !containsString(commands, "show version") {
		t.Fatalf("expected show version command, got %v", commands)
	}
	if !containsString(commands, "show health") {
		t.Fatalf("expected show health command, got %v", commands)
	}
	if !containsString(commands, "commit confirmed") {
		t.Fatalf("expected admin command commit confirmed, got %v", commands)
	}
}

func TestCLIExecuteHandlerSupportsBlankAndCommandExecution(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/cli/execute", bytes.NewBufferString(`{"line":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for blank input, got %d body=%s", rec.Code, rec.Body.String())
	}
	var blankResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &blankResp); err != nil {
		t.Fatalf("decode blank response: %v", err)
	}
	if blankResp.Output != "" || blankResp.Error != "" {
		t.Fatalf("expected blank no-op response, got %+v", blankResp)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/cli/execute", bytes.NewBufferString(`{"line":"show version"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for show version, got %d body=%s", rec.Code, rec.Body.String())
	}
	var execResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if !strings.Contains(execResp.Output, "containd") {
		t.Fatalf("expected version output, got %+v", execResp)
	}
	if execResp.Error != "" {
		t.Fatalf("unexpected execute error: %+v", execResp)
	}
}

func TestCLICompleteHandlerSuggestsConfigAwareArgs(t *testing.T) {
	store := &mockStore{cfg: &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan"},
			{Name: "dmz"},
		},
		Zones: []config.Zone{
			{Name: "wan"},
			{Name: "dmz"},
		},
	}}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/cli/complete?line="+url.QueryEscape("set interface "), nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var suggestions []string
	if err := json.Unmarshal(rec.Body.Bytes(), &suggestions); err != nil {
		t.Fatalf("decode suggestions: %v", err)
	}
	if !containsString(suggestions, "wan") || !containsString(suggestions, "dmz") {
		t.Fatalf("expected interface suggestions, got %v", suggestions)
	}
}

func TestCLIWebsocketHandlerExecutesCommands(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	srv := httptest.NewServer(NewServer(store, nil))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/cli/ws"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+testAdminToken)
	headers.Set("Origin", srv.URL)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			t.Fatalf("websocket dial failed: %v (status=%d)", err, resp.StatusCode)
		}
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close()

	var greeting struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := conn.ReadJSON(&greeting); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting.Output, "containd in-app CLI") {
		t.Fatalf("unexpected greeting: %+v", greeting)
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"line":"show version"}`)); err != nil {
		t.Fatalf("write command: %v", err)
	}

	var cmdResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := conn.ReadJSON(&cmdResp); err != nil {
		t.Fatalf("read command response: %v", err)
	}
	if !strings.Contains(cmdResp.Output, "containd") {
		t.Fatalf("unexpected websocket output: %+v", cmdResp)
	}
	if cmdResp.Error != "" {
		t.Fatalf("unexpected websocket error: %+v", cmdResp)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

// Each certificate uses a fresh key, unlike httptest's shared default certificate.
func consoleTestCertificate(t *testing.T) (*tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "appliance.example"},
		DNSNames:     []string{"appliance.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func consoleTestRouter(store config.Store) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(ctxRoleKey, "admin") })
	r.POST("/execute", cliExecuteHandler(store))
	r.GET("/ws", cliWSHandler(store))
	return r
}

func consoleTestConfig(addr, certFile string) *config.Config {
	cfg := config.DefaultConfig()
	enabled, disabled := true, false
	cfg.System.Mgmt.EnableHTTP = &disabled
	cfg.System.Mgmt.EnableHTTPS = &enabled
	cfg.System.Mgmt.HTTPSListenAddr = addr
	cfg.System.Mgmt.TLSCertFile = certFile
	return cfg
}

func executeConsoleTest(t *testing.T, router http.Handler, host string) (string, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"line":"show health"}`))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer console-secret")
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var result struct{ Output, Error string }
	if rec.Code != http.StatusOK {
		t.Fatalf("console status = %d, body=%s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Output, result.Error
}

func TestConsoleTLSVerificationAndRotation(t *testing.T) {
	first, firstPEM := consoleTestCertificate(t)
	second, secondPEM := consoleTestCertificate(t)
	var served atomic.Pointer[tls.Certificate]
	served.Store(first)
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		n := calls.Add(1)
		wantToken := "Bearer console-secret"
		if n == 4 {
			wantToken = "Bearer console-renewed"
		}
		if r.Header.Get("Authorization") != wantToken || r.URL.Path != "/api/v1/health" {
			t.Errorf("unexpected request: %s %v", r.URL.Path, r.Header)
		}
		if n == 3 {
			w.Header().Set("X-Auth-Token", "console-renewed")
		}
		_, _ = io.WriteString(w, `{"status":"verified"}`)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return served.Load(), nil
		},
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "server.crt")
	t.Setenv("CONTAIND_TLS_CERT_FILE", path)
	store := &mockStore{cfg: consoleTestConfig(srv.Listener.Addr().String(), "/not-the-served-certificate")}
	router := consoleTestRouter(store)
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(firstPEM)
	output, errText := executeConsoleTest(t, router, "untrusted.example")
	if errText != "" || !strings.Contains(output, "verified") || calls.Load() != 1 {
		t.Fatalf("verified call: output=%q error=%q calls=%d", output, errText, calls.Load())
	}

	// A different valid certificate must fail before the bearer reaches HTTP.
	served.Store(second)
	_, errText = executeConsoleTest(t, router, "untrusted.example")
	if errText == "" || calls.Load() != 1 {
		t.Fatalf("mismatched certificate: error=%q calls=%d", errText, calls.Load())
	}
	write(secondPEM)
	output, errText = executeConsoleTest(t, router, "untrusted.example")
	if errText != "" || !strings.Contains(output, "verified") || calls.Load() != 2 {
		t.Fatalf("rotated certificate: output=%q error=%q calls=%d", output, errText, calls.Load())
	}

	// An open WebSocket must also refresh its trust for each command.
	wsServer := httptest.NewServer(router)
	defer wsServer.Close()
	headers := http.Header{"Origin": {wsServer.URL}, "Authorization": {"Bearer console-secret"}}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(wsServer.URL, "http")+"/ws", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var response struct{ Output, Error string }
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatal(err)
	}
	for i, cert := range []*tls.Certificate{second, first} {
		served.Store(cert)
		if i == 1 {
			write(firstPEM)
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte("show health")); err != nil {
			t.Fatal(err)
		}
		if err := conn.ReadJSON(&response); err != nil {
			t.Fatal(err)
		}
		if response.Error != "" || !strings.Contains(response.Output, "verified") {
			t.Fatalf("websocket command %d: %+v", i, response)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("expected four verified API calls, got %d", calls.Load())
	}
}

func TestConsoleTLSCertificateFileErrors(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	for _, tt := range []struct{ name, data, want string }{
		{"missing", "", "read management TLS certificate"},
		{"empty", "", "no certificates"},
		{"invalid PEM", "not PEM", "expected PEM certificate"},
		{"invalid DER", "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n", "parse management TLS certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.crt")
			if tt.name != "missing" {
				if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			router := consoleTestRouter(&mockStore{cfg: consoleTestConfig(":1", path)})
			_, errText := executeConsoleTest(t, router, "untrusted.example")
			if !strings.Contains(errText, tt.want) {
				t.Fatalf("error = %q; want %q", errText, tt.want)
			}
		})
	}
}

func TestConsoleConfigFailureNeverUsesRequestHost(t *testing.T) {
	var calls atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		calls.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer host.Close()
	for _, tt := range []struct {
		name  string
		store config.Store
	}{
		{"load error", &mockStore{load: func() (*config.Config, error) { return nil, errors.New("store offline") }}},
		{"nil config", &mockStore{load: func() (*config.Config, error) { return nil, nil }}},
		{"nil store", nil},
		{"disabled listeners", &mockStore{cfg: func() *config.Config {
			cfg := consoleTestConfig(":1", "")
			disabled := false
			cfg.System.Mgmt.EnableHTTPS = &disabled
			return cfg
		}()}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, errText := executeConsoleTest(t, consoleTestRouter(tt.store), strings.TrimPrefix(host.URL, "http://"))
			if !strings.Contains(errText, "console:") {
				t.Fatalf("expected console error, got %q", errText)
			}
			if calls.Load() != 0 {
				t.Fatalf("contacted request Host %d times", calls.Load())
			}
		})
	}
}

func TestConsoleHTTPStillPreferred(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "/unreadable")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer console-secret" {
			t.Error("missing bearer token")
		}
		_, _ = io.WriteString(w, `{"status":"http"}`)
	}))
	defer srv.Close()
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPListenAddr = srv.Listener.Addr().String()
	output, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: cfg}), "untrusted.example")
	if errText != "" || !strings.Contains(output, "http") || calls.Load() != 1 {
		t.Fatalf("HTTP call: output=%q error=%q calls=%d", output, errText, calls.Load())
	}
}

func TestConsoleTLSRefusesRedirect(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		leaked.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer target.Close()
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		calls.Add(1)
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "server.crt")
	// Accept a PEM bundle while retaining an exact first-certificate pin.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, append(certPEM, certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	cfg := consoleTestConfig(srv.Listener.Addr().String(), path)
	_, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: cfg}), "untrusted.example")
	if !strings.Contains(errText, "redirect refused") || calls.Load() != 1 || leaked.Load() != 0 {
		t.Fatalf("redirect: error=%q verified calls=%d leaked calls=%d", errText, calls.Load(), leaked.Load())
	}
}

func TestConsoleTLSInfoUsesServedEnvironmentPaths(t *testing.T) {
	_, certPEM := consoleTestCertificate(t)
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", path)
	t.Setenv("CONTAIND_TLS_KEY_FILE", "/env/server.key")
	cfg := consoleTestConfig(":8443", "/config/server.crt")
	cfg.System.Mgmt.TLSKeyFile = "/config/server.key"
	router := gin.New()
	router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
	var result tlsInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || result.CertFile != path || result.KeyFile != "/env/server.key" ||
		!containsString(result.CertDNSNames, "appliance.example") {
		t.Fatalf("TLS info status=%d result=%+v", rec.Code, result)
	}
}
