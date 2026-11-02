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
	serveWithConfigRevision(t, s, rec, req)
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
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: config.DefaultManagementHTTPAddr, Enabled: true}})
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/cli/execute", bytes.NewBufferString(`{"line":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	serveWithConfigRevision(t, s, rec, req)
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
	serveWithConfigRevision(t, s, rec, req)
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
	serveWithConfigRevision(t, s, rec, req)
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
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: config.DefaultManagementHTTPAddr, Enabled: true}})
	store := &mockStore{cfg: config.DefaultConfig()}
	srv := httptest.NewServer(NewServer(store, nil))
	defer srv.Close()
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}})

	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, srv.Config.Handler, rec, authedRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil))
	ticket := decodeCLITicket(t, rec)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/cli/ws?ticket=" + ticket
	headers := http.Header{}
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
	if !strings.Contains(greeting.Output, "Configuration CLI") {
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
	// This command needs the loopback API, not just the local registry. The
	// issuer's credential must survive redemption without a browser cookie.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"line":"show health"}`)); err != nil {
		t.Fatal(err)
	}
	if err := conn.ReadJSON(&cmdResp); err != nil {
		t.Fatal(err)
	}
	if cmdResp.Error != "" || !strings.Contains(cmdResp.Output, "status") {
		t.Fatalf("ticket-authenticated loopback command: %+v", cmdResp)
	}

	// Mode errors must not execute Linux tools or terminate the console.
	if err := conn.WriteJSON(map[string]string{"line": "configure"}); err != nil {
		t.Fatal(err)
	}
	if err := conn.ReadJSON(&cmdResp); err != nil {
		t.Fatal(err)
	}
	if cmdResp.Error != "" || !strings.Contains(cmdResp.Output, "Already in configuration CLI") {
		t.Fatal(cmdResp)
	}
	if err := conn.WriteJSON(map[string]string{"line": "pwd"}); err != nil {
		t.Fatal(err)
	}
	if err := conn.ReadJSON(&cmdResp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmdResp.Error, "not Linux") {
		t.Fatal(cmdResp)
	}
	if err := conn.WriteJSON(map[string]string{"control": "status"}); err != nil {
		t.Fatal(err)
	}
	var state struct{ Control, Prompt, Status string }
	if err := conn.ReadJSON(&state); err != nil {
		t.Fatal(err)
	}
	if state.Control != "status" || !strings.Contains(state.Prompt, "(config") || !strings.Contains(state.Status, "Shared candidate") {
		t.Fatal(state)
	}
	if err := conn.WriteJSON(map[string]string{"line": "exit"}); err != nil {
		t.Fatal(err)
	}
	if err := conn.ReadJSON(&state); err != nil {
		t.Fatal(err)
	}
	if state.Control != "close" {
		t.Fatal(state)
	}
	// Closing the command runner must not revoke its management session.
	rec = httptest.NewRecorder()
	srv.Config.Handler.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/auth/me", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("console exit logged out management: %d", rec.Code)
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

// bindConsoleTest records l as the listeners this process has bound until
// the test ends.
func bindConsoleTest(t *testing.T, l config.ManagementListeners) {
	t.Helper()
	config.SetBoundManagementListeners(l)
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
}

// bindConsoleHTTPS records a bound HTTPS listener on addr serving certFile,
// and no HTTP one.
func bindConsoleHTTPS(t *testing.T, addr, certFile string) {
	t.Helper()
	bindConsoleTest(t, config.ManagementListeners{HTTPS: config.ManagementListener{Addr: addr, Enabled: true}})
	SetServedManagement(ServedManagement{CertFile: certFile})
	t.Cleanup(func() { SetServedManagement(ServedManagement{}) })
}

// consoleTestConfig saves certFile and the default listeners, neither of
// which the console uses: it calls the bound listener and pins the
// certificate it serves.
func consoleTestConfig(certFile string) *config.Config {
	cfg := config.DefaultConfig()
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
	serveWithConfigRevision(t, router, rec, req)
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
		if r.URL.Path != "/api/v1/health" {
			wantToken := "Bearer console-secret"
			if calls.Load() >= 3 {
				wantToken = "Bearer console-renewed"
			}
			if r.Header.Get("Authorization") != wantToken {
				t.Errorf("status/identity lost refreshed token: %v", r.Header)
			}
			switch r.URL.Path {
			case "/api/v1/auth/me":
				_, _ = io.WriteString(w, `{"username":"operator","role":"admin"}`)
			case "/api/v1/config":
				_, _ = io.WriteString(w, `{"system":{"hostname":"appliance"}}`)
			case "/api/v1/config/diff":
				_, _ = io.WriteString(w, `{"changed":false,"pendingConfirm":null}`)
			default:
				t.Errorf("unexpected request: %s", r.URL.Path)
			}
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
	t.Setenv("CONTAIND_TLS_CERT_FILE", "/not-the-served-certificate")
	bindConsoleHTTPS(t, srv.Listener.Addr().String(), path)
	store := &mockStore{cfg: consoleTestConfig("/not-the-served-certificate")}
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
		{"invalid PEM", "not PEM", "unexpected text in TLS bundle"},
		{"invalid DER", "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n", "parse management TLS certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.crt")
			if tt.name != "missing" {
				if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bindConsoleHTTPS(t, ":1", path)
			router := consoleTestRouter(&mockStore{cfg: consoleTestConfig(path)})
			_, errText := executeConsoleTest(t, router, "untrusted.example")
			if !strings.Contains(errText, tt.want) {
				t.Fatalf("error = %q; want %q", errText, tt.want)
			}
		})
	}
}

func TestConsoleWithoutBoundListenerNeverUsesRequestHost(t *testing.T) {
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
	hostAddr := strings.TrimPrefix(host.URL, "http://")
	for _, tt := range []struct {
		name string
		bind func(*testing.T)
		want string
	}{
		{"no listener bound", func(*testing.T) {}, "console: no management HTTP or HTTPS listener bound"},
		{"HTTPS without a recorded certificate", func(t *testing.T) { bindConsoleHTTPS(t, hostAddr, "") }, "console: the bound HTTPS listener recorded no certificate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.bind(t)
			_, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: consoleTestConfig("")}), hostAddr)
			if errText != tt.want {
				t.Fatalf("console error = %q, want %q", errText, tt.want)
			}
			if calls.Load() != 0 {
				t.Fatalf("contacted request Host %d times", calls.Load())
			}
		})
	}
}

func TestConsoleHTTPStillPreferred(t *testing.T) {
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
	bindConsoleTest(t, config.ManagementListeners{
		HTTP:  config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true},
		HTTPS: config.ManagementListener{Addr: ":1", Enabled: true},
	})
	SetServedManagement(ServedManagement{CertFile: "/unreadable"})
	t.Cleanup(func() { SetServedManagement(ServedManagement{}) })
	output, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: config.DefaultConfig()}), "untrusted.example")
	if errText != "" || !strings.Contains(output, "http") || calls.Load() != 1 {
		t.Fatalf("HTTP call: output=%q error=%q calls=%d", output, errText, calls.Load())
	}
}

// A saved or environment listener that is not bound yet is never dialled.
func TestConsoleCallsTheBoundListener(t *testing.T) {
	counting := func(calls *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Errorf("read body: %v", err)
				return
			}
			calls.Add(1)
			_, _ = io.WriteString(w, `{"status":"bound"}`)
		}))
	}
	var boundCalls, savedCalls atomic.Int32
	bound, saved := counting(&boundCalls), counting(&savedCalls)
	defer bound.Close()
	defer saved.Close()
	t.Setenv(config.EnvManagementHTTPAddr, saved.Listener.Addr().String())
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPListenAddr = saved.Listener.Addr().String()
	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: bound.Listener.Addr().String(), Enabled: true}})
	output, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: cfg}), "untrusted.example")
	if errText != "" || !strings.Contains(output, "bound") || boundCalls.Load() != 1 || savedCalls.Load() != 0 {
		t.Fatalf("output=%q error=%q bound calls=%d saved calls=%d", output, errText, boundCalls.Load(), savedCalls.Load())
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
	bindConsoleHTTPS(t, srv.Listener.Addr().String(), path)
	cfg := consoleTestConfig("/not-the-served-certificate")
	_, errText := executeConsoleTest(t, consoleTestRouter(&mockStore{cfg: cfg}), "untrusted.example")
	if !strings.Contains(errText, "redirect refused") || calls.Load() != 1 || leaked.Load() != 0 {
		t.Fatalf("redirect: error=%q verified calls=%d leaked calls=%d", errText, calls.Load(), leaked.Load())
	}
}

// With HTTP off the console calls the bound HTTPS listener and pins the
// certificate it serves, whatever the saved setting or the environment name
// now: the listener can serve a fallback default or a boot-time override.
func TestConsolePinsTheServedCertificate(t *testing.T) {
	served, servedPEM := consoleTestCertificate(t)
	_, savedPEM := consoleTestCertificate(t)
	_, envPEM := consoleTestCertificate(t)
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		calls.Add(1)
		_, _ = io.WriteString(w, `{"status":"served"}`)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*served}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	dir := t.TempDir()
	files := map[string][]byte{"served.crt": servedPEM, "saved.crt": savedPEM, "env.crt": envPEM}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", filepath.Join(dir, "env.crt"))
	router := consoleTestRouter(&mockStore{cfg: consoleTestConfig(filepath.Join(dir, "saved.crt"))})

	bindConsoleHTTPS(t, srv.Listener.Addr().String(), filepath.Join(dir, "served.crt"))
	output, errText := executeConsoleTest(t, router, "untrusted.example")
	if errText != "" || !strings.Contains(output, "served") || calls.Load() != 1 {
		t.Fatalf("served certificate: output=%q error=%q calls=%d", output, errText, calls.Load())
	}
	// Trusting any other file refuses the listener before the bearer is sent.
	for _, other := range []string{"saved.crt", "env.crt"} {
		SetServedManagement(ServedManagement{CertFile: filepath.Join(dir, other)})
		if _, errText := executeConsoleTest(t, router, "untrusted.example"); errText == "" || calls.Load() != 1 {
			t.Fatalf("pinned %s: error=%q calls=%d", other, errText, calls.Load())
		}
	}
}

func TestConsoleTLSInfoUsesServedEnvironmentPaths(t *testing.T) {
	pair, certPEM := consoleTestCertificate(t)
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", path)
	keyPath := filepath.Join(filepath.Dir(path), "server.key")
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_KEY_FILE", keyPath)
	cfg := consoleTestConfig("/config/server.crt")
	cfg.System.Mgmt.TLSKeyFile = "/config/server.key"
	router := gin.New()
	router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
	var result tlsInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || result.CertFile != path || result.KeyFile != keyPath ||
		!containsString(result.CertDNSNames, "appliance.example") {
		t.Fatalf("TLS info status=%d result=%+v", rec.Code, result)
	}
}
