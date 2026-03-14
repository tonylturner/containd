// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type recordingAuditStore struct {
	records []audit.Record
}

func (s *recordingAuditStore) Add(_ context.Context, r audit.Record) error {
	s.records = append(s.records, r)
	return nil
}

func (s *recordingAuditStore) List(_ context.Context, limit int, _ ...int) ([]audit.Record, error) {
	if limit <= 0 || limit > len(s.records) {
		limit = len(s.records)
	}
	out := make([]audit.Record, limit)
	copy(out, s.records[:limit])
	return out, nil
}

func (s *recordingAuditStore) Close() error { return nil }

type sshHTTPRequest struct {
	Method string
	Path   string
	Body   string
}

type sshTestHTTPClient struct {
	cfg      config.Config
	requests []sshHTTPRequest
}

func newSSHTestHTTPClient() *sshTestHTTPClient {
	cfg := config.DefaultConfig()
	cfg.System.Hostname = "lab-fw"
	cfg.System.Mgmt.ListenAddr = ":8080"
	cfg.System.SSH.ListenAddr = ":2222"
	cfg.System.SSH.AuthorizedKeysDir = "/data/ssh"
	cfg.System.SSH.AllowPassword = true
	cfg.Interfaces = []config.Interface{
		{Name: "wan", Device: "eth0", Zone: "wan", AddressMode: "dhcp"},
		{Name: "lan1", Device: "eth1", Zone: "lan", AddressMode: "static", Addresses: []string{"192.0.2.2/24"}},
	}
	return &sshTestHTTPClient{cfg: *cfg}
}

func (c *sshTestHTTPClient) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	c.requests = append(c.requests, sshHTTPRequest{
		Method: req.Method,
		Path:   req.URL.Path,
		Body:   string(body),
	})
	return c.respond(req.Method, req.URL.Path, body), nil
}

func (c *sshTestHTTPClient) respond(method, path string, body []byte) *http.Response {
	switch method {
	case http.MethodGet:
		switch path {
		case "/api/v1/health":
			return jsonResponse(http.StatusOK, map[string]any{
				"status":    "ok",
				"component": "mgmt",
				"build":     "test",
			})
		case "/api/v1/config", "/api/v1/config/candidate", "/api/v1/config/export":
			return jsonResponse(http.StatusOK, c.cfg)
		case "/api/v1/config/diff":
			return jsonResponse(http.StatusOK, map[string]any{})
		case "/api/v1/interfaces":
			return jsonResponse(http.StatusOK, c.cfg.Interfaces)
		case "/api/v1/interfaces/state":
			return jsonResponse(http.StatusOK, []config.InterfaceState{
				{Name: "eth0", Index: 1, Up: true, MTU: 1500, MAC: "00:11:22:33:44:55", Addrs: []string{"198.51.100.2/24"}},
				{Name: "eth1", Index: 2, Up: true, MTU: 1500, MAC: "00:11:22:33:44:66", Addrs: []string{"192.0.2.2/24"}},
			})
		case "/api/v1/routing":
			return jsonResponse(http.StatusOK, config.RoutingConfig{})
		case "/api/v1/firewall/nat":
			return jsonResponse(http.StatusOK, config.NATConfig{})
		case "/api/v1/firewall/rules":
			return jsonResponse(http.StatusOK, []map[string]any{})
		default:
			return jsonResponse(http.StatusOK, map[string]any{})
		}
	case http.MethodPost:
		switch path {
		case "/api/v1/config/candidate":
			var next config.Config
			if err := json.Unmarshal(body, &next); err == nil {
				c.cfg = next
			}
			return jsonResponse(http.StatusOK, map[string]any{})
		case "/api/v1/interfaces/assign":
			return jsonResponse(http.StatusOK, map[string]any{"interfaces": c.cfg.Interfaces})
		default:
			return jsonResponse(http.StatusOK, map[string]any{})
		}
	case http.MethodPatch:
		if strings.HasPrefix(path, "/api/v1/interfaces/") {
			return jsonResponse(http.StatusOK, map[string]any{})
		}
		if strings.HasPrefix(path, "/api/v1/firewall/rules/") {
			return jsonResponse(http.StatusOK, map[string]any{})
		}
		return jsonResponse(http.StatusOK, map[string]any{})
	default:
		return jsonResponse(http.StatusOK, map[string]any{})
	}
}

func jsonResponse(status int, payload any) *http.Response {
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(payload)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
		Header:     make(http.Header),
	}
}

func (c *sshTestHTTPClient) saw(method, path string) bool {
	for _, req := range c.requests {
		if req.Method == method && req.Path == path {
			return true
		}
	}
	return false
}

func newTestSSHServer(t *testing.T) (*Server, *users.SQLiteStore, *recordingAuditStore) {
	t.Helper()

	tmp := t.TempDir()
	userStore, err := users.NewSQLiteStore(filepath.Join(tmp, "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = userStore.Close() })
	if err := userStore.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}

	auditStore := &recordingAuditStore{}
	srv, err := New(Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       filepath.Join(tmp, "host_key"),
		AuthorizedKeysDir: filepath.Join(tmp, "keys"),
		JWTSecret:         []byte(sshTestValue("jwt-signing")),
		UserStore:         userStore,
		AuditStore:        auditStore,
		AllowPassword:     true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, userStore, auditStore
}

func newTestSession(srv *Server, reg *cli.Registry, input string) (*interactiveSession, *bytes.Buffer) {
	rw := &bytes.Buffer{}
	reader := bufio.NewReader(strings.NewReader(input))
	ctx := cli.WithRole(context.Background(), string(cli.RoleAdmin))
	return newInteractiveSession(srv, ctx, "containd", rw, reader, reg), rw
}

func TestInteractiveHelpers(t *testing.T) {
	srv, _, auditStore := newTestSSHServer(t)
	reg := cli.NewRegistry(nil, nil)

	session, rw := newTestSession(srv, reg, "  answer  \n")
	if session.server != srv || session.username != "containd" {
		t.Fatalf("unexpected interactive session: %#v", session)
	}

	session.writeLn("hello")
	if got := rw.String(); got != "hello\r\n" {
		t.Fatalf("writeLn output = %q", got)
	}

	rw.Reset()
	writeTTY(rw, "a\nb\r\nc\r")
	if got := rw.String(); got != "a\r\nb\r\nc\r\n" {
		t.Fatalf("writeTTY output = %q", got)
	}

	rw.Reset()
	writeRaw(rw, "raw")
	if got := rw.String(); got != "raw" {
		t.Fatalf("writeRaw output = %q", got)
	}

	if got := shellEscape("wan"); got != "'wan'" {
		t.Fatalf("shellEscape simple = %q", got)
	}
	if got := shellEscape("a'b"); got != "'a'\"'\"'b'" {
		t.Fatalf("shellEscape quoted = %q", got)
	}

	echo := &bytes.Buffer{}
	line, ok := readLineInteractive(bufio.NewReader(strings.NewReader("ab\x08c\n")), echo)
	if !ok || line != "ac" {
		t.Fatalf("readLineInteractive = %q, %v", line, ok)
	}

	answer, ok := session.ask("Prompt: ")
	if !ok || answer != "answer" {
		t.Fatalf("ask = %q, %v", answer, ok)
	}

	cancelSession, cancelRW := newTestSession(srv, reg, "\x03")
	if answer, ok := cancelSession.ask("Prompt: "); ok || answer != "" {
		t.Fatalf("ctrl-c ask = %q, %v", answer, ok)
	}
	if !strings.Contains(cancelRW.String(), "^C") {
		t.Fatalf("expected ctrl-c echo, got %q", cancelRW.String())
	}

	rw.Reset()
	if ok := session.exec("show version"); !ok {
		t.Fatal("expected show version to succeed")
	}
	if rw.Len() == 0 {
		t.Fatal("expected exec output")
	}

	rw.Reset()
	if ok := session.exec("does not exist"); ok {
		t.Fatal("expected invalid command to fail")
	}
	if !strings.Contains(rw.String(), "error: unknown command") {
		t.Fatalf("expected exec error output, got %q", rw.String())
	}

	rw.Reset()
	out, err := session.execWithOutput("help")
	if err != nil || out.Len() == 0 || rw.Len() == 0 {
		t.Fatalf("execWithOutput err=%v out=%q rw=%q", err, out.String(), rw.String())
	}

	session.writeAudit("ssh.test", "target")
	if len(auditStore.records) != 1 || auditStore.records[0].Action != "ssh.test" {
		t.Fatalf("unexpected audit records: %#v", auditStore.records)
	}
}

func TestInteractiveMenus(t *testing.T) {
	srv, _, _ := newTestSSHServer(t)
	httpClient := newSSHTestHTTPClient()
	api := &cli.API{BaseURL: "http://127.0.0.1:8080", Client: httpClient}
	reg := cli.NewRegistry(nil, api)

	menuSession, menuRW := newTestSession(srv, reg, "0\n")
	srv.runMenu(menuSession.ctx, menuSession.username, menuRW, menuSession.reader, reg)
	if !strings.Contains(menuRW.String(), "containd console menu") {
		t.Fatalf("expected main menu output, got %q", menuRW.String())
	}

	diagSession, diagRW := newTestSession(srv, reg, "0\n")
	srv.runDiagnosticsMenu(diagSession.ctx, diagRW, diagSession.reader, reg)
	if !strings.Contains(diagRW.String(), "Diagnostics") {
		t.Fatalf("expected diagnostics output, got %q", diagRW.String())
	}

	session, rw := newTestSession(srv, reg, "NUCLEAR\n")
	if ok := session.handleMainMenuChoice("10"); ok {
		t.Fatal("expected factory reset choice to end menu")
	}
	if !httpClient.saw(http.MethodPost, "/api/v1/system/factory-reset") {
		t.Fatal("expected factory reset API call")
	}

	rw.Reset()
	if ok := session.handleMainMenuChoice("bogus"); !ok {
		t.Fatal("expected unknown option to keep menu open")
	}
	if !strings.Contains(rw.String(), "Unknown option.") {
		t.Fatalf("expected unknown option output, got %q", rw.String())
	}

	rw.Reset()
	if ok := session.handleDiagnosticsChoice("bogus"); !ok {
		t.Fatal("expected unknown diagnostics option to keep menu open")
	}
	if !strings.Contains(rw.String(), "Unknown option.") {
		t.Fatalf("expected diagnostics unknown output, got %q", rw.String())
	}
}

func TestInteractiveConfigurationMenus(t *testing.T) {
	srv, _, _ := newTestSSHServer(t)
	httpClient := newSSHTestHTTPClient()
	api := &cli.API{BaseURL: "http://127.0.0.1:8080", Client: httpClient}
	reg := cli.NewRegistry(nil, api)

	assignSession, _ := newTestSession(srv, reg, "yes\n")
	assignSession.menuAssignInterfaces()
	if !httpClient.saw(http.MethodPost, "/api/v1/interfaces/assign") {
		t.Fatal("expected interface auto-assign request")
	}

	dhcpSession, _ := newTestSession(srv, reg, "wan\ndhcp\n")
	dhcpSession.menuSetInterfaceIP()
	if !httpClient.saw(http.MethodPatch, "/api/v1/interfaces/wan") {
		t.Fatal("expected interface DHCP patch request")
	}

	staticSession, _ := newTestSession(srv, reg, "lan1\nstatic\n192.0.2.10/24\n192.0.2.1\n")
	staticSession.menuSetInterfaceIP()
	if !httpClient.saw(http.MethodPatch, "/api/v1/interfaces/lan1") {
		t.Fatal("expected interface static patch request")
	}

	pingSession, pingRW := newTestSession(srv, reg, "\n")
	pingSession.runDiagnosticPing()
	if !strings.Contains(pingRW.String(), "Host required.") {
		t.Fatalf("expected ping validation output, got %q", pingRW.String())
	}

	traceSession, traceRW := newTestSession(srv, reg, "\n")
	traceSession.runDiagnosticTraceroute()
	if !strings.Contains(traceRW.String(), "Host required.") {
		t.Fatalf("expected traceroute validation output, got %q", traceRW.String())
	}

	tcpTraceSession, tcpTraceRW := newTestSession(srv, reg, "example.com\n\n")
	tcpTraceSession.runDiagnosticTCPTraceroute()
	if !strings.Contains(tcpTraceRW.String(), "Port required.") {
		t.Fatalf("expected tcp traceroute validation output, got %q", tcpTraceRW.String())
	}

	captureSession, captureRW := newTestSession(srv, reg, "\n")
	captureSession.runDiagnosticCapture()
	if !strings.Contains(captureRW.String(), "Interface required.") {
		t.Fatalf("expected capture validation output, got %q", captureRW.String())
	}
}

func TestInteractiveWizardAndPasswordFlows(t *testing.T) {
	srv, userStore, auditStore := newTestSSHServer(t)
	httpClient := newSSHTestHTTPClient()
	api := &cli.API{BaseURL: "http://127.0.0.1:8080", Client: httpClient}
	reg := cli.NewRegistry(nil, api)

	wizardSession, wizardRW := newTestSession(srv, reg, "\n\n\n\n\n\n\n\nno\n")
	srv.runWizard(wizardSession.ctx, wizardSession.username, wizardRW, wizardSession.reader, reg)
	if !strings.Contains(wizardRW.String(), "containd setup wizard (text)") {
		t.Fatalf("expected wizard banner, got %q", wizardRW.String())
	}
	if !strings.Contains(wizardRW.String(), "Not committed.") {
		t.Fatalf("expected not committed message, got %q", wizardRW.String())
	}

	resetPassword := sshTestValue("wizard-reset")
	resetSession, _ := newTestSession(srv, reg, resetPassword+"\n")
	resetSession.menuResetPassword()
	admin, err := userStore.GetByUsername(context.Background(), "containd")
	if err != nil || admin == nil {
		t.Fatalf("GetByUsername: %v admin=%#v", err, admin)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(resetPassword)); err != nil {
		t.Fatalf("password was not updated: %v", err)
	}

	pub, line := authorizedKeyLineForTest(t)
	keySession, keyRW := newTestSession(srv, reg, line+"\n")
	added, ok := keySession.wizardPromptSSHKey()
	if !ok || !added {
		t.Fatalf("wizardPromptSSHKey = %v, %v", added, ok)
	}
	authorized, err := isAuthorizedKey(srv.opts.AuthorizedKeysDir, "containd", pub)
	if err != nil || !authorized {
		t.Fatalf("isAuthorizedKey err=%v authorized=%v", err, authorized)
	}
	if !strings.Contains(keyRW.String(), "ssh key added") {
		t.Fatalf("expected ssh key output, got %q", keyRW.String())
	}

	commitSession, _ := newTestSession(srv, reg, "yes\n")
	if ok := commitSession.wizardPromptCommit(); !ok {
		t.Fatal("expected commit prompt to succeed")
	}
	if !httpClient.saw(http.MethodPost, "/api/v1/config/commit") {
		t.Fatal("expected commit API call")
	}

	setSession, _ := newTestSession(srv, reg, "updated-host\n")
	if ok := setSession.wizardPromptSet("Hostname (blank to keep): ", "set system hostname "); !ok {
		t.Fatal("expected wizardPromptSet success")
	}
	if got := httpClient.cfg.System.Hostname; got != "updated-host" {
		t.Fatalf("expected hostname update, got %q", got)
	}

	sshPasswordSession, _ := newTestSession(srv, reg, "no\n")
	if ok := sshPasswordSession.wizardPromptSSHPasswordAuth(); !ok {
		t.Fatal("expected ssh password prompt to succeed")
	}

	disablePasswordSession, _ := newTestSession(srv, reg, "yes\n")
	if ok := disablePasswordSession.wizardPromptDisablePasswordAfterKey(); !ok {
		t.Fatal("expected disable password prompt to succeed")
	}

	outboundSession, _ := newTestSession(srv, reg, "yes\n")
	if ok := outboundSession.wizardPromptOutboundQuickstart(); !ok {
		t.Fatal("expected outbound quickstart prompt to succeed")
	}
	if !httpClient.saw(http.MethodPost, "/api/v1/routing") {
		t.Fatal("expected routing update during outbound quickstart")
	}
	if !httpClient.saw(http.MethodPost, "/api/v1/firewall/nat") {
		t.Fatal("expected NAT update during outbound quickstart")
	}
	if !httpClient.saw(http.MethodPost, "/api/v1/firewall/rules") && !httpClient.saw(http.MethodPatch, "/api/v1/firewall/rules/allow-lan-mgmt-wan") {
		t.Fatal("expected firewall quickstart update")
	}

	if len(auditStore.records) == 0 {
		t.Fatal("expected password audit records")
	}
}
