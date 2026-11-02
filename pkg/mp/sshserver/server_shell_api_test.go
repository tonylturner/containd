// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cli"
)

const shellAPIResetHelperEnv = "CONTAIND_TEST_SSH_CLI_HELPER"
const shellAPIResetRawHelperEnv = "CONTAIND_TEST_SSH_RAW_RESET_HELPER"

// TestShellAPIResetCLIHelper runs as the containd cli child process in
// TestFactoryResetDisconnectsLinuxShellCLI.
func TestShellAPIResetCLIHelper(t *testing.T) {
	if os.Getenv(shellAPIResetHelperEnv) != "1" {
		return
	}
	api, err := cli.ConnectSSHSession(context.Background(), os.Getenv(cli.EnvSSHAPISocket))
	if err != nil {
		t.Fatal(err)
	}
	reg := cli.NewRegistry(nil, api)
	ctx := cli.WithRole(context.Background(), string(cli.RoleAdmin))
	if err := reg.ParseAndExecute(ctx, "factory reset NUCLEAR", os.Stdout); err != nil {
		t.Fatal(err)
	}
}

// TestShellAPIResetRawClientHelper triggers a reset without acknowledging it,
// simulating a shell user that calls the socket without containd cli.
func TestShellAPIResetRawClientHelper(t *testing.T) {
	if os.Getenv(shellAPIResetRawHelperEnv) != "1" {
		return
	}
	socket := os.Getenv(cli.EnvSSHAPISocket)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	read, err := client.Get("http://ssh-session/api/v1/config/candidate")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, read.Body)
	_ = read.Body.Close()
	if readErr != nil || read.StatusCode != http.StatusOK {
		t.Fatalf("candidate read: status %d, error %v", read.StatusCode, readErr)
	}
	req, err := http.NewRequest(http.MethodPost, "http://ssh-session/api/v1/system/factory-reset", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Containd-If-Revision", read.Header.Get("X-Containd-Revision"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("factory reset status: %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, "raw-reset-response-received")
}

// shellAPIUpstream records the requests the shell API forwards to
// management, after reading their bodies.
type shellAPIUpstream struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func (u *shellAPIUpstream) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	u.mu.Lock()
	u.requests = append(u.requests, req)
	u.bodies = append(u.bodies, string(body))
	u.mu.Unlock()
	resp := jsonResponse(http.StatusOK, map[string]string{"username": "shell-api-admin"})
	resp.Header.Set("X-Auth-Token", "refreshed")
	resp.Header.Set("Set-Cookie", "containd_token=refreshed")
	resp.Header.Set("X-Containd-Revision", "0123456789abcdef.2")
	return resp, nil
}

func (u *shellAPIUpstream) last() (*http.Request, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		return nil, ""
	}
	return u.requests[len(u.requests)-1], u.bodies[len(u.bodies)-1]
}

// The CLI in a Linux shell calls management as the SSH login: each request
// carries a token for the connection's session and names the connection,
// and the shell never sees a credential. Closing the shell API removes it.
func TestShellAPIActsAsTheSSHLogin(t *testing.T) {
	srv, store, _ := newAssuranceServer(t)
	upstream := &shellAPIUpstream{}
	srv.opts.APIClient = upstream
	srv.opts.BaseURL = "http://127.0.0.1:8080"
	u, _ := createAdmin(t, store, "shell-api-admin")
	ctx := context.Background()
	sessionID, err := srv.openSession(ctx, u.Username, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := &sshConnection{id: "conn-1", sessionID: sessionID}
	api, err := srv.openShellAPI(conn, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Dir(api.socket)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory: %v, %v", info, err)
	}

	client, err := cli.ConnectSSHSession(ctx, api.socket)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if client.Token != "" {
		t.Fatalf("CLI received a credential: %q", client.Token)
	}
	req, _ := upstream.last()
	if req == nil || req.URL.String() != "http://127.0.0.1:8080/api/v1/auth/me" {
		t.Fatalf("forwarded request: %+v", req)
	}
	if req.Header.Get("X-Containd-SSH-Connection") != "conn-1" {
		t.Fatalf("connection header: %q", req.Header.Get("X-Containd-SSH-Connection"))
	}
	raw := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return srv.opts.JWTSecret, nil }); err != nil || claims["jti"] != sessionID || claims["sub"] != u.ID {
		t.Fatalf("token %v, claims %v", err, claims)
	}

	// Bodies, queries and the method reach management; credentials do not
	// come back.
	write := mustRequest(t, http.MethodPost, "http://ssh-session/api/v1/config/candidate?x=1", `{"a":1}`)
	write.Header.Set("X-Containd-If-Revision", "0123456789abcdef.1")
	resp, err := client.Client.Do(write)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	req, body := upstream.last()
	if req.Method != http.MethodPost || req.URL.RawQuery != "x=1" || body != `{"a":1}` || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("forwarded %s %s %q %q", req.Method, req.URL, body, req.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Auth-Token") != "" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("credential returned to the shell: %v", resp.Header)
	}
	if req.Header.Get("X-Containd-If-Revision") != "0123456789abcdef.1" || resp.Header.Get("X-Containd-Revision") != "0123456789abcdef.2" {
		t.Fatalf("revision transport: request %v, response %v", req.Header, resp.Header)
	}
	// Duplicate preconditions must reach management unchanged, so its syntax
	// validation cannot be bypassed by the proxy collapsing them.
	write = mustRequest(t, http.MethodPost, "http://ssh-session/api/v1/config/candidate", `{}`)
	write.Header.Add("X-Containd-If-Revision", "0123456789abcdef.1")
	write.Header.Add("X-Containd-If-Revision", "0123456789abcdef.2")
	resp, err = client.Client.Do(write)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	req, _ = upstream.last()
	if len(req.Header.Values("X-Containd-If-Revision")) != 2 {
		t.Fatal("proxy collapsed duplicate preconditions")
	}
	for _, p := range []string{"/metrics", "/api/v1/../metrics", "/api/v1/%2e%2e/metrics", "/api/v1/", "/api/v1//health", "/internal/config"} {
		resp, err := client.Client.Do(mustRequest(t, http.MethodGet, "http://ssh-session"+p, ""))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
	}

	// A revoked login fails with the reason.
	if err := store.RevokeSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.ConnectSSHSession(ctx, api.socket); err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("revoked login: %v", err)
	}

	api.close()
	if _, err := os.Stat(filepath.Dir(api.socket)); !os.IsNotExist(err) {
		t.Fatalf("socket directory remains: %v", err)
	}
	if _, err := cli.ConnectSSHSession(ctx, api.socket); err == nil {
		t.Fatal("closed shell API still answers")
	}
}

func TestFactoryResetDisconnectsLinuxShellCLI(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("needs /bin/bash")
	}
	srv, store, _ := newAssuranceServer(t)
	srv.opts.ShellMode = "linux"
	srv.opts.LabMode = true
	api := httptest.NewServer(revisionedSSHResetHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/me":
			_, _ = io.WriteString(w, `{"username":"shell-reset-admin"}`)
		case "/api/v1/system/factory-reset":
			srv.RevokeConnections(r.Header.Get("X-Containd-SSH-Connection"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"reset","loggedOut":true,"warnings":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	srv.opts.BaseURL = api.URL
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "shell-reset-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()
	tty := openTTY(t, client)
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf("%s=1 %q -test.run=^TestShellAPIResetCLIHelper$\n", shellAPIResetHelperEnv, testBinary)
	tty.send(t, command)
	tty.waitFor(t, "ok", 1)

	exited := make(chan error, 1)
	go func() { exited <- tty.session.Wait() }()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		tty.send(t, "echo shell-survived-$((6*7))\n")
		tty.waitFor(t, "shell-survived-42", 1)
		t.Fatalf("factory reset response reached containd cli, but its SSH Linux shell remained usable: %q", tty.output())
	}
}

func TestFactoryResetDisconnectsLinuxShellRawClient(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("needs /bin/bash")
	}
	srv, store, _ := newAssuranceServer(t)
	srv.opts.ShellMode = "linux"
	srv.opts.LabMode = true
	api := httptest.NewServer(revisionedSSHResetHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/me":
			_, _ = io.WriteString(w, `{"username":"shell-reset-raw-admin"}`)
		case "/api/v1/system/factory-reset":
			srv.RevokeConnections(r.Header.Get("X-Containd-SSH-Connection"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"reset","loggedOut":true,"warnings":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	srv.opts.BaseURL = api.URL
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "shell-reset-raw-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()
	tty := openTTY(t, client)
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf("%s=1 %q -test.run=^TestShellAPIResetRawClientHelper$\n", shellAPIResetRawHelperEnv, testBinary)
	tty.send(t, command)
	tty.waitFor(t, "raw-reset-response-received", 1)

	exited := make(chan error, 1)
	go func() { exited <- tty.session.Wait() }()
	connectionClosed := make(chan error, 1)
	go func() { connectionClosed <- client.Conn.Wait() }()
	select {
	case <-exited:
	case <-time.After(shellResetCloseGrace + shellOutputGrace + time.Second):
		tty.send(t, "echo shell-survived-$((6*7))\n")
		tty.waitFor(t, "shell-survived-42", 1)
		t.Fatalf("raw factory reset response reached the socket client, but its SSH Linux shell remained usable: %q", tty.output())
	}
	select {
	case <-connectionClosed:
	case <-time.After(shellResetCloseGrace + shellOutputGrace + time.Second):
		t.Fatal("SSH connection remained open after raw factory reset")
	}
}

func TestShellAPIResetAcknowledgementStopsShell(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &sshConnection{cancel: cancel}
	conn.reset.Store(true)
	stopped := false
	handler := (&Server{}).shellAPIHandler(conn, func() { stopped = true })
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, cli.SSHResetAcknowledgePath, nil))
	if rec.Code != http.StatusNoContent || !stopped || ctx.Err() != nil {
		t.Fatalf("acknowledgement must stop the shell without closing its transport: status %d, stopped %v, context %v", rec.Code, stopped, ctx.Err())
	}
}

func mustRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// A Linux shell opened over SSH, in linux mode or from the appliance CLI,
// receives the socket of its login's shell API, which is removed when the
// shell exits.
func TestLinuxShellReceivesShellAPISocket(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("needs /bin/bash")
	}
	for _, mode := range []string{"linux", "appliance"} {
		t.Run(mode, func(t *testing.T) {
			srv, store, _ := newAssuranceServer(t)
			srv.opts.ShellMode = mode
			addr := serveSSH(t, srv)
			u, password := createAdmin(t, store, "socket-"+mode)
			client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			defer client.Close()
			tty := openTTY(t, client)
			if mode == "appliance" {
				tty.waitFor(t, "containd(config", 1)
				tty.send(t, "shell\n")
				tty.waitFor(t, "shell\r\n", 1)
			}
			tty.send(t, `test -S "$CONTAIND_SSH_API_SOCKET" && echo "socket=[$CONTAIND_SSH_API_SOCKET]"`+"\n")
			tty.waitFor(t, "socket=[/", 1)
			socket := regexp.MustCompile(`socket=\[(/[^\]]+)\]`).FindStringSubmatch(tty.output())[1]
			tty.send(t, "exit\n")
			if mode == "appliance" {
				// Idle redraws are not evidence that the Linux shell
				// has exited and handed input back to the CLI.
				tty.waitFor(t, "Returned to configuration CLI; candidate changes remain staged.", 1)
				tty.waitFor(t, "containd(config", 2)
				tty.send(t, "exit\n")
			}
			if err := tty.session.Wait(); err != nil {
				t.Fatalf("session: %v: %q", err, tty.output())
			}
			if _, err := os.Stat(socket); !os.IsNotExist(err) {
				t.Fatalf("socket %s remains: %v", socket, err)
			}
		})
	}
}
